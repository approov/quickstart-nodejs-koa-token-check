'use strict'

const koa = require('koa')
const api = new koa()

const logger = require('koa-logger')
api.use(logger())

const compress = require('koa-compress')
api.use(compress())

const Router = require('koa-router')
const router = new Router()

const jwt = require('jsonwebtoken')

const dotenv = require('dotenv').config()

if (dotenv.error) {
  console.debug('FAILED TO PARSE `.env` FILE | ' + dotenv.error)
}

const approovBase64Secret = dotenv.parsed.APPROOV_BASE64_SECRET;
const approovSecret = Buffer.from(approovBase64Secret, 'base64')

const verifyApproovToken = async (ctx, next) => {

  const appoovToken = ctx.headers['approov-token']

  if (!appoovToken) {
    // You may want to add some logging here.
    ctx.status = 401
    ctx.body = {}
    return
  }

  // Decode the token with strict verification of the signature (['HS256']) to
  // prevent against the `none` algorithm attack.
  await jwt.verify(appoovToken, approovSecret, { algorithms: ['HS256'] }, function(err, decoded) {
    if (err) {
      // You may want to add some logging here.
      ctx.status = 401
      ctx.body = {}
      return
    }

    // The Approov token was successfully verified. We will add the claims to
    // the request object to allow further use of them during the request
    // processing.
    ctx.approovTokenClaims = decoded

    next()
  })
}

// handle errors
api.use(async (ctx, next) => {
  try {
    await next();
  } catch (err) {
    ctx.status = err.status === 401 ? 401 : 500;
    ctx.body = {}
    ctx.app.emit('error', err, ctx)
  }
})

api.use(router.routes())
api.use(router.allowedMethods())

// @IMPORTANT: Always add the `verifyApproovToken` middleware function before
//             your endpoints declaration.
//
// Using `["/"]` protects all endpoints in your API. Example to protect only
// specific endpoints: `["/checkout", "/payments", "/etc"]`.
// When adding an endpoint `/example` you are also protecting their child
// endpoints, like `/example/content`, `/example/content/:id`, etc. .
router.use(["/"], verifyApproovToken)

router.get('/', async ctx => {
  ctx.body = {message: "Hello, World!"}
})

if (!module.parent) {
  // To run in a docker container add to the .env file `SERVER_HOSTNAME=0.0.0.0`.
  const hostname = dotenv.parsed.SERVER_HOSTNAME || 'localhost'

  // The port for the Quickstart Postman collection and cURL examples is 8002
  const port = dotenv.parsed.HTTP_PORT || 8002

  api.listen(port, hostname)
  console.log('Approov protected server is now listening at: ' + hostname + ':' + port)
}
