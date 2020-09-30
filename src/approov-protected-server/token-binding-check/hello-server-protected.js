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
const crypto = require('crypto')

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

  // decode token, verify secret and check exp
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

const verifyApproovTokenBinding = async (ctx, next) => {
  // Note that the `pay` claim will, under normal circumstances, be present,
  // but if the Approov failover system is enabled, then no claim will be
  // present, and in this case you want to continue processing the request,
  // otherwise you will not be able to benefit from the redundancy afforded by
  // the failover system.
  if (!("pay" in ctx.approovTokenClaims)) {
    // You may want to add some logging here.
    await next()
    return
  }

  // The Approov token claims is added to the request object on a successful
  //  Approov token verification. See `verifyApproovToken()` function.
  const token_binding_claim = ctx.approovTokenClaims.pay

  // We use here the Authorization token, but feel free to use another header,
  // but you need to bind this header to the Approov token in the mobile app.
  const token_binding_header = ctx.req.headers['authorization']

  if (!token_binding_header) {
    // You may want to add some logging here.
    ctx.status = 401
    ctx.body = {}
    return
  }

  // We need to hash and base64 encode the token binding header, because thats
  // how it was included in the Approov token on the mobile app.
  const token_binding_header_encoded = crypto.createHash('sha256').update(token_binding_header, 'utf-8').digest('base64')

  if (token_binding_claim !== token_binding_header_encoded) {
    ctx.status = 401
    ctx.body = {}
    return
  }

  await next()
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

// @IMPORTANT: Always add the `verifyApproovToken` and `verifyApproovTokenBinding`
//             functions as middleware before your endpoints declaration.
//
// Using `["/"]` protects all endpoints in your API.
// To protect only specific endpoints use as `["/checkout", "/payments", "/etc"]`.
// For example when adding the `/payments` endpoint you are also protecting any
// child endpoints of it.
router.use(["/"], verifyApproovToken)
router.use(["/"], verifyApproovTokenBinding)

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
