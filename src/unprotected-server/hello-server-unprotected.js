'use strict'

const koa = require('koa')
const api = new koa()

const logger = require('koa-logger')
api.use(logger())

const compress = require('koa-compress')
api.use(compress())

const Router = require('koa-router')
const router = new Router()

const dotenv = require('dotenv').config()

if (dotenv.error) {
  console.debug('FAILED TO PARSE `.env` FILE | ' + dotenv.error)
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

router.get('/', async ctx => {
  ctx.body = {message: "Hello, World!"}
})

if (!module.parent) {
  // To run in a docker container add to the .env file `SERVER_HOSTNAME=0.0.0.0`.
  const hostname = dotenv.parsed.SERVER_HOSTNAME || 'localhost'

  // The port for the Quickstart Postman collection and cURL examples is 8002
  const port = dotenv.parsed.HTTP_PORT || 8002

  api.listen(port, hostname)
  console.log('Server is now listening at: ' + hostname + ':' + port)
}
