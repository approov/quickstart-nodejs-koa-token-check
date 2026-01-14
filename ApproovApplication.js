'use strict'

const Koa = require('koa')
const Router = require('koa-router')
const compress = require('koa-compress')
const logger = require('koa-logger')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const dotenv = require('dotenv')

const api = new Koa()
const router = new Router()

const envResult = dotenv.config({ quiet: true })
if (envResult.error) {
    console.debug('FAILED TO PARSE `.env` FILE | ' + envResult.error)
}

const APPROOV_HEADER = 'Approov-Token'
const AUTH_HEADER = 'Authorization'
const DIGEST_HEADER = 'Content-Digest'

const approovState = {
    approovEnabled: true,
    tokenBindingEnabled: true
}

function hasText(value) {
    return value != null && String(value).trim() !== ''
}

function loadApproovSecret() {
    const secret = process.env.APPROOV_BASE64URL_SECRET
    if (!hasText(secret)) throw new Error('APPROOV_BASE64URL_SECRET environment variable is not set')
    return Buffer.from(secret.trim(), 'base64url')

}

let approovSecret
try {
    approovSecret = loadApproovSecret()
} catch (err) {
    console.error('Failed to load Approov secret. Ensure `.env` exists and APPROOV_BASE64URL_SECRET is set.')
    console.error(err.message)
    process.exit(1)
}

function infoPayload(details) {
    return {
        approovEnabled: approovState.approovEnabled,
        tokenBindingEnabled: approovState.tokenBindingEnabled,
        details
    }
}

function statePayload() {
    return {
        approovEnabled: approovState.approovEnabled,
        tokenBindingEnabled: approovState.tokenBindingEnabled
    }
}

function unauthorized(ctx) {
    ctx.status = 401
    ctx.body = {}
}

function computeBindingHash(value) {
    return crypto.createHash('sha256').update(value, 'utf8').digest('base64')
}

function getBindingValue(ctx) {
    if (ctx.path === '/token-binding') {
        return ctx.get(AUTH_HEADER)
    }

    const auth = ctx.get(AUTH_HEADER)
    const digest = ctx.get(DIGEST_HEADER)
    if (!hasText(auth) || !hasText(digest)) {
        return null
    }

    return auth + digest
}

async function verifyApproovToken(ctx, next) {
    if (!approovState.approovEnabled) {
        await next()
        return
    }

    const token = ctx.get(APPROOV_HEADER)
    if (!hasText(token)) {
        unauthorized(ctx)
        return
    }

    try {
        const claims = jwt.verify(token.trim(), approovSecret, { algorithms: ['HS256'] })
        ctx.state.approovClaims = claims
    } catch (err) {
        unauthorized(ctx)
        return
    }

    if (approovState.tokenBindingEnabled && (ctx.path === '/token-binding' || ctx.path === '/token-double-binding')) {
        const bindingValue = getBindingValue(ctx)
        const expected = ctx.state.approovClaims && ctx.state.approovClaims.pay

        if (!hasText(bindingValue) || !hasText(expected)) {
            unauthorized(ctx)
            return
        }

        const computed = computeBindingHash(bindingValue)
        if (computed !== expected) {
            unauthorized(ctx)
            return
        }
    }

    await next()
}

if (process.env.HTTP_LOG !== 'false') {
  api.use(logger())
}
api.use(compress())
api.use(async (ctx, next) => {
    try {
        await next()
    } catch (err) {
        console.error('Unhandled error occurred: ' + err.message)
        ctx.status = err.status === 401 ? 401 : 500
        ctx.body = {}
        ctx.app.emit('error', err, ctx)
    }
})

router.use(['/token-check', '/token-binding', '/token-double-binding'], verifyApproovToken)

router.get('/', async ctx => {
    ctx.body = infoPayload(' Approov demo API is running on port 8080.')
})

router.get('/approov-state', async ctx => {
    ctx.body = statePayload()
})

router.post('/approov/enable', async ctx => {
    approovState.approovEnabled = true
    approovState.tokenBindingEnabled = true
    ctx.body = statePayload()
})

router.post('/approov/disable', async ctx => {
  approovState.approovEnabled = false
  approovState.tokenBindingEnabled = false
  ctx.body = statePayload()
})

router.post('/token-binding/enable', async ctx => {
  approovState.tokenBindingEnabled = true
  ctx.body = statePayload()
})

router.post('/token-binding/disable', async ctx => {
    approovState.tokenBindingEnabled = false
    ctx.body = statePayload()
})

router.get('/unprotected', async ctx => {
    ctx.body = infoPayload("Unprotected endpoint '/unprotected'; no Approov checks performed.")
})

router.get('/token-check', async ctx => {
    ctx.body = infoPayload("Protected endpoint '/token-check'; Approov token verified.")
})

router.get('/token-binding', async ctx => {
    const response = infoPayload("Protected endpoint '/token-binding'; Approov token binding enforced.")
    response.authorizationHeaderPresent = hasText(ctx.get(AUTH_HEADER))
    ctx.body = response
})

router.get('/token-double-binding', async ctx => {
    const response = infoPayload("Protected endpoint '/token-double-binding'; dual token binding enforced.")
    response.authorizationHeaderPresent = hasText(ctx.get(AUTH_HEADER))
    response.contentDigestHeaderPresent = hasText(ctx.get(DIGEST_HEADER))
    ctx.body = response
})

api.use(router.routes())
api.use(router.allowedMethods())

if (!module.parent) {
    const hostname = process.env.SERVER_HOSTNAME || 'localhost'
    const port = Number(process.env.HTTP_PORT || 8080)

    api.listen(port, hostname)
    console.log('Approov protected server is now listening at: ' + hostname + ':' + port)
}
