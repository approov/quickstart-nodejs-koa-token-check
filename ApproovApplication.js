'use strict'

const Koa = require('koa')
const Router = require('@koa/router')
const compress = require('koa-compress')
const logger = require('koa-logger')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const dotenv = require('dotenv')

const api = new Koa()
const router = new Router()

const envResult = dotenv.config({ quiet: true })
if (envResult.error && envResult.error.code !== 'ENOENT') {
    console.debug('FAILED TO PARSE `.env` FILE | ' + envResult.error)
}

const APPROOV_HEADER = 'Approov-Token'
const AUTH_HEADER = 'Authorization'
const SESSION_ID_HEADER = 'SessionId'
const APPROOV_PLACEHOLDER_SECRET = 'approov_base64url_secret_here'

const ROUTE_BINDING_HEADERS = Object.freeze({
    '/token-binding': [AUTH_HEADER],
    '/token-double-binding': [AUTH_HEADER, SESSION_ID_HEADER]
})

const approovState = {
    approovEnabled: true,
    tokenBindingEnabled: true
}

function hasText(value) {
    return value != null && String(value).trim() !== ''
}

function formatTimestamp(date = new Date()) {
    const pad = value => String(value).padStart(2, '0')
    const year = date.getFullYear()
    const month = pad(date.getMonth() + 1)
    const day = pad(date.getDate())
    const hour = pad(date.getHours())
    const minute = pad(date.getMinutes())
    const second = pad(date.getSeconds())
    return `${year}-${month}-${day} ${hour}:${minute}:${second}`
}

function logEvent(level, event, payload) {
    const message = `[${formatTimestamp()}] ${event} ${JSON.stringify(payload)}`
    if (level === 'error') {
        console.error(message)
        return
    }
    if (level === 'warn') {
        console.warn(message)
        return
    }
    console.log(message)
}

function logSecretIssue(message) {
    if (!hasText(message)) {
        return
    }
    logEvent('error', 'approov.secret.error', { message })
}

function isBase64Url(value) {
    return /^[A-Za-z0-9_-]+$/.test(value) && value.length % 4 !== 1
}

function loadApproovSecret() {
    const secret = process.env.APPROOV_BASE64URL_SECRET
    if (!hasText(secret) || secret.trim() === APPROOV_PLACEHOLDER_SECRET) {
        return { secret: null, error: 'Required secret is not set' }
    }

    const trimmed = secret.trim()
    if (!isBase64Url(trimmed)) {
        return { secret: null, error: 'Required secret is invalid' }
    }

    try {
        const decoded = Buffer.from(trimmed, 'base64url')
        const normalized = trimmed.replace(/=+$/, '')
        if (decoded.length === 0 || decoded.toString('base64url') !== normalized) {
            return { secret: null, error: 'Required secret is invalid' }
        }
        return { secret: decoded, error: null }
    } catch (err) {
        return { secret: null, error: 'Required secret is invalid' }
    }
}

let approovSecret
let approovSecretError
const secretResult = loadApproovSecret()
approovSecret = secretResult.secret
approovSecretError = secretResult.error
if (approovSecretError) {
    logSecretIssue(approovSecretError)
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

function createUnauthorizedError(reason) {
    const error = new Error('Unauthorized')
    error.status = 401
    error.code = hasText(reason) ? `approov_${String(reason).trim()}` : 'approov_unauthorized'
    return error
}

function computeBindingHash(value) {
    return crypto.createHash('sha256').update(value, 'utf8').digest('base64')
}

function toBase64Url(value) {
    return String(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function timingSafeEqualString(value, expected) {
    const valueBuffer = Buffer.from(String(value), 'utf8')
    const expectedBuffer = Buffer.from(String(expected), 'utf8')
    if (valueBuffer.length !== expectedBuffer.length) {
        return false
    }
    return crypto.timingSafeEqual(valueBuffer, expectedBuffer)
}

function isBindingValid(bindingValue, claims) {
    const expected = claims && claims.pay
    if (!hasText(expected)) {
        return false
    }

    const expectedValue = String(expected).trim()
    const computedBase64 = computeBindingHash(bindingValue)
    const computedBase64Url = toBase64Url(computedBase64)
    const matchBase64 = timingSafeEqualString(computedBase64, expectedValue)
    const matchBase64Url = timingSafeEqualString(computedBase64Url, expectedValue)
    return matchBase64 || matchBase64Url
}

function trimOrNull(value) {
    if (!hasText(value)) {
        return null
    }
    return String(value).trim()
}

function getBindingHeaders(path) {
    return ROUTE_BINDING_HEADERS[path] || []
}

function requiredHeaders(bindingHeaders) {
    if (!approovState.approovEnabled) {
        return []
    }

    const headers = [APPROOV_HEADER]
    if (approovState.tokenBindingEnabled && bindingHeaders.length > 0) {
        headers.push(...bindingHeaders)
    }
    return headers
}

function getBindingValue(ctx, bindingHeaders) {
    const values = []
    for (const header of bindingHeaders) {
        const value = trimOrNull(ctx.get(header))
        if (!hasText(value)) {
            return null
        }
        values.push(value)
    }

    return values.join('')
}

function logRequest(ctx) {
    const summary = hasText(ctx.state.approovSummary)
        ? ctx.state.approovSummary
        : (ctx.status >= 400 ? 'request_failed' : 'request_ok')
    const payload = {
        summary,
        method: ctx.method,
        path: ctx.path,
        status: ctx.status,
        ip: ctx.ip,
        port: ctx.request.socket ? ctx.request.socket.localPort : null,
        approovEnabled: approovState.approovEnabled,
        tokenBindingEnabled: approovState.tokenBindingEnabled,
        required_headers: ctx.state.approovRequiredHeaders || [],
        secret_error: approovSecretError || undefined
    }
    logEvent(ctx.status >= 500 ? 'error' : 'info', 'http.request.completed', payload)
}

function failUnauthorized(ctx, reason) {
    if (hasText(reason)) {
        ctx.state.approovSummary = `approov_failed:${reason}`
        ctx.state.approovFailureReason = reason
    }
    return createUnauthorizedError(reason)
}

async function verifyApproovToken(ctx, next) {
    const bindingHeaders = getBindingHeaders(ctx.path)
    ctx.state.approovRequiredHeaders = requiredHeaders(bindingHeaders)

    if (!approovState.approovEnabled) {
        ctx.state.approovSummary = 'approov_disabled'
        await next()
        return
    }

    if (approovSecretError) {
        const reason = approovSecretError === 'Required secret is not set'
            ? 'secret_missing'
            : 'secret_invalid'
        throw failUnauthorized(ctx, reason)
    }

    const token = ctx.get(APPROOV_HEADER)
    if (!hasText(token)) {
        throw failUnauthorized(ctx, 'missing_approov_token')
    }

    try {
        const claims = jwt.verify(token.trim(), approovSecret, { algorithms: ['HS256'] })
        const exp = claims && claims.exp
        if (!Number.isFinite(Number(exp))) {
            throw failUnauthorized(ctx, 'token_missing_exp')
        }
        ctx.state.approovClaims = claims
    } catch (err) {
        if (err && err.status === 401) {
            throw err
        }
        throw failUnauthorized(ctx, 'token_verification_failed')
    }

    if (approovState.tokenBindingEnabled && bindingHeaders.length > 0) {
        const bindingValue = getBindingValue(ctx, bindingHeaders)
        if (!hasText(bindingValue)) {
            throw failUnauthorized(ctx, 'missing_binding_header')
        }
        if (!isBindingValid(bindingValue, ctx.state.approovClaims)) {
            throw failUnauthorized(ctx, 'binding_mismatch')
        }
    }

    ctx.state.approovSummary = 'approov_ok'
    await next()
}

api.use(async (ctx, next) => {
    try {
        await next()
    } finally {
        logRequest(ctx)
    }
})

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
    response.sessionIdHeaderPresent = hasText(ctx.get(SESSION_ID_HEADER))
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
