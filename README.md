# Approov QuickStart - NodeJS Token Check

[Approov](https://approov.io) is an API security solution used to verify that requests received by your backend services originate from trusted versions of your mobile apps.

This repo implements the Approov server-side request verification code for the NodeJS Koa framework, which performs the Approov token check before allowing valid traffic to be processed by the API endpoint.


## Approov Integration Quickstart

First, get your Approov Secret with the [Appoov CLI](https://approov.io/docs/latest/approov-installation/index.html#initializing-the-approov-cli):

```bash
approov secret -get base64
```

Next, add the [Approov secret](https://approov.io/docs/latest/approov-usage-documentation/#account-secret-key-export) to your project `.env` file:

```env
APPROOV_BASE64_SECRET=approov_base64_secret_here
```

Now, add to your `package.json` file the [JWT dependency](https://github.com/auth0/node-jsonwebtoken#readme):

```json
"jsonwebtoken": "^8.5.1"
```

Next, in your code require the [JWT dependency](https://github.com/auth0/node-jsonwebtoken#readme):

```javascript
const jwt = require('jsonwebtoken')
```

Now, read the Approov secret from the environment and put it into a constant:

```javascript
const dotenv = require('dotenv').config()
const approovBase64Secret = dotenv.parsed.APPROOV_BASE64_SECRET;
const approovSecret = Buffer.from(approovBase64Secret, 'base64')
```

Next, verify the Approov token:

```javascript
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
```

Finally, add the function as a middleware to protect all your API endpoints with the Approov token check:

```javascript
// @IMPORTANT: Always add the `verifyApproovToken` middleware function before
//             your endpoints declaration.
//
// Using `["/"]` protects all endpoints in your API. Example to protect only
// specific endpoints: `["/checkout", "/payments", "/etc"]`.
// When adding an endpoint `/example` you are also protecting their child
// endpoints, like `/example/content`, `/example/content/:id`, etc. .
router.use(["/"], verifyApproovToken)
```

Not enough details in the bare bones quickstart? No worries, check the [detailed quickstarts](QUICKSTARTS.md) that contain a more comprehensive set of instructions, including how to test the Approov integration.


## More Information

* [Approov Overview](OVERVIEW.md)
* [Detailed Quickstarts](QUICKSTARTS.md)
* [Examples](EXAMPLES.md)
* [Testing](TESTING.md)


## Issues

If you find any issue while following our instructions then just report it [here](https://github.com/approov/quickstart-nodejs-koa-token-check/issues), with the steps to reproduce it, and we will sort it out and/or guide you to the correct path.


## Useful Links

If you wish to explore the Approov solution in more depth, then why not try one of the following links as a jumping off point:

* [Approov Free Trial](https://approov.io/signup)(no credit card needed)
* [Approov Get Started](https://approov.io/product/demo)
* [Approov QuickStarts](https://approov.io/docs/latest/approov-integration-examples/)
* [Approov Docs](https://approov.io/docs)
* [Approov Blog](https://approov.io/blog/)
* [Approov Resources](https://approov.io/resource/)
* [Approov Customer Stories](https://approov.io/customer)
* [Approov Support](https://approov.zendesk.com/hc/en-gb/requests/new)
* [About Us](https://approov.io/company)
* [Contact Us](https://approov.io/contact)
