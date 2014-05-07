[![Build Status](https://travis-ci.org/ToastShaman/dropwizard-auth-jwt.svg?branch=master)](https://travis-ci.org/ToastShaman/dropwizard-auth-jwt)

# dropwizard-auth-jwt

An implementation of the JSON Web Token (JWT) draft-ietf-oauth-json-web-token-20 for dropwizard 7.0.

Work in progress...

# Todo
* Support for RSA encrypted tokens
* Support for tokens with the "none" algorithm
* Token verifiers for expiry date etc.
* Integrate with Dropwizard's AuthProvider
* Implement the SystemClock for expiry times (Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.)
* Implement more claims such as "nbf" etc.
* Verify that we compare the signatures correctly
* ...