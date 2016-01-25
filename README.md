[![Build Status](https://travis-ci.org/ToastShaman/dropwizard-auth-jwt.svg?branch=master)](https://travis-ci.org/ToastShaman/dropwizard-auth-jwt)

# dropwizard-auth-jwt

An implementation of the JSON Web Token (JWT) draft-ietf-oauth-json-web-token-20 for Dropwizard.

## What is it?
JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred between two parties.
The claims in a JWT are encoded as a JSON object that is digitally signed using JSON Web Signature (JWS).

Check out http://jwt.io/

## What's new in v0.9.2-0
* Updated the dependencies to Dropwizard 0.9.2.

## What's new in v0.9.1-1
* Added support for CachingAuthenticator.

## What's new in v0.9.1-0
* Added support for Dropwizard 0.9.x.
* Support for extracting JWT tokens from cookies.

## Getting Started

To use this library in your project you can download it from Maven Central.

For Dropwizard 0.9.1 use:
```xml
<dependency>
    <groupId>com.github.toastshaman</groupId>
    <artifactId>dropwizard-auth-jwt</artifactId>
    <version>0.9.2-0</version>
</dependency>
```

For Dropwizard 0.8.1 use:

```xml
<dependency>
    <groupId>com.github.toastshaman</groupId>
    <artifactId>dropwizard-auth-jwt</artifactId>
    <version>0.8.1-1</version>
</dependency>
```

## Example
See this [code example](https://github.com/ToastShaman/dropwizard-auth-jwt/tree/master/src/test/java/com/github/toastshaman/dropwizard/auth/jwt/example) 
if you want to use this code your dropwizard application. Once you have started the example application here are some 
sample requests to generate a valid and an expired token:

```
curl -X GET -H "Cache-Control: no-cache" 'http://localhost:8080/jwt/generate-valid-token'
```

or you can create an invalid token instead to see a failure case with: 

```
curl -X GET -H "Cache-Control: no-cache" 'http://localhost:8080/jwt/generate-expired-token'
```

Once you have a token, you can send it to the following endpoint to get some information about the logged in user:

```
curl -X GET \
-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE0NDkzMTQwOTUsInN1YiI6Imdvb2QtZ3V5In0.oFXdelQECJrw6_e4gR1HU3ljFvY8zmf2EHDsBnnea7n2UDBipmNDbx3bw-Bzzq-FwtEO6qzageK2jbJxM6JHbQ" \
-H "Cache-Control: no-cache" 'http://localhost:8080/jwt/check-token'
```

## License
Apache License Version 2.0 

http://apache.org/licenses/LICENSE-2.0.txt

## Thanks To
A special thanks goes to [MartinSahlen](https://github.com/MartinSahlen) for providing a Gist with the Dropwizard 8 implementation of the AuthFactory.

A special thanks goes to [Kimble](https://github.com/kimble) for adding cookie support.

A special thanks goes to [alexitooi](https://github.com/alexitooi) for adding support for the CachingAuthenticator.
