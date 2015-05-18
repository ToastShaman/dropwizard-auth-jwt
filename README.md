[![Build Status](https://travis-ci.org/ToastShaman/dropwizard-auth-jwt.svg?branch=master)](https://travis-ci.org/ToastShaman/dropwizard-auth-jwt)

# dropwizard-auth-jwt

An implementation of the JSON Web Token (JWT) draft-ietf-oauth-json-web-token-20 for Dropwizard 7 and 8.

## What is it?
JSON Web Token (JWT) is a compact URL-safe means of representing claims to be transferred between two parties.
The claims in a JWT are encoded as a JSON object that is digitally signed using JSON Web Signature (JWS).

Check out http://jwt.io/

## Getting Started

To use this library in your project you can download it from Maven Central.

For Dropwizard 0.7.1 use:

```xml
<dependency>
    <groupId>com.github.toastshaman</groupId>
    <artifactId>dropwizard-auth-jwt</artifactId>
    <version>0.7.1-1</version>
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
if you want to use this code your dropwizard application.

## License
Apache License Version 2.0 
http://apache.org/licenses/LICENSE-2.0.txt

## Thanks To
A special thanks goes to @MartinSahlen for providing a Gist with the Dropwizard 8 implementation of the AuthFactory.