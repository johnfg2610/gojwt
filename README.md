# GoJWT

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a78debb3006344fcb45dd741cd346725)](https://app.codacy.com/manual/johnfg10/gojwt?utm_source=github.com&utm_medium=referral&utm_content=johnfg2610/gojwt&utm_campaign=Badge_Grade_Dashboard)

GoJWT is a middleware chain designed to allow easy authentication using JWT as the authentication mechanism. Designed from the ground up using Squares wonderful jose library which offers high security great support and efficent decoding. 

## Design
This package has been broke down into 3 explicit stages each of which can be easily replaced if required by your application ive outlined the responsiblity of each below

### Verifer
The verifier is responsible for verifiying the token is from who it should be from, if there is any errors it is stored in the context using the constant `ContextJWTError` otherwise the JWT token is put into the context under the constant key `ContextJWTObject` and claims under `ContextJWTClaims` this can be easily retrived by other middleware using the provided helper methods

### Claims Validator
The claims validator is responsible for validating the claims in the token such as the NBF(Not before time), Expiry and Issuer any error found will be placed in the context under `ContextValidatorError`

### Claims terminator 
The claims terminator is responsible for terminating the connection if the above have failed. this was split out as it optionally allows you to add another middleware in between this and claims validator to log the problem with claims, this isnt provided out of the box as there is far to many options for logging and I dont think this should be our decision to make.

