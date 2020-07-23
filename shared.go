package gojwt

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/square/go-jose/v3"
	"github.com/square/go-jose/v3/jwt"
)

//ContextKey used to access values in the context
type ContextKey string

const (
	//ContextJWTError is used to access the JWT error in the context
	ContextJWTError ContextKey = "JWT_ERROR"
	//ContextJWTObject is used to access the JWT object in the context
	ContextJWTObject ContextKey = "JWT_OBJECT"
	//ContextJWTClaims is used to access the JWT claims in the context
	ContextJWTClaims ContextKey = "JWT_CLAIMS"
	//ContextValidatorError is used to access the error provided by validators
	ContextValidatorError ContextKey = "VALIDATOR_ERROR"
	//ContextJWTInfo is used to get jwt info from the context
	ContextJWTInfo ContextKey = "JWT_INFO"
	//ContextJWTResolverError is used to get a error from the resolver
	ContextJWTResolverError ContextKey = "JWT_RESOLVER_ERROR"

	//ErrInvalidToken is returned as a error if the token was invalid
	ErrInvalidToken = "The token provided was invalid"
)

//GetJWKSetFromOpenIDURL creates a jsonwebkeyset from the JWK url provided
func GetJWKSetFromOpenIDURL(JWKURL string) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(JWKURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 199 && resp.StatusCode < 301 {
		return nil, errors.New("Response code was not sucessfull")
	}

	byteArr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var keySet jose.JSONWebKeySet

	err = json.Unmarshal(byteArr, &keySet)

	return &keySet, err
}

//GetClaimsFromContext will get the claims from the context or return a error stating that it was unable to
func GetClaimsFromContext(ctx context.Context) (*jwt.Claims, error) {
	claims, exist := ctx.Value(ContextJWTClaims).(*jwt.Claims)
	if !exist {
		return nil, errors.New("JWT claims not found in context, Are you sure this was called after Middleware?")
	}
	return claims, nil
}

//GetTokenFromContext will get any tokens from context or return a error stating that it was unable to
func GetTokenFromContext(ctx context.Context) (*jwt.JSONWebToken, error) {
	jwt, exist := ctx.Value(ContextJWTObject).(*jwt.JSONWebToken)
	if !exist {
		return nil, errors.New("JWT object not found in context, Are you sure this was called after Middleware?")
	}
	return jwt, nil
}

//GetErrorFromContext will get any error from the current context or return a error stating that it was unable to
func GetErrorFromContext(ctx context.Context) (error, error) {
	err, exist := ctx.Value(ContextJWTError).(error)
	if !exist {
		return nil, errors.New("Error could not be found in context")
	}
	return err, nil
}

//GetValidatorErrorFromContext will get any validator error from the current context or return a error stating that it was unable to
func GetValidatorErrorFromContext(ctx context.Context) (error, error) {
	err, exist := ctx.Value(ContextValidatorError).(error)
	if !exist {
		return nil, errors.New("Validator error could not be found in context")
	}
	return err, nil
}

//GetResolverErrorFromContext will get any resolver error from the current context or return a error stating that it was unable to
func GetResolverErrorFromContext(ctx context.Context) (error, error) {
	err, exist := ctx.Value(ContextJWTResolverError).(error)
	if !exist {
		return nil, errors.New("Error could not be found in context")
	}
	return err, nil
}

func GetJWTInfoFromContext(ctx context.Context) (*JWTInfo, error) {
	jwt, exists := ctx.Value(ContextJWTInfo).(*JWTInfo)
	if !exists {
		return nil, errors.New("JWTInfo did not exist in context")
	}
	return jwt, nil
}
