package gojwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

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

	//ErrInvalidToken is returned as a error if the token was invalid
	ErrInvalidToken = "The token provided was invalid"
)

//JWTMiddleware is used to mange JWT middleware
type JWTMiddleware struct {
	JWKS        *jose.JSONWebKeySet
	Issuer      string
	EnableDebug bool
}

//NewJWTMiddleware is used to greate a new JWTMiddleware
func NewJWTMiddleware(jwks *jose.JSONWebKeySet, issuer string) JWTMiddleware {
	return JWTMiddleware{
		JWKS:        jwks,
		Issuer:      issuer,
		EnableDebug: false,
	}
}

//NewJWTMiddlewareFromOpenID creates a new JWTMiddleware from a OpenID definition
func NewJWTMiddlewareFromOpenID(baseURL string) (*JWTMiddleware, error) {

	resp, err := http.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	byteArr, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var bodyWellKnown OpenIDWellKnown
	err = json.Unmarshal(byteArr, &bodyWellKnown)
	if err != nil {
		return nil, err
	}

	keyset, err := GetJWKSetFromOpenIDURL(bodyWellKnown.JWKSURL)
	if err != nil {
		return nil, err
	}

	middleware := NewJWTMiddleware(keyset, bodyWellKnown.Issuer)
	return &middleware, nil

}

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

//Verifier validtes every request to test if it matches the provided JWKs
func (mid *JWTMiddleware) Verifier(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerHeaderRaw := r.Header.Get("Authorization")
		if mid.EnableDebug {
			fmt.Println("Raw bearer token: " + bearerHeaderRaw)
		}
		bearerHeader := strings.Replace(bearerHeaderRaw, "Bearer ", "", -1)
		if mid.EnableDebug {
			fmt.Println("Cleaned bearer token: " + bearerHeader)
		}

		tok, err := jwt.ParseSigned(bearerHeader)

		if err != nil {
			if mid.EnableDebug {
				fmt.Println("Error getting claims: " + err.Error())
			}
			ctx := context.WithValue(r.Context(), ContextJWTError, err)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		var claims *jwt.Claims
		for _, jwk := range mid.JWKS.Keys {
			err = tok.Claims(jwk, &claims)

			if err == nil {
				break
			}
		}

		if claims == nil {
			if mid.EnableDebug {
				fmt.Println("Error no claims found: " + err.Error())
			}
			ctx := context.WithValue(r.Context(), ContextJWTError, err)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		ctx := context.WithValue(r.Context(), ContextJWTObject, tok)
		ctx = context.WithValue(r.Context(), ContextJWTClaims, claims)

		if mid.EnableDebug {
			fmt.Println("Verifier passed, calling next http")
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

//ClaimsValidator will read claim values from context and validate, this includes ISS, EXP, NBF. if any validations fail a error will be logged under ContextValidatorError
func (mid *JWTMiddleware) ClaimsValidator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := GetClaimsFromContext(r.Context())
		if err != nil {
			if mid.EnableDebug {
				fmt.Println("Error getting claims: " + err.Error())
			}
			ctx := context.WithValue(r.Context(), ContextValidatorError, err)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		err = claims.ValidateWithLeeway(jwt.Expected{
			Issuer: mid.Issuer,
		}, time.Second*30)

		if err != nil {
			if mid.EnableDebug {
				fmt.Println("Error invalid token: " + err.Error())
			}
			ctx := context.WithValue(r.Context(), ContextValidatorError, err)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if mid.EnableDebug {
			fmt.Println("Claims validator passed")
		}
		next.ServeHTTP(w, r)
	})
}

//ClaimsTerminator will read any errors generated by claims validator and if any are found end the request with a `401` error code, this was seperated out to allow for more efficent logging to your chosen logging platform.
func (mid *JWTMiddleware) ClaimsTerminator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err, _ := GetValidatorErrorFromContext(r.Context())

		if err != nil {
			fmt.Println("Error was not nil: " + err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if mid.EnableDebug {
			fmt.Println("Claims terminator passed")
		}
		next.ServeHTTP(w, r)
	})
}
