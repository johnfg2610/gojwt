package gojwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"

	"github.com/square/go-jose"
)

type JWTError error
type ContextKey string

const (
	CONTEXT_JWT_ERROR  ContextKey = "JWT_ERROR"
	CONTEXT_JWT_OBJECT ContextKey = "JWT_OBJECT"
)

type JWTMiddleware struct {
	JWKS   *jose.JSONWebKeySet
	Issuer string
}

func NewJWTMiddleware(jwks *jose.JSONWebKeySet, issuer string) JWTMiddleware {
	return JWTMiddleware{
		JWKS:   jwks,
		Issuer: issuer,
	}
}

func NewJWTMiddlewareFromOpenID(baseURL string) (*JWTMiddleware, error) {

	resp, err := http.Get(path.Join(baseURL + "/.well-known/openid-configuration"))
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

	var bodyWellKnown OpenidWellKnown
	err = json.Unmarshal(byteArr, &bodyWellKnown)
	if err != nil {
		return nil, err
	}

	keyset, err := GetJWKSetFromOpenidURL(bodyWellKnown.JWKSURL)
	if err != nil {
		return nil, err
	}

	middleware := NewJWTMiddleware(keyset, bodyWellKnown.Issuer)
	return &middleware, nil

}

func GetJWKSetFromOpenidURL(JWKURL string) (*jose.JSONWebKeySet, error) {
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

//TODO wrap errors
func (mid *JWTMiddleware) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerHeaderRaw := r.Header.Get("Authorization")
		fmt.Print(bearerHeaderRaw)
		bearerHeader := strings.Replace(bearerHeaderRaw, "Bearer ", "", 0)
		fmt.Print(bearerHeader)
		fmt.Println(bearerHeader)
		//tok, err := jwt.ParseSigned(bearerHeader)

		object, err := jose.ParseSigned(bearerHeader)
		if err != nil {
			ctx := context.WithValue(r.Context(), CONTEXT_JWT_ERROR, err)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		//we have a valid key
		var out interface{}
		for _, jwk := range mid.JWKS.Keys {
			out, err = object.Verify(jwk.Public())
			if err != nil {
				ctx := context.WithValue(r.Context(), CONTEXT_JWT_ERROR, err)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			break
		}

		ctx := context.WithValue(r.Context(), CONTEXT_JWT_OBJECT, out)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
