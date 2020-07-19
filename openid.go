package gojwt

//OpenIDWellKnown is used to map a OpenID discovery document to the values we need
type OpenIDWellKnown struct {
	Issuer  string `json:"issuer"`
	JWKSURL string `json:"jwks_uri"`
}
