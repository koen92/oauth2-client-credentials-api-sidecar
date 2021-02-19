package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"net/url"
	"time"
)

// Parse env var containing x509 rsa key, return error if parsing fails
func parseRsaPrivateKeyFromPem(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try again to parse with PKCS8 instead of PKCS1
		privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		priv, ok := privInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("cannot cast Private Key: Not an RSA key")
		}

		return priv, nil
	}
	return privKey, nil
}

// Parse env var containing x509 cert, return error if parsing fails
func parseX509CertFromPem(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

// Sign a JWT token using x509 cert and key
func signAuthJwt(payload map[string]interface{}) (string, error) {
	fingerprint := sha1.Sum(auth_x509_cert_parsed.Raw)
	fingerprintB64 := b64.StdEncoding.EncodeToString(fingerprint[:])

	s, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.RS256,
			Key:       auth_x509_key_parsed,
		},
		&jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{
				"x5t": fingerprintB64,
			},
		},
	)

	if err != nil {
		return "", err
	}

	return jwt.Signed(s).Claims(payload).CompactSerialize()
}

// Create a JWT token for jwt-bearer grant
func createAuthJwt() (string, error) {
	currentTime := time.Now().Unix()

	payload := map[string]interface{}{
		"aud": auth_endpoint_url,
		"iss": auth_client_id,
		"sub": auth_client_id,
		"jti": uuid.New().String(),
		"iat": currentTime,
		"nbf": currentTime,
		"exp": currentTime + 60,
	}

	return signAuthJwt(payload)
}

// Construct request body for an access token request using x509 client cert and private key
func getOuath2AuthAccessTokenWithX509() {
	authToken, err := createAuthJwt()

	if err != nil {
		// TODO: how to handle this?
		log.Println(err)
		return
	}

	request_body := url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {auth_client_id},
		"client_secret":         {auth_client_secret},
		"client_assertion":      {authToken},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	}
	doOauthRequest(request_body)
}
