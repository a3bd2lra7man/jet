package jwt

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	_jwt "github.com/golang-jwt/jwt"
)

func validator(token *_jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*_jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(os.Getenv("API_SECRET")), nil
}

func Verify(token string) error {
	_, err := _jwt.Parse(token, validator)
	if err != nil {
		return err
	}
	return nil
}

func parseClaims(token string) (*_jwt.MapClaims, error) {
	claims := _jwt.MapClaims{}
	_, err := _jwt.ParseWithClaims(token, claims, validator)
	if err != nil {
		return &claims, UnAuthenticated
	}
	return &claims, nil
}

func VerifyAudience(token string, audience string) error {
	claims, err := parseClaims(token)
	if err != nil {
		return err
	}
	isValid := claims.VerifyAudience(audience, true)
	if !isValid {
		return UnAuthorized
	}
	return nil
}

type claimVerifier func(interface{}) bool

func VerifyClaim(token string, key string, verifier claimVerifier) error {
	claims, err := parseClaims(token)
	if err != nil {
		return err
	}

	claim := (*claims)[key]
	if claim == nil {
		return UnAuthorized
	}

	isValid := verifier(claim)
	if !isValid {
		return UnAuthorized
	}

	return nil
}

func VerifyAudWithClaims(token string, audience string, key string, verifier claimVerifier) error {
	claims, err := parseClaims(token)
	if err != nil {
		return err
	}

	isValid := claims.VerifyAudience(audience, true)
	if !isValid {
		return UnAuthorized
	}

	claim := (*claims)[key]
	if claim == nil {
		return UnAuthorized
	}

	isValid = verifier(claim)
	if !isValid {
		return UnAuthorized
	}

	return nil
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func Create(claims map[string]interface{}, expireTime time.Duration, aud string) (JwtToken, error) {
	_claims := _jwt.MapClaims{}
	_claims["aud"] = aud
	_claims["exp"] = time.Now().Add(expireTime).Unix()
	for k, v := range claims {
		_claims[k] = v
	}
	str, err := _jwt.NewWithClaims(_jwt.SigningMethodHS256, _claims).SignedString([]byte(os.Getenv("API_SECRET")))

	if err != nil {
		return JwtToken{}, err
	}
	return JwtToken{Token: str, Refresh: generateRandomString(100)}, nil
}

func Get(token, refresh string) (JwtToken, error) {
	jwtToken, err := get(JwtToken{Token: token, Refresh: refresh})
	if err != nil {
		return JwtToken{}, err
	}
	return jwtToken, err
}

func Delete(id string) error {
	return delete(id)
}

func GetClaim(token string, claim string) (interface{}, error) {
	t, _, err := new(_jwt.Parser).ParseUnverified(token, _jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := t.Claims.(jwt.MapClaims)

	if !ok {
		return nil, UnExpected
	}

	return claims[claim], nil
}
