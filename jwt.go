package jwt

import (
	"errors"
	"fmt"
	"os"

	_jwt "github.com/golang-jwt/jwt"
)

func jwtValidator(token *_jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*_jwt.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	}
	return []byte(os.Getenv("API_SECRET")), nil
}

func Verify(token string) error {
	_, err := _jwt.Parse(token, jwtValidator)
	if err != nil {
		return err
	}
	return nil
}

func parseClaims(token string) (*_jwt.MapClaims, error) {
	claims := _jwt.MapClaims{}
	_, err := _jwt.ParseWithClaims(token, claims, jwtValidator)
	return &claims, err
}

func VerifyAudience(token string, audience string) error {
	claims, err := parseClaims(token)
	if err != nil {
		return err
	}
	isValid := claims.VerifyAudience(audience, true)
	if !isValid {
		return errors.New("audience failed")
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
		return errors.New("Claims not found")
	}

	isValid := verifier(claim)
	if !isValid {
		return errors.New("Claims not valid")
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
		return errors.New("audience failed")
	}

	claim := (*claims)[key]
	if claim == nil {
		return errors.New("Claims not found")
	}

	isValid = verifier(claim)
	if !isValid {
		return errors.New("Claims not valid")
	}

	return nil
}
