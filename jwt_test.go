package jwt_test

import (
	"os"
	"testing"
	"time"

	"github.com/a3bd2lra7man/jwt"
	_jwt "github.com/golang-jwt/jwt"
)

func createJwt(claims map[string]interface{}, expireTime time.Duration, aud string) string {
	_claims := _jwt.MapClaims{}
	_claims["aud"] = aud
	_claims["exp"] = time.Now().Add(expireTime).Unix()
	for k, v := range claims {
		_claims[k] = v
	}
	str, _ := _jwt.NewWithClaims(_jwt.SigningMethodHS256, _claims).SignedString([]byte(os.Getenv("API_SECRET")))
	return str
}

func TestVerify(t *testing.T) {

	tests := []struct {
		name   string
		token  string
		wanted bool
	}{
		{
			name:   "failed case",
			token:  "un valid token",
			wanted: false,
		},
		{
			name:   "expired case",
			token:  createJwt(map[string]interface{}{}, -time.Hour, ""),
			wanted: false,
		},
		{
			name:   "success case",
			token:  createJwt(map[string]interface{}{}, time.Hour, ""),
			wanted: true,
		},
	}

	for _, test := range tests {
		var err = jwt.Verify(test.token)
		if (err == nil) != test.wanted {
			t.Fatalf("in %s expected: %v, got: %v", test.name, test.wanted, err)
		}
	}
}

func TestVerifyAudience(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		wanted bool
	}{
		{
			name:   "failed case",
			token:  createJwt(map[string]interface{}{}, time.Hour, ""),
			wanted: false,
		},
		{
			name:   "success case",
			token:  createJwt(map[string]interface{}{}, time.Hour, "client"),
			wanted: true,
		},
	}

	for _, test := range tests {
		var err = jwt.VerifyAudience(test.token, "client")
		if (err == nil) != test.wanted {
			t.Fatalf("in %s expected: %v, got: %v", test.name, test.wanted, err)
		}
	}
}

func TestVerifyClaims(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		wanted bool
	}{
		{
			name: "failed case",
			token: func() string {
				claims := make(map[string]interface{})
				return createJwt(claims, time.Hour, "")
			}(),
			wanted: false,
		},
		{
			name: "success case",
			token: func() string {
				claims := make(map[string]interface{})
				claims["roles"] = []string{"admin"}
				return createJwt(claims, time.Hour, "")
			}(),
			wanted: true,
		},
	}

	for _, test := range tests {
		var err = jwt.VerifyClaim(test.token, "roles", func(claim interface{}) bool {
			values, ok := claim.([]interface{})
			if !ok {
				return false
			}
			for _, val := range values {
				if val == "admin" {
					return true
				}
			}
			return false
		})
		if (err == nil) != test.wanted {
			t.Fatalf("in %s expected: %v, got: %v", test.name, test.wanted, err)
		}
	}
}

func TestVerifyClaimsComplex(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		wanted bool
	}{
		{
			name: "success case complex object",
			token: func() string {
				claims := make(map[string]interface{})
				rolesMap := make(map[string]interface{})
				permissions := []string{"create", "read"}
				rolesMap["admin"] = true
				rolesMap["permissions"] = permissions
				claims["roles"] = rolesMap
				return createJwt(claims, time.Hour, "")
			}(),
			wanted: true,
		},
	}

	for _, test := range tests {
		var err = jwt.VerifyClaim(test.token, "roles", func(claim interface{}) bool {
			rolesMap, ok := claim.(map[string]interface{})
			if !ok {
				return false
			}

			adminBool, ok := rolesMap["admin"].(bool)
			if !ok {
				return false
			}

			if adminBool != true {
				return false
			}

			permissions, ok := rolesMap["permissions"].([]interface{})
			if !ok {
				return false
			}

			for _, val := range permissions {
				if val == "create" {
					return true
				}
			}

			return false
		})
		if (err == nil) != test.wanted {
			t.Fatalf("in %s expected: %v, got: %v", test.name, test.wanted, err)
		}
	}
}

func TestVerifyAudWithClaims(t *testing.T) {
	tests := []struct {
		name   string
		token  string
		wanted bool
	}{
		{
			name: "failed case audience failed",
			token: func() string {
				claims := make(map[string]interface{})
				return createJwt(claims, time.Hour, "client")
			}(),
			wanted: false,
		},
		{
			name: "failed case claims failed",
			token: func() string {
				claims := make(map[string]interface{})
				claims["roles"] = []string{"partner"}
				return createJwt(claims, time.Hour, "admin")
			}(),
			wanted: false,
		},
		{
			name: "success case",
			token: func() string {
				claims := make(map[string]interface{})
				claims["roles"] = []string{"admin"}
				return createJwt(claims, time.Hour, "admin")
			}(),
			wanted: true,
		},
	}

	for _, test := range tests {
		var err = jwt.VerifyAudWithClaims(test.token, "admin", "roles", func(claim interface{}) bool {
			values, ok := claim.([]interface{})
			if !ok {
				return false
			}
			for _, val := range values {
				if val == "admin" {
					return true
				}
			}
			return false
		})
		if (err == nil) != test.wanted {
			t.Fatalf("in %s expected: %v, got: %v", test.name, test.wanted, err)
		}
	}
}
