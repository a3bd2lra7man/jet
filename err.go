package jwt

type jwtError uint8

const (
	UnAuthenticated jwtError = 0
	UnAuthorized    jwtError = 1
	UnExpected      jwtError = 2
)

func (e jwtError) Error() string {
	switch e {
	case UnAuthenticated:
		return "UnAuthenticated"
	case UnAuthorized:
		return "UnAuthorized"
	case UnExpected:
		return "UnExpected"
	}
	return "error"
}
