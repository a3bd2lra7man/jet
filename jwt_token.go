package jwt

type JwtToken struct {
	Id    string `bson:"_id"`
	Token string
	// refresh token
	Refresh string
}
