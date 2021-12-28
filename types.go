package auth

type userCookie struct {
	userID        string
	tokenLocation string
}

// Authorization specifies user authorization status
type Authorization struct {
	Authorized    bool   `json:"authorized"`
	UserID        string `json:"userId"`
	TokenLocation string `json:"tokenLocation"`
}

// Token is a token structure for sundstedt.us
type Token struct {
	SA        bool     `json:"sa"`
	Evenson   bool     `json:"evenson"`
	Woodard   bool     `json:"woodard"`
	Sundstedt bool     `json:"sundstedt"`
	Groups    []string `json:"groups"`
}

// PassSet is a username password combination
type PassSet struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// UserInfo contains the user's ID and token
type UserInfo struct {
	UserID string `json:"userId"`
	Token  Token  `json:"token"`
}
