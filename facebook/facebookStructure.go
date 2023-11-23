package facebook

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

type FacebookUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

var (
	oauthConf = &oauth2.Config{
		ClientID:     "2037951636580578",
		ClientSecret: "03b80fc8f004fb3cfdcde4b75ab99b39",
		RedirectURL:  "http://localhost:3000/oauth2callback",
		Scopes:       []string{"public_profile"},
		Endpoint:     facebook.Endpoint,
	}
	oauthStateString = "thisshouldberandom"
)
