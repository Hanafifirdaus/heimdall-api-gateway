package middleware

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Auth struct {
	oauth2Google *oauth2.Config
}

var (
	// TODO: randomize it
	oauthStateString  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	googleOauthConfig *oauth2.Config
)

func CreateAuth(oauth2Google *oauth2.Config) Auth {
	return Auth{oauth2Google}
}

func ConfigOauth2Google() *oauth2.Config {
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8000/v5/google/callback",
		ClientID:     "642584725255-00pc0njmjra4a8le6qvnaoblvs0oou0m.apps.googleusercontent.com",
		ClientSecret: "rM4o3pxRXOZIbpWGYxz235ah",
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
		Endpoint:     google.Endpoint,
	}
	return googleOauthConfig
}

func (a Auth) HandleGoogleLogin(c *gin.Context) {
	url := a.oauth2Google.AuthCodeURL(oauthStateString)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (a Auth) HandleGoogleCallback(c *gin.Context) {

	content, err := a.GetUserInfo(c.Query("state"), c.Query("code"))
	if err != nil {
		fmt.Println(err.Error())
		c.Redirect(http.StatusTemporaryRedirect, "/")
		return
	}

	fmt.Fprintf(c.Writer, "Content: %s\n", content)
}

func (a Auth) GetUserInfo(state string, code string) ([]byte, error) {
	if state != oauthStateString {
		return nil, fmt.Errorf("invalid oauth state")
	}

	token, err := a.oauth2Google.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	return contents, nil
}
