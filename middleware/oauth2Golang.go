package middleware

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
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
