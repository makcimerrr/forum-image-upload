package facebook

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"forum/forum"

	"golang.org/x/oauth2"
)

func HandleFacebookCallback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != oauthStateString {
		fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	code := r.FormValue("code")

	token, err := oauthConf.Exchange(oauth2.NoContext, code)
	if err != nil {
		fmt.Printf("oauthConf.Exchange() failed with '%s'\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Make a request to get user information
	resp, err := http.Get("https://graph.facebook.com/v3.3/me?fields=id,name,email&access_token=" + url.QueryEscape(token.AccessToken))
	if err != nil {
		fmt.Printf("Get: %s\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	defer resp.Body.Close()

	var user FacebookUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		fmt.Printf("Decode: %s\n", err)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	log.Printf("User ID: %s\n", user.ID)
	log.Printf("User Name: %s\n", user.Name)
	log.Printf("User Email: %s\n", user.Email)

	// Créez une instance de FacebookUser avec les données de l'utilisateur Facebook
	facebookUser := FacebookUser{
		ID:    user.ID,
		Name:  user.Name,
		Email: user.Email,
	}

	// Vérifiez si l'utilisateur existe déjà dans la base de données
	userExists, err := userExistsInDatabase(facebookUser)
	if err != nil {
		log.Panic("Error checking user existence:", err)
	}

	// Si l'utilisateur n'existe pas, insérez un nouvel enregistrement
	if !userExists {
		err := insertUserIntoDatabase(facebookUser)
		if err != nil {
			log.Panic("Error inserting user into the database:", err)
		}
	}

	// Create a cookie named "username" and set its value to the GitHub login
	expiration := time.Now().Add(24 * time.Hour) // Cookie expiration time (adjust as needed)
	cookie := http.Cookie{
		Name:    "username",
		Value:   facebookUser.Name,
		Expires: expiration,
		Path:    "/",
	}

	// Create and set session cookies
	err = forum.CreateAndSetSessionCookies(w, facebookUser.Name)
	if err != nil {
		log.Panic("Error creating and setting session cookies:", err)
	}

	// Set the cookie in the response
	http.SetCookie(w, &cookie)

	http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
}
