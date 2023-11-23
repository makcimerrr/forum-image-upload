package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"forum/forum"
	"log"
	"net/http"
	"time"
)

func LoggedinHandler(w http.ResponseWriter, r *http.Request, githubData string) {
	if githubData == "" {
		// Unauthorized users get an unauthorized message
		fmt.Fprintf(w, "UNAUTHORIZED!")
		return
	}

	// Set return type JSON
	w.Header().Set("Content-type", "application/json")

	// Prettifying the json (optional)
	var prettyJSON bytes.Buffer
	parserr := json.Indent(&prettyJSON, []byte(githubData), "", "\t")
	if parserr != nil {
		log.Panic("JSON parse error")
	}

	// Parse JSON data into GitHubUser struct
	var githubUser GitHubUser
	if err := json.Unmarshal([]byte(githubData), &githubUser); err != nil {
		log.Panic("Error decoding JSON:", err)
	}

	// Display the extracted fields in the terminal
	fmt.Printf("GitHub ID: %d\n", githubUser.ID)
	fmt.Printf("GitHub Login: %s\n", githubUser.Login)

	// Check if the user already exists in the database
	userExists, err := userExistsInDatabase(githubUser)
	if err != nil {
		log.Panic("Error checking user existence:", err)
	}

	// If the user does not exist, insert a new record
	if !userExists {
		err := insertUserIntoDatabase(githubUser)
		if err != nil {
			log.Panic("Error inserting user into the database:", err)
		}
	}

	// Create a cookie named "username" and set its value to the GitHub login
	expiration := time.Now().Add(24 * time.Hour) // Cookie expiration time (adjust as needed)
	cookie := http.Cookie{
		Name:    "username",
		Value:   githubUser.Login,
		Expires: expiration,
		Path:    "/",
	}

	// Create and set session cookies
	err = forum.CreateAndSetSessionCookies(w, githubUser.Login)
	if err != nil {
		log.Panic("Error creating and setting session cookies:", err)
	}

	// Set the cookie in the response
	http.SetCookie(w, &cookie)

	// Redirect to the home page
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func GithubLoginHandler(w http.ResponseWriter, r *http.Request) {
	// Get the environment variable
	githubClientID := getGithubClientID()

	// Create the dynamic redirect URL for login
	redirectURL := fmt.Sprintf(
		"https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
		githubClientID,
		"http://localhost:3000/login/github/callback",
	)

	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

