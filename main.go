package main

import (
	"fmt"
	"log"
	"net/http"
	"text/template"

	"forum/facebook"
	"forum/forum"
	"forum/github"

	"github.com/gorilla/pat"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"
)

func init() {
	// loads values from .env into the system
	if err := godotenv.Load("data.env"); err != nil {
		log.Fatal("No .env file found")
	}
}

func main() {
	key := "Secret-session-key" // Replace with your SESSION_SECRET or similar
	maxAge := 86400 * 30        // 30 days
	isProd := false             // Set to true when serving over https

	store := sessions.NewCookieStore([]byte(key))
	store.MaxAge(maxAge)
	store.Options.Path = "/"
	store.Options.HttpOnly = true // HttpOnly should always be enabled
	store.Options.Secure = isProd

	gothic.Store = store

	goth.UseProviders(
		google.New("our-google-client-id", "our-google-client-secret", "http://localhost:3000/auth/google/callback", "email", "profile"),
	)

	p := pat.New()
	p.Get("/auth/{provider}/callback", func(res http.ResponseWriter, req *http.Request) {
		user, err := gothic.CompleteUserAuth(res, req)
		if err != nil {
			fmt.Fprintln(res, err)
			return
		}
		t, _ := template.ParseFiles("templates/success.html")
		t.Execute(res, user)
	})

	p.Get("/auth/{provider}", func(res http.ResponseWriter, req *http.Request) {
		gothic.BeginAuthHandler(res, req)
	})

	p.Get("/", func(res http.ResponseWriter, req *http.Request) {
		t, _ := template.ParseFiles("templates/index.html")
		t.Execute(res, false)
	})

	if err := godotenv.Load("data.env"); err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	// Login route
	http.HandleFunc("/login/github/", github.GithubLoginHandler)

	// Github callback
	http.HandleFunc("/login/github/callback", github.GithubCallbackHandler)

	// Route where the authenticated user is redirected to
	http.HandleFunc("/loggedin", func(w http.ResponseWriter, r *http.Request) {
		github.LoggedinHandler(w, r, "")
	})

	http.HandleFunc("/login/facebook", facebook.HandleFacebookLogin)
	http.HandleFunc("/oauth2callback", facebook.HandleFacebookCallback)

	http.HandleFunc("/", forum.Home)
	http.HandleFunc("/404", forum.HandleNotFound)
	http.HandleFunc("/500", forum.HandleServerError)
	http.HandleFunc("/400", forum.HandleBadRequest)
	http.HandleFunc("/logorsign", forum.Logorsign)
	http.HandleFunc("/log_in", forum.Log_in)
	http.HandleFunc("/sign_up", forum.Sign_up)
	http.HandleFunc("/logout", forum.Logout)
	http.HandleFunc("/home", forum.Home)
	http.HandleFunc("/create_discussion", forum.CreateDiscussion)
	http.HandleFunc("/discussion/", forum.ShowDiscussion)
	http.HandleFunc("/add_message/", forum.AddMessage)
	http.HandleFunc("/like/", forum.LikeDiscussion)
	http.HandleFunc("/dislike/", forum.DislikeDiscussion)

	// Définir le dossier "static" comme dossier de fichiers statiques
	fs := http.FileServer(http.Dir("assets"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))
	fmt.Println("Voici le lien pour ouvrir la page web http://localhost:3000/")
	http.ListenAndServe(":3000", nil)
}
