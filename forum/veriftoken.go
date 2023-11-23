package forum

import (
	"database/sql"
	"fmt"
	"net/http"
)

// isSessionValid vérifie si le token de session dans les cookies correspond à celui dans la base de données
func isSessionValid(r *http.Request) (bool, string) {
	// Obtenez le jeton de session à partir des cookies
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return true, "No session cookie"
	}
	sessionToken := sessionCookie.Value

	// Obtenez le nom d'utilisateur à partir des cookies
	userCookie, err := r.Cookie("username")
	if err != nil {
		return false, "No username cookie"
	}
	username := userCookie.Value

	// Ouvrez une connexion à la base de données
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return false, "Database connection error"
	}
	defer db.Close()

	// Vérifiez si le nom d'utilisateur est vide
	if username == "" {
		return false, "No username in cookies"
	}

	fmt.Println("Username:", username)

	// Vérifiez si le jeton de session correspond à celui dans la base de données
	var dbSessionToken string
	err = db.QueryRow("SELECT sessionToken FROM token_user WHERE username = ?", username).Scan(&dbSessionToken)
	if err != nil {
		fmt.Println("Database query error:", err)
		return false, "Error querying database"
	}

	fmt.Println("DB Session Token:", dbSessionToken)
	fmt.Println("Session Token:", sessionToken)

	return sessionToken == dbSessionToken, "You have been disconnected"
}

func clearSessionCookies(w http.ResponseWriter) {
	// Créer un cookie avec une date d'expiration antérieure pour effacer le cookie
	clearCookie := http.Cookie{
		Name:     "username",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, &clearCookie)

	clearCookie = http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	}
	http.SetCookie(w, &clearCookie)
}
