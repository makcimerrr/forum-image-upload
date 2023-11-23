package forum

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"hash/fnv"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func codeErreur(w http.ResponseWriter, r *http.Request, url string, route string, html string) {
	if url != route {
		http.Redirect(w, r, "/404", http.StatusFound)
	}
	_, err := template.ParseFiles(html)
	if err != nil {
		http.Redirect(w, r, "/500", http.StatusFound)
	}
}

func HandleNotFound(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/404.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func HandleServerError(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/500.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func HandleBadRequest(w http.ResponseWriter, r *http.Request) {
	template.Must(template.ParseFiles("templates/400.html"))
}

func Logorsign(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/logorsign.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func Sign_up(w http.ResponseWriter, r *http.Request) {
	var formError []string

	if r.Method == http.MethodPost {
		// Récupération des informations du formulaire
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		hashpass := hash(password)

		// Ouverture de la connexion à la base de données
		db, err := sql.Open("sqlite", "database/data.db")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer db.Close()

		// Création de la table s'il n'existe pas
		createTable := `
           CREATE TABLE IF NOT EXISTS account_user (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               username TEXT,
               email TEXT,
               mot_de_passe INT
           )
       `
		_, err = db.Exec(createTable)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Vérification si le nom d'utilisateur est déjà utilisé
		var existingUsername string
		err = db.QueryRow("SELECT username FROM account_user WHERE username = ?", username).Scan(&existingUsername)
		if err == nil {
			formError = append(formError, "This Username Is Already Use !! ")
		}

		// Vérification si l'e-mail est déjà utilisé
		var existingEmail string
		err = db.QueryRow("SELECT email FROM account_user WHERE email = ?", email).Scan(&existingEmail)
		if err == nil {
			formError = append(formError, "This Email Is Already Use !!")
		}

		if formError == nil {
			insertUser := "INSERT INTO account_user (username, email, mot_de_passe) VALUES (?, ?, ?)"
			_, err = db.Exec(insertUser, username, email, hashpass)

			err := CreateAndSetSessionCookies(w, username)
			fmt.Println(username)

			if err != nil {
				fmt.Println(err)
				return
			}

			// Rediriger l'utilisateur vers la page "/home" après l'enregistrement
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		}
	}

	tmpl := template.Must(template.ParseFiles("templates/sign_up.html"))
	data := struct {
		Errors []string
	}{
		Errors: formError,
	}
	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func Log_in(w http.ResponseWriter, r *http.Request) {
	var formError []string
	errMsg := r.URL.Query().Get("error") // Récupérez le message d'erreur de la requête

	if r.Method == http.MethodPost {
		loginemail := r.FormValue("loginemail")
		loginpassword := r.FormValue("loginpassword")

		// Ouverture de la connexion à la base de données
		db, err := sql.Open("sqlite", "database/data.db")
		if err != nil {
			formError = append(formError, "Internal Server Error")
			http.Redirect(w, r, "/log_in?error="+url.QueryEscape(strings.Join(formError, "; ")), http.StatusSeeOther)
			return
		}
		defer db.Close()

		var trueemail string
		var truepassword uint32
		var username string
		err = db.QueryRow("SELECT username, email, mot_de_passe FROM account_user WHERE email = ?", loginemail).Scan(&username, &trueemail, &truepassword)
		if err != nil {
			formError = append(formError, "Email Doesn't exist.")
		} else {
			hashloginpassword := hash(loginpassword)

			// Vérifier le mot de passe
			if hashloginpassword != truepassword {
				formError = append(formError, "Password Failed.")
			} else {
				// L'utilisateur est connecté avec succès
				err := CreateAndSetSessionCookies(w, username)
				if err != nil {
					formError = append(formError, "Internal Server Error")
					http.Redirect(w, r, "/log_in?error="+url.QueryEscape(strings.Join(formError, "; ")), http.StatusSeeOther)
					return
				}

				// Redirigez l'utilisateur vers la page "/"
				http.Redirect(w, r, "/home", http.StatusSeeOther)
				return
			}
		}
	}

	tmpl := template.Must(template.ParseFiles("templates/login.html"))
	data := struct {
		Error  string
		Errors []string
	}{
		Error:  errMsg,
		Errors: formError,
	}
	err := tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func hash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func generateSessionToken() (string, error) {
	token := make([]byte, 32) // Crée un slice de bytes de 32 octets

	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(token), nil
}

func CreateAndSetSessionCookies(w http.ResponseWriter, username string) error {
	// Générer un nouveau jeton de session uniquement si le nom d'utilisateur n'est pas vide
	if username == "" {
		return errors.New("Username is empty")
	}

	// Ouvrir une connexion à la base de données
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return err
	}
	defer db.Close()

	// Vérifier si l'utilisateur a déjà une entrée dans la base de données
	var existingSessionToken string
	err = db.QueryRow("SELECT sessionToken FROM token_user WHERE username = ?", username).Scan(&existingSessionToken)
	if err == sql.ErrNoRows {
		// Si l'utilisateur n'a pas encore d'entrée, générer un nouveau jeton de session
		sessionToken, err := generateSessionToken()
		if err != nil {
			return err
		}

		// Insérer la nouvelle entrée dans la base de données
		_, err = db.Exec("INSERT INTO token_user (username, sessionToken) VALUES (?, ?)", username, sessionToken)
		if err != nil {
			return err
		}

		// Créer un cookie contenant le nom d'utilisateur
		userCookie := http.Cookie{
			Name:     "username",
			Value:    username,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, &userCookie)

		// Créer un cookie contenant le jeton de session
		sessionCookie := http.Cookie{
			Name:     "session",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, &sessionCookie)

	} else if err == nil {
		// Si l'utilisateur a déjà une entrée, mettre à jour le jeton de session existant
		sessionToken, err := generateSessionToken()
		if err != nil {
			return err
		}

		// Mettre à jour le jeton de session dans la base de données
		_, err = db.Exec("UPDATE token_user SET sessionToken = ? WHERE username = ?", sessionToken, username)
		if err != nil {
			return err
		}

		// Créer un cookie contenant le nom d'utilisateur
		userCookie := http.Cookie{
			Name:     "username",
			Value:    username,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, &userCookie)

		// Créer un cookie contenant le jeton de session
		sessionCookie := http.Cookie{
			Name:     "session",
			Value:    sessionToken,
			Path:     "/",
			HttpOnly: true,
		}
		http.SetCookie(w, &sessionCookie)

	} else {
		// En cas d'erreur différente de "pas de lignes", renvoyer l'erreur
		return err
	}

	return nil
}

func Logout(w http.ResponseWriter, r *http.Request) {
	var notification []string
	// Supprimer le cookie "username"
	usernameCookie, err := r.Cookie("username")
	if err == nil {
		usernameCookie.Expires = time.Now().AddDate(0, 0, -1) // Définir une date d'expiration dans le passé pour supprimer le cookie
		http.SetCookie(w, usernameCookie)
	}

	// Supprimer le cookie "session"
	sessionCookie, err := r.Cookie("session")
	if err == nil {
		sessionCookie.Expires = time.Now().AddDate(0, 0, -1) // Définir une date d'expiration dans le passé pour supprimer le cookie
		http.SetCookie(w, sessionCookie)
	}

	// Créer un message de notification
	notification = append(notification, "Déconnexion réussie.")

	// Rediriger vers la page "/home" avec le message de notification
	http.Redirect(w, r, "/log_in?error="+url.QueryEscape(strings.Join(notification, "; ")), http.StatusSeeOther)
}

func Home(w http.ResponseWriter, r *http.Request) {

	// Vérifiez la validité de la session
	validSession, errMsg := isSessionValid(r)
	if !validSession {
		clearSessionCookies(w)
		// La session n'est pas valide, redirigez l'utilisateur vers la page de connexion ou effectuez d'autres actions
		http.Redirect(w, r, "/log_in?error="+url.QueryEscape(errMsg), http.StatusSeeOther)
		return
	}

	// Récupérer le nom d'utilisateur à partir du cookie "username"
	usernameCookie, err := r.Cookie("username")
	var username string
	if err == nil {
		username = usernameCookie.Value
	}

	var category string
	var discussions []Discussion

	category = r.URL.Query().Get(`category`)

	if category == "" {
		// Récupérer toutes les discussions à partir de la base de données
		discussions, err = GetAllDiscussionsFromDB()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		discussions, err = GetDiscussionsFromDBByCategories(category)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	// Récupérer les catégories pour chaque discussion
	for i, discussion := range discussions {
		category, err := GetCategoryForDiscussionFromDB(discussion.ID)
		if err == nil {
			discussions[i].Category = category
		}
	}

	// Récupérer les catégories uniques
	categories := GetUniqueCategoriesFromDiscussions(discussions)

	// Pour chaque discussion, vérifiez si l'utilisateur l'a aimée
	for i := range discussions {
		liked, err := CheckIfUserLikedDiscussion(username, discussions[i].ID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		discussions[i].Liked = liked

		// Pour chaque discussion, vérifiez si l'utilisateur l'a pas aimée
		disliked, err := CheckIfUserDislikedDiscussion(username, discussions[i].ID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		discussions[i].Disliked = disliked

		// Pour chaque discussion, vérifiez si l'utilisateur l'a aimée
		numberLike, err := CheckNumberOfLikesForDiscussion(discussions[i].ID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		discussions[i].NumberLike = numberLike

		numberDislike, err := CheckNumberOfDislikesForDiscussion(discussions[i].ID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		discussions[i].NumberDislike = numberDislike
	}

	// Créer une structure de données pour passer les informations au modèle
	data := struct {
		Username    string
		Discussions []Discussion
		Categories  []string
	}{
		Username:    username,
		Discussions: discussions,
		Categories:  categories,
	}

	tmpl := template.Must(template.ParseFiles("templates/home.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
