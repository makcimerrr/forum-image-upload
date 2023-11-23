package forum

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

func CreateDiscussion(w http.ResponseWriter, r *http.Request) {
	// Vérifiez la validité de la session

	var formError []string
	validSession, errMsg := isSessionValid(r)
	if !validSession {
		clearSessionCookies(w)
		// La session n'est pas valide, redirigez l'utilisateur vers la page de connexion ou effectuez d'autres actions
		http.Redirect(w, r, "/log_in?error="+url.QueryEscape(errMsg), http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		title := r.FormValue("title")
		message := r.FormValue("message")
		category := r.FormValue("category") // Récupérez la catégorie du formulaire

		const maxFileSize = 20 << 20 // 20 MB en octets
		file, fileHeader, err := r.FormFile("file")

		if err != nil {
			fmt.Println("Erreur lors de la récupération du fichier :", err)
			http.Error(w, "Internal Server Error: Erreur lors de la récupération du fichier", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// Vérification de la taille du fichier
		if fileHeader.Size > maxFileSize {
			formError = append(formError, "Fichier trop volumineux. La taille maximale autorisée est de 20 MB.")
			http.Error(w, "Fichier trop volumineux. La taille maximale autorisée est de 20 MB.", http.StatusBadRequest)
			return
		}

		// Obtenez le nom d'utilisateur à partir du cookie "username"
		usernameCookie, err := r.Cookie("username")
		if err != nil {
			http.Redirect(w, r, "/log_in", http.StatusSeeOther)
			return
		}
		username := usernameCookie.Value

		// Ouverture de la connexion à la base de données
		db, err := sql.Open("sqlite", "database/data.db")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Insérez la nouvelle discussion dans la base de données, y compris la catégorie
		stmt, err := db.Prepare("INSERT INTO discussion_user (username, title, message, filter, image) VALUES (?, ?, ?, ?, ?)")
		if err != nil {
			http.Error(w, "Internal Server Error: Préparation de la requête SQL", http.StatusInternalServerError)
			fmt.Println("Erreur lors de la préparation de la requête SQL :", err)
			return
		}
		defer stmt.Close()

		// Lire le contenu du fichier dans un tableau de bytes
		var imageBuffer bytes.Buffer
		_, err = io.Copy(&imageBuffer, file)
		if err != nil {
			http.Error(w, "Internal Server Error: Lecture du fichier", http.StatusInternalServerError)
			fmt.Println("Erreur lors de la lecture du fichier :", err)
			return
		}

		_, err = stmt.Exec(username, title, message, category, imageBuffer.Bytes())
		if err != nil {
			http.Error(w, "Internal Server Error: Insertion dans la base de données", http.StatusInternalServerError)
			fmt.Println("Erreur lors de l'insertion dans la base de données :", err)
			return
		}

		// Récupérez l'ID de la discussion nouvellement créée
		var discussionID int
		err = db.QueryRow("SELECT last_insert_rowid()").Scan(&discussionID)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirigez l'utilisateur vers la page de la discussion
		http.Redirect(w, r, "/discussion/"+strconv.Itoa(discussionID), http.StatusSeeOther)
		return
	}

	// Affichez la page pour écrire une discussion (write_discussion.html) avec le menu déroulant
	tmpl := template.Must(template.ParseFiles("templates/write_discussion.html"))
	data := struct {
		Errors []string
	}{
		Errors: formError,
	}
	tmpl.Execute(w, data)
}

func ShowDiscussion(w http.ResponseWriter, r *http.Request) {
	// Vérifiez la validité de la session
	validSession, errMsg := isSessionValid(r)
	if !validSession {
		clearSessionCookies(w)
		// La session n'est pas valide, redirigez l'utilisateur vers la page de connexion ou effectuez d'autres actions
		http.Redirect(w, r, "/log_in?error="+url.QueryEscape(errMsg), http.StatusSeeOther)
		return
	}
	// Récupérez l'ID de la discussion à partir de l'URL
	discussionID := r.URL.Path[len("/discussion/"):]
	// Convertissez l'ID de la discussion en un entier
	discussionIDInt, err := strconv.Atoi(discussionID)
	if err != nil {
		http.Error(w, "Invalid discussion ID", http.StatusBadRequest)
		return
	}
	// Ouverture de la connexion à la base de données
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	// Effectuez une requête SQL pour récupérer les détails de la discussion en fonction de l'ID
	var username, title, message string
	var imageData []byte // Utilisez un slice de bytes pour stocker les données binaires de l'image
	err = db.QueryRow("SELECT username, title, message, image FROM discussion_user WHERE id = ?", discussionIDInt).Scan(&username, &title, &message, &imageData)
	if err != nil {
		http.Error(w, "Discussion not found", http.StatusNotFound)
		return
	}

	// Effectuez une autre requête SQL pour récupérer les commentaires associés à cette discussion
	rows, err := db.Query("SELECT username, message FROM comments WHERE discussion_id = ?", discussionIDInt)
	if err != nil {
		http.Error(w, "Error fetching comments", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Créez une structure de données pour stocker les détails de la discussion et les commentaires
	data := struct {
		Username string
		Title    string
		ID       int
		Message  string
		Image    string
		Filter   *string
		Comments []struct {
			Username string
			Message  string
		}
	}{
		Username: username,
		Title:    title,
		Image:    base64.StdEncoding.EncodeToString(imageData),
		ID:       discussionIDInt,
		Message:  message,
	}

	var filter sql.NullString
	err = db.QueryRow("SELECT COALESCE(filter, '') FROM discussion_user WHERE id = ?", discussionIDInt).Scan(&filter)
	if err != nil {
		http.Error(w, "Filter not found", http.StatusNotFound)
		return
	}

	var filterValue string
	if filter.Valid {
		filterValue = filter.String
	}

	data.Filter = &filterValue // Permet l'affiche du filtre {{ .Filter}}

	// Parcourez les commentaires et ajoutez-les à la structure de données
	for rows.Next() {
		var comment struct {
			Username string
			Message  string
		}
		if err := rows.Scan(&comment.Username, &comment.Message); err != nil {
			http.Error(w, "Error scanning comments", http.StatusInternalServerError)
			return
		}
		data.Comments = append(data.Comments, comment)
	}

	// Affichez les détails de la discussion et les commentaires dans un modèle HTML
	tmpl := template.Must(template.ParseFiles("templates/show_discussion.html"))
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func GetAllDiscussionsFromDB() ([]Discussion, error) {
	// Ouvrez la connexion à la base de données
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// Exécutez une requête SQL pour récupérer toutes les discussions
	rows, err := db.Query("SELECT id, username, title, message FROM discussion_user")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// Créez une slice pour stocker les discussions
	var discussions []Discussion
	// Parcourez les résultats et stockez-les dans la slice
	for rows.Next() {
		var discussion Discussion
		err := rows.Scan(&discussion.ID, &discussion.Username, &discussion.Title, &discussion.Message)
		if err != nil {
			return nil, err
		}
		discussions = append(discussions, discussion)
	}
	return discussions, nil
}

func GetDiscussionsFromDBByCategories(category string) ([]Discussion, error) {
	// Ouvrez la connexion à la base de données
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// Exécutez une requête SQL pour récupérer toutes les discussions
	// Créez une requête préparée
	stmt, err := db.Prepare("SELECT id, username, title, message FROM discussion_user WHERE filter = $1")
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	// Exécutez la requête préparée avec la variable category
	rows, err := stmt.Query(category)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	// Créez une slice pour stocker les discussions
	var discussions []Discussion
	// Parcourez les résultats et stockez-les dans la slice
	for rows.Next() {
		var discussion Discussion
		err := rows.Scan(&discussion.ID, &discussion.Username, &discussion.Title, &discussion.Message)
		if err != nil {
			return nil, err
		}
		discussions = append(discussions, discussion)
	}
	return discussions, nil
}

func AddMessage(w http.ResponseWriter, r *http.Request) {
	// Vérifiez la validité de la session
	validSession, errMsg := isSessionValid(r)
	if !validSession {
		clearSessionCookies(w)
		// La session n'est pas valide, redirigez l'utilisateur vers la page de connexion ou effectuez d'autres actions
		http.Redirect(w, r, "/log_in?error="+url.QueryEscape(errMsg), http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		// Récupérez l'ID de la discussion à partir de l'URL
		discussionID := r.URL.Path[len("/add_message/"):]
		// Convertissez l'ID de la discussion en un entier
		discussionIDInt, err := strconv.Atoi(discussionID)
		if err != nil {
			http.Error(w, "Invalid discussion ID", http.StatusBadRequest)
			return
		}

		message := r.FormValue("message")
		// Obtenez le nom d'utilisateur à partir du cookie "username"
		usernameCookie, err := r.Cookie("username")
		if err != nil {
			// Gérer l'erreur ici, par exemple, en redirigeant l'utilisateur vers une page de connexion s'il n'est pas connecté.
			http.Redirect(w, r, "/log_in", http.StatusSeeOther)
			return
		}
		username := usernameCookie.Value

		// Ouverture de la connexion à la base de données
		db, err := sql.Open("sqlite", "database/data.db")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Insérez le nouveau message dans la base de données en incluant l'ID de discussion
		_, err = db.Exec("INSERT INTO comments (discussion_id, username, message) VALUES (?, ?, ?)", discussionIDInt, username, message)
		if err != nil {
			log.Printf("Erreur lors de l'insertion du message : %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Redirigez l'utilisateur vers la page de discussion
		http.Redirect(w, r, fmt.Sprintf("/discussion/%d", discussionIDInt), http.StatusSeeOther)
		return
	}

	// Affichez la page pour écrire une discussion (write_discussion.html)
	tmpl := template.Must(template.ParseFiles("templates/show_discussion.html"))
	tmpl.Execute(w, nil)
}

func GetCategoryForDiscussionFromDB(discussionID int) (string, error) {
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return "", err
	}
	defer db.Close()

	var category string
	err = db.QueryRow("SELECT COALESCE(filter, '') FROM discussion_user WHERE id = ?", discussionID).Scan(&category)
	if err != nil {
		return "", err
	}

	return category, nil
}

func GetUniqueCategoriesFromDiscussions(discussions []Discussion) []string {
	uniqueCategories := make(map[string]struct{})

	// Parcourez les discussions et ajoutez chaque catégorie à la carte uniqueCategories
	for _, discussion := range discussions {
		uniqueCategories[discussion.Category] = struct{}{}
	}

	// Créez une slice pour stocker les catégories uniques
	categories := make([]string, 0, len(uniqueCategories))

	// Parcourez la carte uniqueCategories pour extraire les catégories uniques
	for category := range uniqueCategories {
		categories = append(categories, category)
	}

	return categories
}
