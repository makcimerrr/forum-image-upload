package forum

import (
	"database/sql"
	"net/http"
	"net/url"
	"strconv"
)

func LikeDiscussion(w http.ResponseWriter, r *http.Request) {
	// Vérifiez la validité de la session
	validSession, errMsg := isSessionValid(r)
	if !validSession {
		clearSessionCookies(w)
		// La session n'est pas valide, redirigez l'utilisateur vers la page de connexion ou effectuez d'autres actions
		http.Redirect(w, r, "/log_in?error="+url.QueryEscape(errMsg), http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		// Récupérez l'ID de la discussion depuis l'URL
		discussionID := r.URL.Path[len("/like/"):]
		discussionIDInt, err := strconv.Atoi(discussionID)
		if err != nil {
			http.Error(w, "Invalid discussion ID", http.StatusBadRequest)
			return
		}

		// Obtenez le nom d'utilisateur à partir du cookie "username"
		usernameCookie, err := r.Cookie("username")
		if err != nil {
			// Gérez l'erreur, par exemple, en redirigeant l'utilisateur vers une page de connexion s'il n'est pas connecté.
			http.Redirect(w, r, "/log_in", http.StatusSeeOther)
			return
		}
		username := usernameCookie.Value

		// Ouvrez la connexion à la base de données
		db, err := sql.Open("sqlite", "database/data.db")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer db.Close()

		// Vérifiez si l'utilisateur a déjà aimé ou disliké cette discussion
		var liked bool
		var disliked bool
		err = db.QueryRow("SELECT 1 FROM likes WHERE discussion_id = ? AND username = ?", discussionIDInt, username).Scan(&liked)
		if err != nil && err != sql.ErrNoRows {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = db.QueryRow("SELECT 1 FROM dislikes WHERE discussion_id = ? AND username = ?", discussionIDInt, username).Scan(&disliked)
		if err != nil && err != sql.ErrNoRows {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if liked {
			// Si l'utilisateur a déjà aimé la discussion, supprimez le like
			_, err = db.Exec("DELETE FROM likes WHERE discussion_id = ? AND username = ?", discussionIDInt, username)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		} else {
			// Si l'utilisateur a déjà disliké la discussion, supprimez le dislike
			_, err = db.Exec("DELETE FROM dislikes WHERE discussion_id = ? AND username = ?", discussionIDInt, username)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Ajoutez un like
			_, err = db.Exec("INSERT INTO likes (discussion_id, username) VALUES (?, ?)", discussionIDInt, username)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
		}

		// Redirigez l'utilisateur vers la page d'accueil après la mise à jour du like
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	// Traitez d'autres méthodes HTTP comme nécessaire
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func CheckIfUserLikedDiscussion(username string, discussionID int) (bool, error) {
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return false, err
	}
	defer db.Close()

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM likes WHERE discussion_id = ? AND username = ?)", discussionID, username).Scan(&exists)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func CheckNumberOfLikesForDiscussion(discussionID int) (int, error) {
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return 0, err
	}
	defer db.Close()

	var likeCount int
	err = db.QueryRow("SELECT COUNT(*) FROM likes WHERE discussion_id = ?", discussionID).Scan(&likeCount)
	if err != nil {
		return 0, err
	}

	return likeCount, nil
}
