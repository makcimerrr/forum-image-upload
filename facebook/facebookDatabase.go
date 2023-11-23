package facebook

import "database/sql"

func userExistsInDatabase(user FacebookUser) (bool, error) {
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return false, err
	}
	defer db.Close()

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM account_user WHERE id = ?", user.ID).Scan(&count)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func insertUserIntoDatabase(user FacebookUser) error {
	db, err := sql.Open("sqlite", "database/data.db")
	if err != nil {
		return err
	}
	defer db.Close()

	_, err = db.Exec("INSERT INTO account_user (id, username, email, mot_de_passe) VALUES (?, ?, NULL, NULL)", user.ID, user.Name)
	if err != nil {
		return err
	}

	return nil
}
