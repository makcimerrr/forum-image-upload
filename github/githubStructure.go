package github

// Define a struct to represent the relevant fields from the JSON data
type GitHubUser struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}
