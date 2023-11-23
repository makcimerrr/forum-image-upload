package github

import "net/http"

func GithubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	githubAccessToken := getGithubAccessToken(code)

	githubData := getGithubData(githubAccessToken)

	LoggedinHandler(w, r, githubData)
}
