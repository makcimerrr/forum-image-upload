package forum

type Discussion struct {
	ID            int
	Title         string
	Message       string
	Username      string
	Category      string
	Liked         bool // Champ pour indiquer si l'utilisateur a aimé cette discussion
	Disliked      bool
	NumberLike    int
	NumberDislike int
}

// Ajoutez cette structure pour représenter un message
type Comment struct {
	Username string
	Message  string
}
