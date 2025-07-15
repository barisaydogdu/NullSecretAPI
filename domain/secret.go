package domain

type Secret struct {
	ID      string `json:"id"`
	Message string `json:"message"`
	Created int64  `json:"created"`
}
