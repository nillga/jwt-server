package entity

type User struct {
	Id string `json:"_id"`
	Username string `json:"name"`
	Email string `json:"email"`
	Password []byte `json:"password,omitempty"`
}

type Input struct {
	Username string `json:"username"`
	Email string `json:"mail"`
	Password string `json:"password"`
	Repeated string `json:"repeated"`
}

type LoginInput struct {
	Identifier string `json:"id"`
	Password string `json:"password"`
}