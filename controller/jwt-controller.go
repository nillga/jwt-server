package controller

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/nillga/jwt-server/entity"
	"github.com/nillga/jwt-server/errors"
	"github.com/nillga/jwt-server/service"
)

type JwtController interface {
	SignUp(w http.ResponseWriter, r *http.Request)
	Login(w http.ResponseWriter, r *http.Request)
	Resolve(w http.ResponseWriter, r *http.Request)
	Delete(w http.ResponseWriter, r *http.Request)
	// deprecated
	ChangePassword(w http.ResponseWriter, r *http.Request)
}

type controller struct{}

type Claims struct {
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
	jwt.StandardClaims
}

var (
	jwtService service.JwtService
	secretKey  = os.Getenv("JWT_SECRET_KEY")
)

func NewController(service service.JwtService) JwtController {
	jwtService = service
	return &controller{}
}

func (c *controller) SignUp(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var signupData entity.SignupInput

	if err := json.NewDecoder(r.Body).Decode(&signupData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: http.StatusText(http.StatusBadRequest)})
		return
	}

	if err := jwtService.ValidateInput(&signupData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: err.Error()})
		return
	}

	user, err := jwtService.CreateUser(&signupData)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Failed creating new user."})
		return
	}
	if err = json.NewEncoder(w).Encode(user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Invalid login data."})
		return
	}
}

func (c *controller) Login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var loginData entity.LoginInput
	var user *entity.User

	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Failed reading request body."})
		return
	}

	user, err := jwtService.CheckUser(&loginData)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Invalid login data."})
		return
	}

	if err = json.NewEncoder(w).Encode(user); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Invalid login data."})
		return
	}
}

func (c *controller) Resolve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ids, ok := r.URL.Query()["id"]
	if !ok || len(ids) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Failed reading request"})
		return
	}

	user, err := jwtService.Verify(ids[0])
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Failed finding user."})
		return
	}

	json.NewEncoder(w).Encode(user)
}

func (c *controller) Delete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	ids, ok := r.URL.Query()["id"]
	if !ok || len(ids) < 1 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Failed reading request"})
		return
	}

	log.Println(ids[0])

	if err := jwtService.DeleteUser(&entity.User{Id: ids[0]}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Failed deleting user."})
		return
	}
}

func (c *controller) ChangePassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	claims := &Claims{}

	if err := claims.decodeJwt(r); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: "Not authenticated. This resource can not be accessed."})
		return
	}

	var next entity.ChangePassInput
	if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: err.Error()})
		return
	}

	next.Id = claims.Username

	if err := jwtService.NewPassword(&next); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errors.ProceduralError{Message: err.Error()})
		return
	}
}

func (c *Claims) decodeJwt(r *http.Request) error {
	jwtCookie, err := r.Cookie("jwt")
	if err != nil {
		return err
	}

	if _, err = jwt.ParseWithClaims(jwtCookie.Value, c, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	}); err != nil {
		return err
	}
	return nil
}
