package routes

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/nillga/jwt-server/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type UserValidation struct {
	Id string `json:"id"`
	Valid bool `json:"valid"`
}

var (
	SecretKey = "no-secret, lol"
	InvalidUser = UserValidation{"-", false}
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if InvalidMethod(w, r, "POST") {
		return
	}

	var registerData map[string]string

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed reading request body."))
		return
	}

	if err = json.Unmarshal(body, &registerData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return
	}

	var bin interface{}

	if err = database.Users.FindOne(context.TODO(), bson.D{
		primitive.E{Key: "$or", Value:
			bson.A {
				bson.D {
					primitive.E{Key: "name", Value: registerData["name"]},
				},
				bson.D {
					primitive.E{Key: "email", Value: registerData["email"]},
				},
			},
		},
	}).Decode(&bin); err != mongo.ErrNoDocuments {
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return
	}

	password, err := bcrypt.GenerateFromPassword([]byte(registerData["password"]), 14)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return
	}

	user := bson.D{
		primitive.E{Key: "name", Value: registerData["name"]},
		primitive.E{Key: "email", Value: registerData["email"]},
		primitive.E{Key: "password", Value: password},
	}

	inserted, err := database.Users.InsertOne(context.TODO(), user)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Database error"))
		return
	}

	obscureUser := struct {
		ID    interface{} `json:"id"`
		Name   string `json:"name"`
		EMail string `json:"email"`
	}{
		ID:    inserted.InsertedID,
		Name:   registerData["name"],
		EMail: registerData["email"],
	}

	obscureUserJSON, err := json.Marshal(obscureUser)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Database error"))
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(obscureUserJSON)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if InvalidMethod(w, r, "POST") {
		return
	}

	var loginData map[string]string

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Failed reading request body."))
		return
	}

	if err = json.Unmarshal(body, &loginData); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(http.StatusText(http.StatusBadRequest)))
		return
	}

	var requested map[string]string

	if err = database.Users.FindOne(context.TODO(), bson.D{
		primitive.E{Key: "$and", Value:
			bson.A {
				bson.D {
					primitive.E{Key: "name", Value: loginData["name"]},
				},
			},
		},
	}).Decode(&requested); err != nil {
		if err == mongo.ErrNoDocuments {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("User does not exist"))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(requested["password"]), []byte(loginData["password"])); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
		return
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    requested["_id"],
		ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
	})

	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
		return
	}

	cookie := &http.Cookie{
        Name:   "jwt",
        Value:  token,
        Expires: time.Now().Add(time.Hour * 2),
		HttpOnly: true,
    }

	http.SetCookie(w, cookie)
}

func ResolveUserHandler(w http.ResponseWriter, r *http.Request) {
	if InvalidMethod(w, r, "GET") {
		return
	}

	jwtCookie, err := r.Cookie("jwt")
	if err != nil {
		ReturnInvalidUser(w, r)
		return
	}

	token, err := jwt.ParseWithClaims(jwtCookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		ReturnInvalidUser(w, r)
		return
	}

	claims := token.Claims
	var requested map[string]string

	id, err := primitive.ObjectIDFromHex(claims.(*jwt.StandardClaims).Issuer)
	if err != nil {
		ReturnInvalidUser(w, r)
		return
	}

	if err = database.Users.FindOne(context.TODO(), bson.D{
		primitive.E{Key: "$and", Value:
			bson.A {
				bson.D {
					primitive.E{Key: "_id", Value: id},
				},
			},
		},
	}).Decode(&requested); err != nil {
		ReturnInvalidUser(w, r)
		return
	}

	obscureUser := UserValidation{
		Id:    requested["_id"],
		Valid: true,
	}

	obscureUserJSON, err := json.Marshal(obscureUser)
	if err != nil {
		ReturnInvalidUser(w, r)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(obscureUserJSON)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if InvalidMethod(w, r, "POST") {
		return
	}
	
	cookie := &http.Cookie{
        Name:   "jwt",
        Value:  "",
        Expires: time.Now().Add(-time.Hour),
		HttpOnly: true,
    }

	http.SetCookie(w, cookie)
}

func InvalidMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Add("Allow", method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte(http.StatusText(http.StatusMethodNotAllowed)))
		return true
	}
	return false
}

func ReturnInvalidUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	invalidResponse, err := json.Marshal(InvalidUser)
	if err != nil {
		return
	}
	w.Write(invalidResponse)
}