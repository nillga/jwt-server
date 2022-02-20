package routes

import (
	"context"
	"encoding/json"
	"fmt"
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

var SecretKey = "no-secret, lol"

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		// rip no post so lets deal with it
	}

	var registerData map[string]string

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// cope
	}

	if err = json.Unmarshal(body, &registerData); err != nil {
		// cope again
	}

	password, err := bcrypt.GenerateFromPassword([]byte(registerData["password"]), 14)
	if err != nil {
		// cope yet another time
	}

	user := bson.D{
		primitive.E{Key: "name", Value: registerData["name"]},
		primitive.E{Key: "email", Value: registerData["email"]},
		primitive.E{Key: "password", Value: password},
	}

	inserted, err := database.Users.InsertOne(context.TODO(), user)
	if err != nil {
		// handle
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
		// another handle
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(obscureUserJSON)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		// get off!
	}

	var loginData map[string]string

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		// copium
	}

	if err = json.Unmarshal(body, &loginData); err != nil {
		// copium
	}

	var requested map[string]string

	if err = database.Users.FindOne(context.TODO(), bson.D{
		{"$and",
			bson.A {
				bson.D {
					{"name", loginData["name"]},
				},
			},
		},
	}).Decode(&requested); err != nil {
		if err == mongo.ErrNoDocuments {
			// user does not exist
		}
		// internal error
	}

	if err = bcrypt.CompareHashAndPassword([]byte(requested["password"]), []byte(loginData["password"])); err != nil {
		// wrong password KEKW
	}

	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Issuer:    requested["_id"],
		ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
	})

	token, err := claims.SignedString([]byte(SecretKey))
	if err != nil {
		// handle me
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
	if r.Method != "GET" {
		// handle
	}
	jwtCookie, err := r.Cookie("jwt")
	if err != nil {
		fmt.Println("No cookie")
	}

	token, err := jwt.ParseWithClaims(jwtCookie.Value, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
	if err != nil {
		fmt.Println("Token parsing failed")
	}

	claims := token.Claims
	var requested map[string]string

	id, err := primitive.ObjectIDFromHex(claims.(*jwt.StandardClaims).Issuer)
	if err != nil {
		// handle
	}

	if err = database.Users.FindOne(context.TODO(), bson.D{
		{"$and",
			bson.A {
				bson.D {
					{"_id", id},
				},
			},
		},
	}).Decode(&requested); err != nil {
		if err == mongo.ErrNoDocuments {
			fmt.Println("User does not exist: "+claims.(*jwt.StandardClaims).Issuer)
		}
		// internal error
	}

	obscureUser := struct {
		ID    interface{} `json:"id"`
		Name   string `json:"name"`
		EMail string `json:"email"`
	}{
		ID:    requested["_id"],
		Name:   requested["name"],
		EMail: requested["email"],
	}

	obscureUserJSON, err := json.Marshal(obscureUser)
	if err != nil {
		fmt.Println("Marshaling went wrong")
	}

	w.Header().Add("Content-Type", "application/json")
	w.Write(obscureUserJSON)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		// cry
	}
	
	cookie := &http.Cookie{
        Name:   "jwt",
        Value:  "",
        Expires: time.Now().Add(-time.Hour),
		HttpOnly: true,
    }

	http.SetCookie(w, cookie)
}