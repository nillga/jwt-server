package routes

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/nillga/jwt-server/database"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
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
		primitive.E{Key: "$or", Value: bson.A{
			bson.D{
				primitive.E{Key: "name", Value: registerData["name"]},
			},
			bson.D{
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
		Name  string      `json:"name"`
		EMail string      `json:"email"`
	}{
		ID:    inserted.InsertedID,
		Name:  registerData["name"],
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