package database

import (
	"context"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var DB *mongo.Client

var Users *mongo.Collection

func Connect() {
	client, err := mongo.Connect(context.TODO(),options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		panic(err)
	}

	users := client.Database("sample_name").Collection("users")

	DB = client
	Users = users
}