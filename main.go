package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/nillga/jwt-server/database"
	"github.com/nillga/jwt-server/routes"
)

func main() {
	database.Connect()

	fmt.Println("Database is connected -> The server is up and running at http://localhost:8000")

	http.HandleFunc("/register", routes.RegisterHandler)

	http.HandleFunc("/login", routes.LoginHandler)

	http.HandleFunc("/user", routes.ResolveUserHandler)

	http.HandleFunc("/logout", routes.LogoutHandler)

	log.Fatalln(http.ListenAndServe(":8000", nil))
}
