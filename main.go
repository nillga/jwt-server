package main

import (
	"os"

	"github.com/nillga/jwt-server/controller"
	router "github.com/nillga/jwt-server/http"
	"github.com/nillga/jwt-server/repository"
	"github.com/nillga/jwt-server/service"
)

var (
	jwtRepo       repository.JwtRepository = repository.NewPostgresRepo()
	jwtService    service.JwtService       = service.NewJwtService(jwtRepo)
	jwtController controller.JwtController = controller.NewController(jwtService)
	jwtRouter     router.Router            = router.NewVanillaRouter()
)

func main() {
	jwtRouter.POST("/signup", jwtController.SignUp)
	jwtRouter.POST("/login", jwtController.Login)
	jwtRouter.DELETE("/delete", jwtController.Delete)
	jwtRouter.GET("/resolve", jwtController.Resolve)
	jwtRouter.PUT("/changepass", jwtController.ChangePassword)

	jwtRouter.SERVE(os.Getenv("PORT"))
}
