package repository

import (
	"github.com/nillga/jwt-server/entity"
)

type JwtRepository interface {
	Store(user *entity.User) (*entity.User, error)
	Find(user *entity.User) (*entity.User, error)
	FindById(id string) (*entity.User, error)
	Delete(id string) error
}