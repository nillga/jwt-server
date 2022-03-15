package cache

import "github.com/nillga/jwt-server/entity"

type JwtCache interface {
	Get(id string) *entity.User
	Set(user *entity.User)
}
