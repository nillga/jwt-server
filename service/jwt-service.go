package service

import (
	"errors"
	"regexp"

	"github.com/nillga/jwt-server/entity"
	"github.com/nillga/jwt-server/repository"
	"golang.org/x/crypto/bcrypt"
)

type JwtService interface {
	Verify(id string) (*entity.User, error)
	ValidateInput(input *entity.SignupInput) error
	CreateUser(input *entity.SignupInput) (*entity.User, error)
	CheckUser(input *entity.LoginInput) (*entity.User, error)
	DeleteUser(user *entity.User) error
	ElevateUser(user *entity.User) error
	NewPassword(passwords *entity.ChangePassInput) error
	ShowAllUsers() ([]*entity.User, error)
}

type service struct{}

var (
	repo repository.JwtRepository
)

func NewJwtService(mongoRepo repository.JwtRepository) JwtService {
	repo = mongoRepo
	return &service{}
}

func (s *service) Verify(id string) (*entity.User, error) {
	return repo.FindById(id)
}

func (s *service) ValidateInput(input *entity.SignupInput) error {
	mailRegex := regexp.MustCompile(`^\S+@\S+.[A-Za-z]+$`)

	if input.Username == "" {
		return errors.New("no username provided")
	}
	if !mailRegex.Match([]byte(input.Email)) {
		return errors.New("no valid mailadress provided")
	}
	if input.Password == "" {
		return errors.New("no password provided")
	}
	if input.Repeated == "" {
		return errors.New("no repeated password provided")
	}
	if input.Password != input.Repeated {
		return errors.New("password and repeated do not match")
	}

	user := &entity.User{
		Username: input.Username,
		Email:    input.Email,
	}

	var got *entity.User

	got, err := repo.Find(user)
	if err != nil {
		return nil
	}

	if got.Username == input.Username {
		return errors.New("username has been chosen already")
	}
	if got.Email == input.Email {
		return errors.New("email is already in use")
	}

	return errors.New("internal DB error")
}

func (s *service) CreateUser(input *entity.SignupInput) (*entity.User, error) {
	password, err := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
	if err != nil {
		return nil, err
	}

	user := &entity.User{
		Username: input.Username,
		Email:    input.Email,
		Password: password,
	}

	return repo.Store(user)
}

func (s *service) CheckUser(input *entity.LoginInput) (*entity.User, error) {
	identifier := input.Identifier

	user, err := repo.Find(&entity.User{Username: identifier, Email: identifier})
	if err != nil {
		return nil, err
	}

	if err = bcrypt.CompareHashAndPassword(user.Password, []byte(input.Password)); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *service) DeleteUser(user *entity.User) error {
	if user.Id == "" {
		return errors.New("no ID provided")
	}
	return repo.Delete(user.Id)
}

func (s *service) NewPassword(passwords *entity.ChangePassInput) error {
	if passwords.Id == "" {
		return errors.New("no user ID provided")
	}
	if passwords.Old == "" {
		return errors.New("no current password provided")
	}

	current, err := repo.FindById(passwords.Id)
	if err != nil {
		return err
	}

	if err = bcrypt.CompareHashAndPassword(current.Password, []byte(passwords.Old)); err != nil {
		return err
	}

	if passwords.Password == "" {
		return errors.New("no new password provided")
	}
	if passwords.Repeated == "" {
		return errors.New("password has to be repeated")
	}
	if passwords.Password != passwords.Repeated {
		return errors.New("password and repeated differ")
	}

	password, err := bcrypt.GenerateFromPassword([]byte(passwords.Password), 14)
	if err != nil {
		return err
	}

	current.Password = password

	return repo.UpdateUser(passwords.Id, current)
}

func (s *service) ElevateUser(user *entity.User) error {
	if user.Id == "" {
		return errors.New("no ID provided")
	}
	return repo.Elevate(user.Id)
}

func (s *service) ShowAllUsers() ([]*entity.User, error) {
	return repo.AllUsers()
}