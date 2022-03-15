package service

import (
	"errors"
	"testing"

	"github.com/nillga/jwt-server/entity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type mockRepository struct {
	mock.Mock
}

func (m *mockRepository) Store(user *entity.User) (*entity.User, error) {
	args := m.Called()
	result := args.Get(0)
	return result.(*entity.User), args.Error(1)
}

func (m *mockRepository) Find(user *entity.User) (*entity.User, error) {
	args := m.Called()
	result := args.Get(0)
	return result.(*entity.User), args.Error(1)
}

func (m *mockRepository) FindById(id string) (*entity.User, error) {
	args := m.Called()
	result := args.Get(0)
	return result.(*entity.User), args.Error(1)
}

func (m *mockRepository) UpdateUser(id string, user *entity.User) error {
	args := m.Called()
	return args.Error(0)
}

func (m *mockRepository) Delete(id string) error {
	args := m.Called()
	return args.Error(0)
}

func TestService_Store(t *testing.T) {
	mockRepo := new(mockRepository)

	input := entity.SignupInput{
		Username: "testname",
		Email:    "testmail@wierbicki.org",
		Password: "asdf1234",
		Repeated: "asdf1234",
	}

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), 14)
	if err != nil {
		t.Errorf("Password encryption failed test-sided")
	}

	toStore := entity.User{
		Id:       "gwalqwpü",
		Username: "testname",
		Email:    "testmail@wierbicki.org",
		Password: encryptedPassword,
	}

	mockRepo.On("Store").Return(&toStore, nil)

	testService := NewJwtService(mockRepo)

	result, err := testService.CreateUser(&input)

	mockRepo.AssertExpectations(t)

	assert.Nil(t, err)
	assert.NotEqual(t, "", result.Id)
	assert.Equal(t, input.Username, result.Username)
	assert.Equal(t, input.Email, result.Email)
	assert.Nil(t, bcrypt.CompareHashAndPassword(result.Password, []byte(input.Password)))
}

func TestService_Verify(t *testing.T) {
	mockRepo := new(mockRepository)

	input := "sampleId"

	toStore := entity.User{
		Id: "sampleId",
	}

	mockRepo.On("FindById").Return(&toStore, nil)

	testService := NewJwtService(mockRepo)

	result, err := testService.Verify(input)

	mockRepo.AssertExpectations(t)

	assert.Nil(t, err)
	assert.Equal(t, result.Id, input)
}

func TestService_ValidateInput(t *testing.T) {
	type validateCase struct {
		ret        error
		input      *entity.SignupInput
		findOutput *entity.User
		findErr    error
	}

	toStore := entity.User{
		Id:       "sampleId",
		Username: "test",
		Email:    "test@wierbicki.org",
		Password: []byte("asdf"),
	}

	tests := []validateCase{
		{nil, &entity.SignupInput{Username: "test", Email: "test@wierbicki.org", Password: "asdf", Repeated: "asdf"}, nil, errors.New("")},
		{errors.New(""), &entity.SignupInput{Username: "test", Email: "test@wierbicki.org", Password: "asdf", Repeated: "asdf"}, &toStore, nil},
		{errors.New(""), &entity.SignupInput{Username: "daniel", Email: "test@wierbicki.org", Password: "asdf", Repeated: "asdf"}, &toStore, nil},
		{errors.New(""), &entity.SignupInput{Username: "daniel", Email: "spam@wierbicki.org", Password: "asdf", Repeated: "asdf"}, &toStore, nil},
		{errors.New(""), &entity.SignupInput{Username: "test", Email: "test@wierbicki.org", Password: "", Repeated: "asdf"}, nil, errors.New("")},
		{errors.New(""), &entity.SignupInput{Username: "test", Email: "test@wierbicki.org", Password: "asdf", Repeated: ""}, nil, errors.New("")},
		{errors.New(""), &entity.SignupInput{Username: "test", Email: "test@wierbicki.org", Password: "asdf", Repeated: "1234"}, nil, errors.New("")},
		{errors.New(""), &entity.SignupInput{Username: "", Email: "test@wierbicki.org", Password: "asdf", Repeated: ""}, nil, errors.New("")},
		{errors.New(""), &entity.SignupInput{Username: "test", Email: "mail", Password: "asdf", Repeated: "1234"}, nil, errors.New("")},
	}

	for _, test := range tests {
		mockRepo := new(mockRepository)
		mockRepo.On("Find").Return(test.findOutput, test.findErr)
		testService := NewJwtService(mockRepo)

		err := testService.ValidateInput(test.input)

		if test.ret == nil {
			assert.Nil(t, err)
		} else {
			assert.NotNil(t, err)
		}
	}
}

func TestService_CheckUser(t *testing.T) {
	type checkUserCase struct {
		in        *entity.LoginInput
		mockUser  *entity.User
		mockError error
		findUser  *entity.User
		findError error
	}

	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte("DOGECOIN69"), 14)
	if err != nil {
		t.Errorf("Password generation failed test-sided")
	}

	found := &entity.User{
		Id:       "1",
		Username: "daniel",
		Email:    "daniel@wierbicki.org",
		Password: encryptedPassword,
	}

	tests := []checkUserCase{
		{in: &entity.LoginInput{Identifier: "daniel", Password: "DOGECOIN69"}, mockUser: found, mockError: nil, findUser: found, findError: nil},
		{in: &entity.LoginInput{Identifier: "daniel", Password: "wrong"}, mockUser: nil, mockError: errors.New(""), findUser: found, findError: nil},
		{in: &entity.LoginInput{Identifier: "daniel", Password: "DOGECOIN69"}, mockUser: nil, mockError: errors.New(""), findUser: nil, findError: errors.New("")},
	}

	for _, test := range tests {
		mockRepo := new(mockRepository)
		mockRepo.On("Find").Return(test.findUser, test.findError)

		testService := NewJwtService(mockRepo)

		res, err := testService.CheckUser(test.in)

		if test.mockError == nil {
			assert.Nil(t, err)
			assert.NotNil(t, res)
			assert.Equal(t, test.mockUser.Username, res.Username)
			assert.Equal(t, test.mockUser.Email, res.Email)
			assert.Equal(t, test.mockUser.Password, res.Password)
			assert.Equal(t, test.mockUser.Id, res.Id)
		} else {
			assert.NotNil(t, err)
			assert.Nil(t, res)
		}
	}
}

func TestService_DeleteUser(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		mockRepo := new(mockRepository)
		mockRepo.On("Delete").Return(nil)

		testService := NewJwtService(mockRepo)
		err := testService.DeleteUser(&entity.User{Id: "42"})
		assert.Nil(t, err)
	})
	t.Run("No ID", func(t *testing.T) {
		mockRepo := new(mockRepository)
		mockRepo.On("Delete").Return(nil)

		testService := NewJwtService(mockRepo)
		err := testService.DeleteUser(&entity.User{})
		assert.NotNil(t, err)
	})
}

func TestService_NewPassword(t *testing.T) {
	t.Run("Errors", func(t *testing.T) {
		type newPasswordCase struct {
			input    *entity.ChangePassInput
			fbiUser  *entity.User
			fbiError error
			uError   error
			ret      error
		}

		input := &entity.ChangePassInput{
			Id:       "42",
			Old:      "SHIB>>DOGE",
			Password: "sMaShCaPiTaLiSm",
			Repeated: "sMaShCaPiTaLiSm",
		}

		stored, err := bcrypt.GenerateFromPassword([]byte("SHIB>>DOGE"), 14)
		if err != nil {
			t.Errorf("bcrypt-Error in test")
		}

		fbiUser := &entity.User{
			Password: stored,
		}

		tests := []newPasswordCase{
			{input: func() *entity.ChangePassInput { this := *input; this.Repeated = "tAxThErIcH"; return &this }(), fbiUser: fbiUser, fbiError: nil, uError: nil, ret: errors.New("")},
			{input: func() *entity.ChangePassInput { this := *input; this.Repeated = ""; return &this }(), fbiUser: fbiUser, fbiError: nil, uError: nil, ret: errors.New("")},
			{input: func() *entity.ChangePassInput { this := *input; this.Password = ""; return &this }(), fbiUser: fbiUser, fbiError: nil, uError: nil, ret: errors.New("")},
			{input: func() *entity.ChangePassInput { this := *input; this.Old = "DOGE>>SHIB"; return &this }(), fbiUser: fbiUser, fbiError: nil, uError: nil, ret: errors.New("")},
			{input: input, fbiUser: fbiUser, fbiError: nil, uError: errors.New(""), ret: errors.New("")},
			{input: input, fbiUser: nil, fbiError: errors.New(""), uError: nil, ret: errors.New("")},
			{input: &entity.ChangePassInput{}, fbiUser: fbiUser, fbiError: nil, uError: errors.New(""), ret: errors.New("")},
			{input: &entity.ChangePassInput{Id: "42"}, fbiUser: nil, fbiError: errors.New(""), uError: nil, ret: errors.New("")},
		}

		for _, test := range tests {
			mockRepo := new(mockRepository)

			mockRepo.On("FindById").Return(test.fbiUser, test.fbiError)
			mockRepo.On("UpdateUser").Return(test.uError)

			testService := NewJwtService(mockRepo)

			err := testService.NewPassword(test.input)

			if test.ret == nil {
				assert.Nil(t, err)
			} else {
				assert.NotNil(t, err)
			}
		}
	})
	t.Run("Working example", func(t *testing.T) {
		input := &entity.ChangePassInput{
			Id:       "42",
			Old:      "SHIB>>DOGE",
			Password: "sMaShCaPiTaLiSm",
			Repeated: "sMaShCaPiTaLiSm",
		}

		stored, err := bcrypt.GenerateFromPassword([]byte("SHIB>>DOGE"), 14)
		if err != nil {
			t.Errorf("bcrypt-Error in test")
		}

		fbiUser := &entity.User{
			Password: stored,
		}

		mockRepo := new(mockRepository)
		mockRepo.On("FindById").Return(fbiUser, nil)
		mockRepo.On("UpdateUser").Return(nil)

		testService := NewJwtService(mockRepo)

		assert.Nil(t, testService.NewPassword(input))
	})
}
