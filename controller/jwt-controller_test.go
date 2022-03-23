package controller

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/nillga/jwt-server/entity"
	"github.com/nillga/jwt-server/repository"
	"github.com/nillga/jwt-server/service"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

type mockRepo struct {
	users []entity.User
}

type failRepo struct {
	mockRepo
}

func (f *failRepo) Store(user *entity.User) (*entity.User, error) {
	return nil, errors.New("")
}

func (m *mockRepo) Store(user *entity.User) (*entity.User, error) {
	m.users = append(m.users, *user)
	return user, nil
}

func (m *mockRepo) Find(user *entity.User) (*entity.User, error) {
	for _, u := range m.users {
		if user.Id == u.Id || user.Username == u.Username || user.Email == u.Email {
			return &u, nil
		}
	}
	return nil, errors.New("")
}
func (m *mockRepo) FindById(id string) (*entity.User, error) {
	for _, u := range m.users {
		if id == u.Id {
			return &u, nil
		}
	}
	return nil, errors.New("")
}
func (m *mockRepo) UpdateUser(id string, user *entity.User) error {
	for i, u := range m.users {
		if id == u.Id {
			m.users[i] = *user
			return nil
		}
	}
	return errors.New("")
}
func (m *mockRepo) Delete(id string) error {
	for i, u := range m.users {
		if id == u.Id {
			if i == len(m.users)-1 {
				m.users = m.users[:i]
				return nil
			}
			m.users = append(m.users[:i], m.users[i+1:]...)
			return nil
		}
	}
	return errors.New("")
}

func NewMockRepo() repository.JwtRepository {
	return &mockRepo{[]entity.User{}}
}

type testTable struct {
	name         string
	method       string
	input        []byte
	statusCode   int
	responseText string
}

func TestController_Signup(t *testing.T) {
	type suTable struct {
		testTable
		repo repository.JwtRepository
	}
	signUpTests := []suTable{
		{
			testTable{"Perfectly fine", http.MethodPost,
				[]byte(`{"username":"` + "daniel" + `","mail":"` + "daniel@wierbicki.org" + `","password":"` + "mehmJIFF" + `","repeated":"` + "mehmJIFF" + `"}`),
				http.StatusOK, ""}, NewMockRepo(),
		},
		{
			testTable{"Broken JSON", http.MethodPost,
				[]byte(`kekw`),
				http.StatusBadRequest, `{"message":"` + http.StatusText(http.StatusBadRequest) + `"}` + "\n",
			}, NewMockRepo(),
		},
		{
			testTable{"Invalid Input", http.MethodPost,
				[]byte(`{"username":"` + "daniel" + `","mail":"` + "daniel@wierbicki.org" + `","password":"` + "" + `","repeated":"` + "" + `"}`),
				http.StatusBadRequest, `{"message":"` + "no password provided" + `"}` + "\n"}, NewMockRepo(),
		},
		{
			testTable{"Repo error", http.MethodPost,
				[]byte(`{"username":"` + "daniel" + `","mail":"` + "daniel@wierbicki.org" + `","password":"` + "mehmJIFF" + `","repeated":"` + "mehmJIFF" + `"}`),
				http.StatusInternalServerError, `{"message":"` + "Failed creating new user." + `"}` + "\n"}, &failRepo{},
		},
	}

	for _, test := range signUpTests {
		t.Run(test.name, func(t *testing.T) {
			testService := service.NewJwtService(test.repo)
			testController := NewController(testService)

			req, _ := http.NewRequest(test.method, "/signup", bytes.NewBuffer(test.input))

			handler := http.HandlerFunc(testController.SignUp)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)

			if status := response.Code; status != test.statusCode {
				t.Errorf("Received status %d but wanted %d", status, test.statusCode)
			}

			resp := response.Body.String()
			assert.Equal(t, test.responseText, resp)
		})
	}
}

func TestController_Login_Errors(t *testing.T) {
	os.Setenv("JWT_SECRET_KEY", "lenin")

	stored, _ := bcrypt.GenerateFromPassword([]byte("dogecoin"), 14)

	testService := service.NewJwtService(&mockRepo{users: []entity.User{
		{Id: "1917", Username: "daniel", Email: "test@wierbicki.org", Password: stored},
	}})

	testController := NewController(testService)

	loginTests := []testTable{
		{
			"Broken JSON", http.MethodGet,
			[]byte(`kekw`),
			http.StatusInternalServerError, `{"message":"` + "Failed reading request body." + `"}` + "\n",
		},
		{
			"Invalid Input", http.MethodGet,
			[]byte(`{"id":"` + "daniel" + `","password":"` + "mehmJIFF" + `"}`),
			http.StatusBadRequest, `{"message":"` + "Invalid login data." + `"}` + "\n",
		},
	}

	for _, test := range loginTests {
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, "/login", bytes.NewBuffer(test.input))

			handler := http.HandlerFunc(testController.Login)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)

			if status := response.Code; status != test.statusCode {
				t.Errorf("Received status %d but wanted %d", status, test.statusCode)
			}

			resp := response.Body.String()
			assert.Equal(t, test.responseText, resp)
		})
	}
}

func TestController_Login_Fine(t *testing.T) {
	os.Setenv("JWT_SECRET_KEY", "lenin")

	stored, _ := bcrypt.GenerateFromPassword([]byte("dogecoin"), 14)

	testService := service.NewJwtService(&mockRepo{users: []entity.User{
		{Id: "1917", Username: "daniel", Email: "test@wierbicki.org", Password: stored},
	}})

	testController := NewController(testService)

	loginTest := testTable{
		"Valid", http.MethodGet,
		[]byte(`{"id":"` + "daniel" + `","password":"` + "dogecoin" + `"}`),
		http.StatusOK, "",
	}

	req, _ := http.NewRequest(loginTest.method, "/login", bytes.NewBuffer(loginTest.input))
	handler := http.HandlerFunc(testController.Login)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	if status := response.Code; status != loginTest.statusCode {
		t.Errorf("Received status %d but wanted %d", status, loginTest.statusCode)
	}

	resp := response.Body.String()
	assert.Equal(t, loginTest.responseText, resp)
	assert.NotNil(t, response.Result().Cookies())
	assert.Equal(t, 1, len(response.Result().Cookies()))

	cookie := response.Result().Cookies()[0]

	assert.Equal(t, "jwt", cookie.Name)

	claims := &Claims{}
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(cookie)
	err := claims.decodeJwt(r)
	if err != nil {
		t.Errorf("Cookie could not be decoded!")
	}

	assert.Equal(t, "1917", claims.Username)
}

func TestController_Resolve_Success(t *testing.T) {
	stored, _ := bcrypt.GenerateFromPassword([]byte("dogecoin"), 14)

	testService := service.NewJwtService(&mockRepo{users: []entity.User{
		{Id: "1917", Username: "daniel", Email: "test@wierbicki.org", Password: stored},
	}})

	testController := NewController(testService)

	test := testTable{
		"Valid", http.MethodGet, []byte{}, http.StatusOK, `{"_id":"` + "1917" + `","name":"` + "daniel" + `","email":"` + "test@wierbicki.org" + `","password":"` + base64.StdEncoding.EncodeToString(stored) + `","admin":` + "false" + `}` + "\n",
	}

	claims := &Claims{
		Username: "1917",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secretKey))

	cookie := http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 2),
		Path:    "/",
	}

	req, _ := http.NewRequest(test.method, "/resolve", bytes.NewBuffer(test.input))
	req.AddCookie(&cookie)
	handler := http.HandlerFunc(testController.Resolve)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)

	if status := response.Code; status != test.statusCode {
		t.Errorf("Received status %d but wanted %d", status, test.statusCode)
	}

	resp := response.Body.String()
	assert.Equal(t, test.responseText, resp)
}

func TestController_Resolve_Errors(t *testing.T) {
	stored, _ := bcrypt.GenerateFromPassword([]byte("dogecoin"), 14)

	testService := service.NewJwtService(&mockRepo{users: []entity.User{
		{Id: "1917", Username: "daniel", Email: "test@wierbicki.org", Password: stored},
	}})

	testController := NewController(testService)

	test := testTable{
		"Valid", http.MethodGet, []byte{}, http.StatusOK, `{"_id":"` + "1917" + `","name":"` + "daniel" + `","email":"` + "test@wierbicki.org" + `","password":"` + base64.StdEncoding.EncodeToString(stored) + `"}` + "\n",
	}

	t.Run("Invalid cookie", func(t *testing.T) {
		test.statusCode = http.StatusInternalServerError
		test.responseText = `{"message":"` + "Failed finding user." + `"}` + "\n"
		claims := &Claims{
			Username: "AynRand",
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, _ := token.SignedString([]byte(secretKey))

		cookie := http.Cookie{
			Name:    "jwt",
			Value:   tokenString,
			Expires: time.Now().Add(time.Hour * 2),
			Path:    "/",
		}

		req, _ := http.NewRequest(test.method, "/resolve", bytes.NewBuffer(test.input))
		req.AddCookie(&cookie)
		handler := http.HandlerFunc(testController.Resolve)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)

		if status := response.Code; status != test.statusCode {
			t.Errorf("Received status %d but wanted %d", status, test.statusCode)
		}

		resp := response.Body.String()
		assert.Equal(t, test.responseText, resp)
	})
	t.Run("No cookie", func(t *testing.T) {
		test.statusCode = http.StatusUnauthorized
		test.responseText = `{"message":"` + "Not authenticated. This resource can not be accessed." + `"}` + "\n"
		req, _ := http.NewRequest(test.method, "/resolve", bytes.NewBuffer(test.input))
		handler := http.HandlerFunc(testController.Resolve)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)

		if status := response.Code; status != test.statusCode {
			t.Errorf("Received status %d but wanted %d", status, test.statusCode)
		}

		resp := response.Body.String()
		assert.Equal(t, test.responseText, resp)
	})
}

func TestController_Delete(t *testing.T) {
	type deleteTable struct {
		testTable
		cookie     *http.Cookie
		availUsers int
		retCookie  bool
	}
	claims := &Claims{
		Username: "AynRand",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secretKey))

	invalid := http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 2),
		Path:    "/",
	}

	claims.Username = "1917"
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ = token.SignedString([]byte(secretKey))
	valid := http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 2),
		Path:    "/",
	}

	claims.Username = "191"
	claims.Admin = true
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ = token.SignedString([]byte(secretKey))

	su := http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 2),
		Path:    "/",
	}

	tests := []deleteTable{
		{testTable{"Valid", http.MethodPost, []byte(`{"id":"` + "1917" + `"}`), http.StatusOK, ""}, &valid, 0, true},
		{testTable{"No cookie", http.MethodPost, []byte{}, http.StatusUnauthorized, `{"message":"` + "Not authenticated. This resource can not be accessed." + `"}` + "\n"}, nil, 1, false},
		{testTable{"Invalid Cookie", http.MethodPost, []byte(`{"id":"` + "1917" + `"}`), http.StatusUnauthorized, `{"message":"` + "No permissions to delete this user" + `"}` + "\n"}, &invalid, 1, false},
		{testTable{"Invalid Id", http.MethodPost, []byte(`{"id":"` + "19170" + `"}`), http.StatusInternalServerError, `{"message":"` + "Failed deleting user." + `"}` + "\n"}, &su, 1, false},
		{testTable{"Invalid Request", http.MethodPost, []byte(`"di":"` + "1917" + `"}[`), http.StatusBadRequest, `{"message":"` + "Failed reading request body." + `"}` + "\n"}, &valid, 1, false},
	}

	for _, test := range tests {
		stored, _ := bcrypt.GenerateFromPassword([]byte("dogecoin"), 14)

		repo := &mockRepo{users: []entity.User{
			{Id: "1917", Username: "daniel", Email: "test@wierbicki.org", Password: stored},
		}}

		testService := service.NewJwtService(repo)

		testController := NewController(testService)

		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, "/delete", bytes.NewBuffer(test.input))
			if test.cookie != nil {
				req.AddCookie(test.cookie)
			}
			handler := http.HandlerFunc(testController.Delete)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)

			if status := response.Code; status != test.statusCode {
				t.Errorf("Received status %d but wanted %d", status, test.statusCode)
			}

			resp := response.Body.String()
			assert.Equal(t, test.responseText, resp)

			assert.Equal(t, test.availUsers, len(repo.users))

			if test.retCookie {
				assert.NotNil(t, response.Result().Cookies())
				assert.Equal(t, 1, len(response.Result().Cookies()))

				cookie := response.Result().Cookies()[0]

				assert.Equal(t, "jwt", cookie.Name)
				assert.Equal(t, "", cookie.Value)
				assert.True(t, cookie.Expires.Before(time.Now()))
			}
		})
	}
}

func TestController_ChangePassword(t *testing.T) {
	claims := &Claims{
		Username: "1917",
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 2).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, _ := token.SignedString([]byte(secretKey))

	valid := http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 2),
		Path:    "/",
	}

	type passTable struct {
		testTable
		cookie *http.Cookie
	}

	tests := []passTable{{testTable{
		"Valid", http.MethodPut,
		[]byte(`{"old":"` + "3th3r3um" + `","password":"` + "m3hm-3ng1n33r1ng" + `","repeated":"` + "m3hm-3ng1n33r1ng" + `"}`),
		http.StatusOK, ""}, &valid,
	}, {testTable{
		"No Cookie", http.MethodPut,
		[]byte(`{"old":"` + "3th3r3um" + `","password":"` + "m3hm-3ng1n33r1ng" + `","repeated":"` + "m3hm-3ng1n33r1ng" + `"}`),
		http.StatusUnauthorized, `{"message":"` + "Not authenticated. This resource can not be accessed." + `"}` + "\n"}, nil,
	}, {testTable{
		"Wrong body", http.MethodPut,
		[]byte{},
		http.StatusBadRequest, `{"message":"` + "EOF" + `"}` + "\n"}, &valid,
	}, {testTable{
		"Format error", http.MethodPut,
		[]byte(`{"old":"` + "3th3r3um" + `","password":"` + "" + `","repeated":"` + "m3hm-3ng1n33r1ng" + `"}`),
		http.StatusInternalServerError, `{"message":"` + "no new password provided" + `"}` + "\n"}, &valid,
	},
	}

	for _, test := range tests {
		stored, _ := bcrypt.GenerateFromPassword([]byte("3th3r3um"), 14)

		repo := &mockRepo{users: []entity.User{
			{Id: "1917", Username: "daniel", Email: "test@wierbicki.org", Password: stored},
		}}

		testService := service.NewJwtService(repo)

		testController := NewController(testService)

		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest(test.method, "/newpass", bytes.NewBuffer(test.input))
			if test.cookie != nil {
				req.AddCookie(test.cookie)
			}
			handler := http.HandlerFunc(testController.ChangePassword)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)

			if status := response.Code; status != test.statusCode {
				t.Errorf("Received status %d but wanted %d", status, test.statusCode)
			}

			resp := response.Body.String()
			assert.Equal(t, test.responseText, resp)
		})
	}
}

func TestDecodeCookie(t *testing.T) {
	invalid := &http.Cookie{
		Name:    "jwt",
		Value:   "10",
		Expires: time.Now().Add(time.Hour * 2),
		Path:    "/",
	}

	req := &http.Request{Header: http.Header{}}
	req.AddCookie(invalid)

	testClaims := Claims{}

	assert.NotNil(t, testClaims.decodeJwt(req))
}
