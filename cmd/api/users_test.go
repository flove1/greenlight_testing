package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"greenlight.bcc/internal/assert"
)

func TestRegisterUser(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	const (
		validName     = "Test"
		validEmail    = "test@test.com"
		validPassword = "pa$$word"
	)

	tests := []struct {
		name     string
		Name     string
		Email    string
		Password string
		wantCode int
	}{
		{
			name:     "valid data",
			Name:     validName,
			Email:    validEmail,
			Password: validPassword,
			wantCode: http.StatusCreated,
		},
		{
			name:     "non-valid name",
			Name:     "",
			Email:    validEmail,
			Password: validPassword,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "non-valid email",
			Name:     validName,
			Email:    "test",
			Password: validPassword,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "non-valid password",
			Name:     validName,
			Email:    validEmail,
			Password: "",
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "too long password",
			Name:     validName,
			Email:    validEmail,
			Password: strings.Repeat("1", 100),
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "email already exists",
			Name:     validName,
			Email:    "exists@test.com",
			Password: validPassword,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "error on insert",
			Name:     validName,
			Email:    "errorInsert@test.com",
			Password: validPassword,
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "error on permissions insert",
			Name:     validName,
			Email:    "errorPermissions@test.com",
			Password: validPassword,
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "error on tokens insert",
			Name:     validName,
			Email:    "errorTokens@test.com",
			Password: validPassword,
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "test for wrong input",
			Name:     validName,
			Email:    validEmail,
			Password: validPassword,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Name     string `json:"name"`
				Email    string `json:"email"`
				Password string `json:"password"`
			}{

				Name:     tt.Name,
				Email:    tt.Email,
				Password: tt.Password,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}
			switch tt.name {
			case "test for wrong input":
				b = append(b, 'a')
				code, _, _ := ts.postForm(t, "/v1/users", b)
				assert.Equal(t, code, tt.wantCode)
			default:
				code, _, _ := ts.postForm(t, "/v1/users", b)
				assert.Equal(t, code, tt.wantCode)
			}
		})
	}
}

func TestActivateUser(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	tests := []struct {
		name     string
		Token    string
		wantCode int
	}{
		{
			name:     "valid data",
			Token:    strings.Repeat("a", 26),
			wantCode: http.StatusOK,
		},
		{
			name:     "non-valid token",
			Token:    "",
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "expired token",
			Token:    strings.Repeat("b", 26),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "server error while retriving user",
			Token:    strings.Repeat("c", 26),
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "conflict while updating user",
			Token:    strings.Repeat("d", 26),
			wantCode: http.StatusConflict,
		},
		{
			name:     "error while updating user",
			Token:    strings.Repeat("e", 26),
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "error while deleting tokens",
			Token:    strings.Repeat("f", 26),
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "test for wrong input",
			Token:    strings.Repeat("a", 26),
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Token string `json:"token"`
			}{
				Token: tt.Token,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}
			switch tt.name {
			case "test for wrong input":
				b = append(b, 'a')
				code, _, _ := ts.putForm(t, "/v1/users/activated", b)
				assert.Equal(t, code, tt.wantCode)
			default:
				code, _, _ := ts.putForm(t, "/v1/users/activated", b)
				assert.Equal(t, code, tt.wantCode)
			}
		})
	}
}
