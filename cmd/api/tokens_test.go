package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"greenlight.bcc/internal/assert"
)

func TestCreateToken(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	const (
		validEmail    = "test@test.com"
		validPassword = "pa$$word"
	)

	tests := []struct {
		testName string
		Email    string
		Password string
		wantCode int
	}{
		{
			testName: "valid data",
			Email:    validEmail,
			Password: validPassword,
			wantCode: http.StatusCreated,
		},
		{
			testName: "missing email",
			Email:    "",
			Password: validPassword,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			testName: "missing password",
			Email:    validEmail,
			Password: "",
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			testName: "non-valid email",
			Email:    "test",
			Password: validPassword,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			testName: "email not found",
			Email:    "notFound@test.com",
			Password: validPassword,
			wantCode: http.StatusUnauthorized,
		},
		{
			testName: "not matching password",
			Email:    "notMatch@test.com",
			Password: validPassword,
			wantCode: http.StatusUnauthorized,
		},
		{
			testName: "server error while authenticating",
			Email:    "error@test.com",
			Password: validPassword,
			wantCode: http.StatusInternalServerError,
		},
		{
			testName: "server error while creating token",
			Email:    "errorToken@test.com",
			Password: validPassword,
			wantCode: http.StatusInternalServerError,
		},
		{
			testName: "test for wrong input",
			Email:    validEmail,
			Password: validPassword,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {

		t.Run(tt.testName, func(t *testing.T) {
			inputData := struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}{
				Email:    tt.Email,
				Password: tt.Password,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}
			switch tt.testName {
			case "test for wrong input":
				b = append(b, 'a')
				code, _, _ := ts.postForm(t, "/v1/tokens/authentication", b)
				assert.Equal(t, code, tt.wantCode)
			default:
				code, _, _ := ts.postForm(t, "/v1/tokens/authentication", b)
				assert.Equal(t, code, tt.wantCode)
			}
		})
	}
}
