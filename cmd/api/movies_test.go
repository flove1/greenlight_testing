package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"greenlight.bcc/internal/assert"
)

func TestShowMovie(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	tests := []struct {
		name     string
		urlPath  string
		wantCode int
	}{
		{
			name:     "Valid ID",
			urlPath:  "/v1/movies/1",
			wantCode: http.StatusOK,
		},
		{
			name:     "Non-existent ID",
			urlPath:  "/v1/movies/100",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Negative ID",
			urlPath:  "/v1/movies/-1",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Decimal ID",
			urlPath:  "/v1/movies/1.23",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "String ID",
			urlPath:  "/v1/movies/foo",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Error while retriving",
			urlPath:  "/v1/movies/11",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.get(t, tt.urlPath)
			assert.Equal(t, code, tt.wantCode)
		})
	}
}

func TestCreateMovie(t *testing.T) {
	app := newTestApplication(t, false)
	ts := newTestServer(t, app.routes())
	defer ts.Close()

	const (
		validTitle   = "Test Title"
		validYear    = 2021
		validRuntime = "105 mins"
	)

	validGenres := []string{"comedy", "drama"}

	tests := []struct {
		name     string
		Title    string
		Year     int32
		Runtime  string
		Genres   []string
		wantCode int
	}{
		{
			name:     "Valid submission",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusCreated,
		},
		{
			name:     "Empty Title",
			Title:    "",
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "year < 1888",
			Title:    validTitle,
			Year:     1500,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "error while inserting",
			Title:    "error",
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "test for wrong input",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Title   string   `json:"title"`
				Year    int32    `json:"year"`
				Runtime string   `json:"runtime"`
				Genres  []string `json:"genres"`
			}{
				Title:   tt.Title,
				Year:    tt.Year,
				Runtime: tt.Runtime,
				Genres:  tt.Genres,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}

			switch tt.name {
			case "test for wrong input":
				b = append(b, 'a')
				code, _, _ := ts.postForm(t, "/v1/movies", b)
				assert.Equal(t, code, tt.wantCode)
			default:
				code, _, _ := ts.postForm(t, "/v1/movies", b)
				assert.Equal(t, code, tt.wantCode)
			}
		})
	}
}

func TestUpdateMovie(t *testing.T) {
	app := newTestApplication(t, false)
	ts := newTestServer(t, app.routes())
	defer ts.Close()

	const (
		validTitle   = "Test Title"
		validYear    = 2021
		validRuntime = "105 mins"
	)

	validGenres := []string{"comedy", "drama"}

	tests := []struct {
		name     string
		urlPath  string
		Title    string
		Year     int32
		Runtime  string
		Genres   []string
		wantCode int
	}{
		{
			name:     "valid submission",
			urlPath:  "/v1/movies/1",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusOK,
		},
		{
			name:     "empty Title",
			urlPath:  "/v1/movies/1",
			Title:    "",
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "year < 1888",
			urlPath:  "/v1/movies/1",
			Title:    validTitle,
			Year:     1500,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "non-existing id",
			urlPath:  "/v1/movies/100",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusNotFound,
		},
		{
			name:     "test for wrong input",
			urlPath:  "/v1/movies/1",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "test for wrong id",
			urlPath:  "/v1/movies/a",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusNotFound,
		},
		{
			name:     "test for error while retriving",
			urlPath:  "/v1/movies/11",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "test for edit conflict",
			urlPath:  "/v1/movies/12",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusConflict,
		},
		{
			name:     "test for error while updating",
			urlPath:  "/v1/movies/13",
			Title:    validTitle,
			Year:     validYear,
			Runtime:  validRuntime,
			Genres:   validGenres,
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Title   string   `json:"title"`
				Year    int32    `json:"year"`
				Runtime string   `json:"runtime"`
				Genres  []string `json:"genres"`
			}{

				Title:   tt.Title,
				Year:    tt.Year,
				Runtime: tt.Runtime,
				Genres:  tt.Genres,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}

			switch tt.name {
			case "test for wrong input":
				b = append(b, 'a')
				code, _, _ := ts.patchForm(t, tt.urlPath, b)
				assert.Equal(t, code, tt.wantCode)
			default:
				code, _, _ := ts.patchForm(t, tt.urlPath, b)
				assert.Equal(t, code, tt.wantCode)
			}
		})
	}
}

func TestDeleteMovie(t *testing.T) {
	app := newTestApplication(t, false)
	ts := newTestServer(t, app.routes())
	defer ts.Close()

	tests := []struct {
		name     string
		urlPath  string
		wantCode int
	}{
		{
			name:     "deleting existing movie",
			urlPath:  "/v1/movies/1",
			wantCode: http.StatusOK,
		},
		{
			name:     "Non-existent ID",
			urlPath:  "/v1/movies/100",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "Wrong ID",
			urlPath:  "/v1/movies/2a",
			wantCode: http.StatusNotFound,
		},
		{
			name:     "test for error while deleting",
			urlPath:  "/v1/movies/13",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.deleteReq(t, tt.urlPath)
			assert.Equal(t, code, tt.wantCode)
		})
	}
}

func TestListMovie(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	const (
		validTitle    = "Test"
		validPage     = 1
		validPageSize = 10
		validSort     = "id"
	)

	validGenres := "comedy,drama"

	tests := []struct {
		name     string
		urlPath  string
		wantCode int
	}{
		{
			name:     "Valid filters",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", validTitle, validGenres, validPage, validPageSize, validSort),
			wantCode: http.StatusOK,
		},
		{
			name:     "Negative page",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", validTitle, validGenres, -1, validPageSize, validSort),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Negative page size",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", validTitle, validGenres, validPage, -1, validSort),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Too large page",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", validTitle, validGenres, 10_000_001, validPageSize, validSort),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Too large page size",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", validTitle, validGenres, validPage, 101, validSort),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Non-valid sort value",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", validTitle, validGenres, validPage, validPageSize, "version"),
			wantCode: http.StatusUnprocessableEntity,
		},
		{
			name:     "Error while retrieving",
			urlPath:  fmt.Sprintf("/v1/movies?title=%s&genres=%s&page=%d&page_size=%d&sort=%s", "error", validGenres, validPage, validPageSize, validSort),
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.get(t, tt.urlPath)
			assert.Equal(t, code, tt.wantCode)
		})
	}
}
