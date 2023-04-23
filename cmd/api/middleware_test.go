package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"greenlight.bcc/internal/assert"
)

func TestAuthentication(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	tests := []struct {
		name     string
		header   string
		wantCode int
	}{
		{
			name:     "empty header",
			header:   "",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "one-word header",
			header:   "eripasdcnk",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "non-valid token header",
			header:   "Bearer token",
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "user not found",
			header:   "Bearer " + strings.Repeat("b", 26),
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "error while retrieving user",
			header:   "Bearer " + strings.Repeat("c", 26),
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "not activated user",
			header:   "Bearer " + strings.Repeat("g", 26),
			wantCode: http.StatusForbidden,
		},
		{
			name:     "permission error",
			header:   "Bearer " + strings.Repeat("h", 26),
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "not enough permission error",
			header:   "Bearer " + strings.Repeat("k", 26),
			wantCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(map[string]string)
			headers["Authorization"] = tt.header
			code, _, _ := ts.getCustomHeaders(t, "/v1/movies", headers)
			assert.Equal(t, code, tt.wantCode)
		})
	}

}

func TestOtherMiddleware(t *testing.T) {
	app := newTestApplication(t, true)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	tests := []struct {
		name     string
		wantCode int
	}{
		{
			name:     "panic recover",
			wantCode: http.StatusInternalServerError,
		},
		{
			name:     "rate limiter",
			wantCode: http.StatusTooManyRequests,
		},
		{
			name:     "cors",
			wantCode: http.StatusOK,
		},
		{
			name:     "cors options",
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var code int
			switch tt.name {
			case "panic recover":
				code, _, _ = ts.get(t, "/v1/movies/404")
			case "rate limiter":
				exitChan := make(chan int)
				rate_func := func(ts *testServer, exit chan int) {
					code, _, _ := ts.get(t, "/v1/movies/1")
					exit <- code
				}
				for i := 0; i < 9; i++ {
					go rate_func(ts, exitChan)
				}
				time.Sleep(3 * time.Minute)
				go rate_func(ts, exitChan)
				for i := 0; i < 10; i++ {
					code = <-exitChan
					if code == http.StatusTooManyRequests {
						break
					}
				}
			case "cors":
				headers := make(map[string]string)
				headers["Authorization"] = "Bearer abcdefghijklmnopqrstuvwxyz"
				headers["Origin"] = "https://localhost:4000"
				code, _, _ = ts.getCustomHeaders(t, "/v1/movies/1", headers)
			case "cors options":
				headers := make(map[string]string)
				headers["Authorization"] = "Bearer abcdefghijklmnopqrstuvwxyz"
				headers["Origin"] = "https://localhost:8000"
				headers["Access-Control-Request-Method"] = "true"
				code, _, _ = ts.optionsCustomHeaders(t, "/v1/movies/1", headers)
			}
			assert.Equal(t, code, tt.wantCode)

			time.Sleep(250 * time.Millisecond)
		})
	}

}
