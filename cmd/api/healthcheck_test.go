package main

import (
	"net/http"
	"testing"

	"greenlight.bcc/internal/assert"
)

func TestHealthcheck(t *testing.T) {
	app := newTestApplication(t, false)

	ts := newTestServer(t, app.routes())
	defer ts.Close()

	tests := []struct {
		name     string
		wantCode int
		wantBody string
	}{
		{
			name:     "Access test",
			wantCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.get(t, "/v1/healthcheck")
			assert.Equal(t, code, tt.wantCode)
		})
	}
}
