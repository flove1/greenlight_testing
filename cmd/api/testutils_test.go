package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"greenlight.bcc/internal/data"
	"greenlight.bcc/internal/jsonlog"
)

func newTestApplication(t *testing.T, enableLimiter bool) *application {
	config := config{}
	if enableLimiter {
		config.limiter.enabled = true
		config.limiter.burst = 4
		config.limiter.rps = 4
	}
	config.cors.trustedOrigins = []string{"https://localhost:8000"}
	config.env = "testing"
	application := application{
		logger: jsonlog.New(io.Discard, jsonlog.LevelFatal),
		models: data.NewMockModels(),
		config: config,
	}
	return &application
}

type testServer struct {
	*httptest.Server
}

func newTestServer(t *testing.T, h http.Handler) *testServer {
	ts := httptest.NewServer(h)

	ts.Client().CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &testServer{ts}
}

func retrieve(ts *testServer, t *testing.T, urlPath string, method string, headers map[string]string) (int, http.Header, string) {
	req, err := http.NewRequest(method, ts.URL+urlPath, nil)
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	if err != nil {
		t.Fatal(err)
	}

	rs, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}

	if err != nil {
		t.Fatal(err)
	}

	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	bytes.TrimSpace(body)

	return rs.StatusCode, rs.Header, string(body)
}

func (ts *testServer) get(t *testing.T, urlPath string) (int, http.Header, string) {
	headers := make(map[string]string)
	headers["Authorization"] = "Bearer abcdefghijklmnopqrstuvwxyz"
	headers["Origin"] = "https://localhost:8000"
	return retrieve(ts, t, urlPath, http.MethodGet, headers)
}

func (ts *testServer) getCustomHeaders(t *testing.T, urlPath string, headers map[string]string) (int, http.Header, string) {
	return retrieve(ts, t, urlPath, http.MethodGet, headers)
}

func (ts *testServer) optionsCustomHeaders(t *testing.T, urlPath string, headers map[string]string) (int, http.Header, string) {
	return retrieve(ts, t, urlPath, http.MethodOptions, headers)
}

func form(ts *testServer, t *testing.T, urlPath string, method string, data []byte) (int, http.Header, string) {
	var (
		req *http.Request
		err error
	)

	if data == nil {
		req, err = http.NewRequest(method, ts.URL+urlPath, nil)
	} else {
		req, err = http.NewRequest(method, ts.URL+urlPath, bytes.NewReader(data))
	}

	req.Header.Add("Authorization", "Bearer abcdefghijklmnopqrstuvwxyz")
	req.Header.Add("Origin", "https://localhost:8000")

	if err != nil {
		t.Fatal(err)
	}

	rs, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	bytes.TrimSpace(body)

	return rs.StatusCode, rs.Header, string(body)
}

func (ts *testServer) deleteReq(t *testing.T, urlPath string) (int, http.Header, string) {
	return form(ts, t, urlPath, http.MethodDelete, nil)
}

func (ts *testServer) postForm(t *testing.T, urlPath string, data []byte) (int, http.Header, string) {
	return form(ts, t, urlPath, http.MethodPost, data)
}

func (ts *testServer) patchForm(t *testing.T, urlPath string, data []byte) (int, http.Header, string) {
	return form(ts, t, urlPath, http.MethodPatch, data)
}

func (ts *testServer) putForm(t *testing.T, urlPath string, data []byte) (int, http.Header, string) {
	return form(ts, t, urlPath, http.MethodPut, data)
}
