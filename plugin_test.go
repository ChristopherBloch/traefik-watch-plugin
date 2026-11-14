package traefik_watch_plugin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareRejectsBlockedIPBeforeNext(t *testing.T) {
	handler := &watcher{
		next: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("upstream should not see a blocked IP")
		}),
		blockStatus: http.StatusForbidden,
		jobs:        make(chan logJob, 1),
		blocked:     map[string]struct{}{"203.0.113.10": {}},
	}
	request := httptest.NewRequest(http.MethodGet, "http://app.example.test/admin", nil)
	request.RemoteAddr = "203.0.113.10:4321"
	request.Host = "app.example.test"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestMiddlewareAllowsWhitelistedIP(t *testing.T) {
	called := false
	handler := &watcher{
		next: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			called = true
			rw.WriteHeader(http.StatusNoContent)
		}),
		blockStatus: http.StatusForbidden,
		jobs:        make(chan logJob, 1),
		blocked:     map[string]struct{}{"203.0.113.10": {}},
		allow:       []Rule{{Kind: "ip", Value: "203.0.113.10"}},
	}
	request := httptest.NewRequest(http.MethodGet, "http://app.example.test/", nil)
	request.RemoteAddr = "203.0.113.10:4321"
	request.Host = "app.example.test"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("called %v status %d", called, recorder.Code)
	}
}
