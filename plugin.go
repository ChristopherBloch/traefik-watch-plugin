// Package traefik_watch_plugin is a Traefik v3.7 Yaegi middleware.
// The package name matches the last segment of the module path, which Yaegi requires.
package traefik_watch_plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config is filled by Traefik from the middleware plugin configuration.
type Config struct {
	WatchURL     string `mapstructure:"watchUrl"`
	Token        string `mapstructure:"token"`
	PollInterval string `mapstructure:"pollInterval"`
	BlockStatus  int    `mapstructure:"blockStatus"`
}

type stateResponse struct {
	Blocked []string `json:"blocked"`
	Rules   []Rule   `json:"rules"`
	Allow   []Rule   `json:"allow"`
}

type ingestResponse struct {
	Block    bool   `json:"block"`
	ClientIP string `json:"client_ip"`
}

type accessEvent struct {
	StartUTC         string `json:"StartUTC"`
	ClientHost       string `json:"ClientHost"`
	RequestHost      string `json:"RequestHost"`
	RequestPath      string `json:"RequestPath"`
	RequestMethod    string `json:"RequestMethod"`
	DownstreamStatus int    `json:"DownstreamStatus"`
	RouterName       string `json:"RouterName"`
	ServiceName      string `json:"ServiceName"`
}

type logJob struct {
	event accessEvent
}

// CreateConfig returns the defaults Traefik decodes the middleware settings into.
func CreateConfig() *Config {
	return &Config{
		PollInterval: "5s",
		BlockStatus:  http.StatusForbidden,
	}
}

type watcher struct {
	next        http.Handler
	name        string
	watchURL    string
	token       string
	blockStatus int
	client      *http.Client
	jobs        chan logJob
	mu          sync.RWMutex
	blocked     map[string]struct{}
	rules       []Rule
	allow       []Rule
}

// New builds the middleware Traefik v3.7.18 calls for each plugin middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil || strings.TrimSpace(config.WatchURL) == "" || strings.TrimSpace(config.Token) == "" {
		return nil, fmt.Errorf("traefikwatch: watchUrl and token are required")
	}
	interval, err := time.ParseDuration(config.PollInterval)
	if err != nil || interval < time.Second {
		interval = 5 * time.Second
	}
	status := config.BlockStatus
	if status < 400 || status > 599 {
		status = http.StatusForbidden
	}
	handler := &watcher{
		next:        next,
		name:        name,
		watchURL:    strings.TrimRight(config.WatchURL, "/"),
		token:       config.Token,
		blockStatus: status,
		client:      &http.Client{Timeout: 2 * time.Second},
		jobs:        make(chan logJob, 256),
		blocked:     map[string]struct{}{},
	}
	handler.refresh()
	go handler.loop(ctx, interval)
	return handler, nil
}

func (w *watcher) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ip := clientIP(req)
	host := hostname(req.Host)
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	if ip != "" && !w.allowed(ip, host, path) && (w.isBlocked(ip) || w.dangerous(ip, host, path, req.URL.RawQuery, 0)) {
		http.Error(rw, "Forbidden", w.blockStatus)
		w.enqueue(accessEvent{
			StartUTC:         time.Now().UTC().Format(time.RFC3339Nano),
			ClientHost:       ip,
			RequestHost:      host,
			RequestPath:      req.URL.RequestURI(),
			RequestMethod:    req.Method,
			DownstreamStatus: w.blockStatus,
		})
		return
	}

	recorder := &statusRecorder{ResponseWriter: rw, status: http.StatusOK}
	w.next.ServeHTTP(recorder, req)
	w.enqueue(accessEvent{
		StartUTC:         time.Now().UTC().Format(time.RFC3339Nano),
		ClientHost:       ip,
		RequestHost:      host,
		RequestPath:      req.URL.RequestURI(),
		RequestMethod:    req.Method,
		DownstreamStatus: recorder.status,
	})
}

func (w *watcher) loop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.refresh()
		case job := <-w.jobs:
			w.send(job.event)
		}
	}
}

func (w *watcher) enqueue(event accessEvent) {
	select {
	case w.jobs <- logJob{event: event}:
	default:
	}
}

func (w *watcher) refresh() {
	body, err := w.get("/api/plugin/state")
	if err != nil {
		return
	}
	var state stateResponse
	if json.Unmarshal(body, &state) != nil {
		return
	}
	blocked := make(map[string]struct{}, len(state.Blocked))
	for _, ip := range state.Blocked {
		if ip != "" {
			blocked[ip] = struct{}{}
		}
	}
	w.mu.Lock()
	w.blocked = blocked
	w.rules = state.Rules
	w.allow = state.Allow
	w.mu.Unlock()
}

func (w *watcher) send(event accessEvent) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	body, err := w.post("/api/ingest", payload)
	if err != nil {
		return
	}
	var decision ingestResponse
	if json.Unmarshal(body, &decision) != nil || !decision.Block {
		return
	}
	ip := decision.ClientIP
	if ip == "" {
		ip = event.ClientHost
	}
	w.remember(ip)
}

func (w *watcher) get(path string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, w.watchURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("X-Traefik-Watch-Token", w.token)
	return w.do(request)
}

func (w *watcher) post(path string, payload []byte) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, w.watchURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Traefik-Watch-Token", w.token)
	return w.do(request)
}

func (w *watcher) do(request *http.Request) ([]byte, error) {
	response, err := w.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("traefikwatch: %s", response.Status)
	}
	return body, nil
}

func (w *watcher) allowed(ip, host, path string) bool {
	w.mu.RLock()
	rules := w.allow
	w.mu.RUnlock()
	return Allowed(ip, host, path, rules)
}

func (w *watcher) dangerous(ip, host, path, rawQuery string, status int) bool {
	w.mu.RLock()
	rules := w.rules
	w.mu.RUnlock()
	return Dangerous(ip, host, path, rawQuery, status, rules)
}

func (w *watcher) isBlocked(ip string) bool {
	w.mu.RLock()
	_, ok := w.blocked[ip]
	w.mu.RUnlock()
	return ok
}

func (w *watcher) remember(ip string) {
	if ip == "" {
		return
	}
	w.mu.Lock()
	w.blocked[ip] = struct{}{}
	w.mu.Unlock()
}

func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func hostname(host string) string {
	if strings.HasPrefix(host, "[") {
		if end := strings.Index(host, "]"); end >= 0 {
			return host[:end+1]
		}
	}
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return name
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(payload []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	return s.ResponseWriter.Write(payload)
}

func (s *statusRecorder) Flush() {
	if flusher, ok := s.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
