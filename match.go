package traefik_watch_plugin

import (
	"net"
	"regexp"
	"strings"
)

// Rule is one allow or block rule published by Traefik Watch.
type Rule struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

var (
	sensitivePath = regexp.MustCompile(`(?i)(^|/)(\.env|\.git|wp-admin|wp-login|phpmyadmin|admin|actuator|graphql|backup|config|login|oauth|debug)(/|$)`)
	longSecret    = regexp.MustCompile(`^[A-Za-z0-9_-]{32,}\.?[A-Za-z0-9_-]*\.?[A-Za-z0-9_-]*$`)
	sensitiveKey  = regexp.MustCompile(`(?i)password|passwd|secret|token|api[_-]?key|authorization|credential|session|signature`)
)

// Dangerous reports whether the request itself matches a block rule.
// status 0 means the upstream status is not known yet, so error_status rules wait.
func Dangerous(ip, host, path, rawQuery string, status int, rules []Rule) bool {
	target := strings.ToLower(joinURL(host, path))
	flags := requestFlags(path, rawQuery, status)
	for _, rule := range rules {
		switch rule.Kind {
		case "ip":
			if ipInRule(ip, rule.Value) {
				return true
			}
		case "url":
			if wildcardMatch(rule.Value, target) {
				return true
			}
		case "flag":
			if status == 0 && rule.Value == "error_status" {
				continue
			}
			if hasFlag(flags, rule.Value) {
				return true
			}
		}
	}
	return false
}

// Allowed reports whether a whitelist rule exempts this request.
func Allowed(ip, host, path string, rules []Rule) bool {
	target := strings.ToLower(joinURL(host, path))
	for _, rule := range rules {
		if rule.Kind == "ip" && ipInRule(ip, rule.Value) {
			return true
		}
		if rule.Kind == "url" && wildcardMatch(rule.Value, target) {
			return true
		}
	}
	return false
}

func joinURL(host, path string) string {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return host + path
}

func requestFlags(path, rawQuery string, status int) []string {
	flags := make([]string, 0, 4)
	for _, segment := range strings.Split(path, "/") {
		if longSecret.MatchString(segment) {
			flags = append(flags, "secret_path")
			break
		}
	}
	if sensitivePath.MatchString(path) {
		flags = append(flags, "sensitive_path")
	}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		key := part
		if eq := strings.Index(part, "="); eq >= 0 {
			key = part[:eq]
		}
		if sensitiveKey.MatchString(key) {
			flags = append(flags, "secret_parameter")
			break
		}
	}
	if status == 401 || status == 403 || status == 404 || status >= 500 {
		flags = append(flags, "error_status")
	}
	return flags
}

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}

func ipInRule(address, rule string) bool {
	ip := net.ParseIP(address)
	if ip == nil || rule == "" {
		return false
	}
	if strings.Contains(rule, "/") {
		_, network, err := net.ParseCIDR(rule)
		if err != nil {
			return false
		}
		return network.Contains(ip)
	}
	other := net.ParseIP(rule)
	return other != nil && other.Equal(ip)
}

func wildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(pattern)
	var builder strings.Builder
	builder.WriteString("^")
	for _, char := range pattern {
		switch char {
		case '*':
			builder.WriteString(".*")
		case '?':
			builder.WriteString(".")
		default:
			builder.WriteString(regexp.QuoteMeta(string(char)))
		}
	}
	builder.WriteString("$")
	compiled, err := regexp.Compile(builder.String())
	if err != nil {
		return false
	}
	return compiled.MatchString(value)
}
