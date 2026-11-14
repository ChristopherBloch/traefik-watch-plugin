package traefik_watch_plugin

import "testing"

func TestDangerousURLAndSensitivePath(t *testing.T) {
	rules := []Rule{{Kind: "url", Value: "app.example.test/.env"}}
	if !Dangerous("203.0.113.10", "app.example.test", "/.env", "", 0, rules) {
		t.Fatal("exact url rule should match")
	}
	flagRules := []Rule{{Kind: "flag", Value: "sensitive_path"}}
	if !Dangerous("203.0.113.10", "app.example.test", "/.env", "", 0, flagRules) {
		t.Fatal("sensitive path should match before the upstream status is known")
	}
	if Dangerous("203.0.113.10", "app.example.test", "/", "", 0, []Rule{{Kind: "flag", Value: "error_status"}}) {
		t.Fatal("error status cannot be decided before the response")
	}
	if !Dangerous("203.0.113.10", "app.example.test", "/", "", 500, []Rule{{Kind: "flag", Value: "error_status"}}) {
		t.Fatal("upstream 500 should match error_status")
	}
}

func TestAllowCIDRExemptsNetwork(t *testing.T) {
	allow := []Rule{{Kind: "ip", Value: "203.0.113.0/24"}}
	if !Allowed("203.0.113.10", "app.example.test", "/.env", allow) {
		t.Fatal("allow network should match")
	}
	if Allowed("198.51.100.10", "app.example.test", "/.env", allow) {
		t.Fatal("address outside the network should not match")
	}
}

func TestIPBlockRule(t *testing.T) {
	rules := []Rule{{Kind: "ip", Value: "203.0.113.10"}}
	if !Dangerous("203.0.113.10", "app.example.test", "/", "", 0, rules) {
		t.Fatal("exact ip rule should match")
	}
}
