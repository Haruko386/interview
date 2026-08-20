package engine

import (
	"encoding/json"
	"os"
	"testing"
)

func TestFingerprintSamples(t *testing.T) {
	e, err := LoadFromFile("../../rules/fingerprints.json")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	raw, err := os.ReadFile("../../data/input.json")
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}

	var samples []Input
	if err := json.Unmarshal(raw, &samples); err != nil {
		t.Fatalf("parse samples: %v", err)
	}
	if len(samples) != 23 {
		t.Fatalf("sample count = %d, want 23", len(samples))
	}

	want := map[string]Result{
		"10.0.0.1":  {Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		"10.0.0.2":  {Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95},
		"10.0.0.3":  {Protocol: "SSH", Product: "OpenSSH", Version: "4.3", Confidence: 0.95},
		"10.0.0.4":  {Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.94},
		"10.0.0.5":  {Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.94},
		"10.0.0.6":  {Protocol: "HTTP", Product: "nginx", Version: "1.25.3", Confidence: 0.94},
		"10.0.0.7":  {Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.94},
		"10.0.0.8":  {Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.94},
		"10.0.0.9":  {Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.93},
		"10.0.0.10": {Protocol: "HTTP", Product: "Microsoft-IIS", Version: "10.0", Confidence: 0.93},
		"10.0.0.11": {Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.95},
		"10.0.0.12": {Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", Confidence: 0.95},
		"10.0.0.13": {Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		"10.0.0.14": {Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		"10.0.0.15": {Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		"10.0.0.16": {Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		"10.0.0.17": {Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5", Confidence: 0.9},
		"10.0.0.18": {Protocol: "FTP", Product: "Pure-FTPd", Confidence: 0.7},
		"10.0.0.19": {Protocol: "TLS", Product: "TLS", Version: "1.0", Confidence: 0.88},
		"10.0.0.20": {Protocol: "TLS", Product: "TLS", Version: "1.2", Confidence: 0.88},
		"10.0.0.21": {Protocol: "unknown"},
		"10.0.0.22": {Protocol: "unknown"},
		"10.0.0.23": {Protocol: "unknown"},
	}

	for _, sample := range samples {
		got := e.Fingerprint(sample)
		expected, ok := want[sample.IP]
		if !ok {
			t.Fatalf("missing expectation for %s", sample.IP)
		}

		if got.Protocol != expected.Protocol ||
			got.Product != expected.Product ||
			got.Version != expected.Version ||
			got.OSHint != expected.OSHint ||
			got.Confidence != expected.Confidence {
			t.Fatalf("%s got %+v, want %+v", sample.IP, got, expected)
		}
	}
}
