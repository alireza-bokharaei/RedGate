package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localProbeRequest(t *testing.T, serverURL string) HTTPProbeRequest {
	t.Helper()
	u, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return HTTPProbeRequest{Target: u.Hostname(), PinnedIPs: []string{u.Hostname()}, Scheme: u.Scheme,
		Port: port, Path: "/", Method: "HEAD", TimeoutSec: 2}
}

func TestHTTPProbePinsDialButPreservesHost(t *testing.T) {
	var receivedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("collector sent credentials")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Set-Cookie", "session=must-not-be-recorded")
		w.Header().Set("X-Private-Token", "must-not-be-recorded")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	req := localProbeRequest(t, server.URL)
	req.Target = "does-not-resolve.invalid" // Must succeed WITHOUT resolving this host.
	result, err := NewHTTPProbe().Capture(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if receivedHost != net.JoinHostPort(req.Target, strconv.Itoa(req.Port)) || result.ConnectedIP != "127.0.0.1" {
		t.Fatalf("lost the logical host or IP pin: host=%q result=%+v", receivedHost, result)
	}
	if result.ResponseHeaders["x-content-type-options"] != "nosniff" {
		t.Fatal("security header missing")
	}
	for _, forbidden := range []string{"set-cookie", "x-private-token"} {
		if _, exists := result.ResponseHeaders[forbidden]; exists {
			t.Fatalf("sensitive header was recorded: %s", forbidden)
		}
	}
	if result.BodyPreview != "" || result.BodyOmitted == "" {
		t.Fatal("HEAD unexpectedly collected a response body")
	}
}

func TestHTTPProbeDoesNotFollowRedirectsOrEnvironmentProxy(t *testing.T) {
	var destinationCalls, proxyCalls atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destinationCalls.Add(1)
	}))
	defer destination.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalls.Add(1)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer source.Close()
	result, err := NewHTTPProbe().Capture(context.Background(), localProbeRequest(t, source.URL))
	if err != nil || result.StatusCode != http.StatusFound {
		t.Fatalf("redirect should be a recorded observation: %+v %v", result, err)
	}
	if destinationCalls.Load() != 0 || proxyCalls.Load() != 0 {
		t.Fatal("collector followed a redirect or inherited a proxy")
	}
}

func TestHTTPProbeBodyIsBoundedAndBinaryIsOmitted(t *testing.T) {
	for _, test := range []struct{ contentType, encoding string }{
		{"application/json", ""}, {"image/png", ""}, {"application/json", "gzip"},
	} {
		t.Run(test.contentType+test.encoding, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				if test.encoding != "" {
					w.Header().Set("Content-Encoding", test.encoding)
				}
				_, _ = w.Write([]byte(strings.Repeat("a", 5000)))
			}))
			defer server.Close()
			req := localProbeRequest(t, server.URL)
			req.Method, req.MaxBodyBytes = "GET", 1024
			result, err := NewHTTPProbe().Capture(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			if test.contentType == "application/json" && test.encoding == "" {
				if len(result.BodyPreview) != 1024 || !result.BodyTruncated {
					t.Fatal("text preview was not truncated at its byte limit")
				}
			} else if result.BodyPreview != "" || result.BodyOmitted == "" {
				t.Fatal("binary or compressed content was collected")
			}
		})
	}
}

func TestHTTPProbeRefusesUnsafeContracts(t *testing.T) {
	valid := HTTPProbeRequest{Target: "lab.example", PinnedIPs: []string{"192.0.2.1"}, Scheme: "https", Port: 443, Path: "/", Method: "HEAD", TimeoutSec: 2}
	tests := map[string]func(*HTTPProbeRequest){
		"no pin":            func(r *HTTPProbeRequest) { r.PinnedIPs = nil },
		"metadata":          func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"169.254.169.254"} },
		"mapped metadata":   func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"::ffff:169.254.169.254"} },
		"other metadata":    func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"100.100.100.200"} },
		"link local":        func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"fe80::1"} },
		"unspecified":       func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"0.0.0.0"} },
		"multicast":         func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"224.0.0.1"} },
		"domain pin":        func(r *HTTPProbeRequest) { r.PinnedIPs = []string{"other.example"} },
		"literal mismatch":  func(r *HTTPProbeRequest) { r.Target = "192.0.2.9" },
		"credentials":       func(r *HTTPProbeRequest) { r.Target = "user:pass@lab.example" },
		"port in target":    func(r *HTTPProbeRequest) { r.Target = "lab.example:443" },
		"post":              func(r *HTTPProbeRequest) { r.Method = "POST" },
		"file scheme":       func(r *HTTPProbeRequest) { r.Scheme = "file" },
		"absolute URI":      func(r *HTTPProbeRequest) { r.Path = "https://other.example/" },
		"protocol relative": func(r *HTTPProbeRequest) { r.Path = "//other.example/" },
		"encoded control":   func(r *HTTPProbeRequest) { r.Path = "/%0d%0aHost:evil" },
		"query":             func(r *HTTPProbeRequest) { r.Path = "/?token=secret" },
		"fragment":          func(r *HTTPProbeRequest) { r.Path = "/#secret" },
		"unbounded body":    func(r *HTTPProbeRequest) { r.MaxBodyBytes = maxEvidenceBody + 1 },
		"unbounded timeout": func(r *HTTPProbeRequest) { r.TimeoutSec = 300 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			req := valid
			mutate(&req)
			if _, _, err := validateHTTPProbe(req); err == nil {
				t.Fatal("unsafe request accepted")
			}
		})
	}
}

func TestHTTPProbeTLSVerificationAndCancellation(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer tlsServer.Close()
	if _, err := NewHTTPProbe().Capture(context.Background(), localProbeRequest(t, tlsServer.URL)); err == nil {
		t.Fatal("collector accepted an untrusted TLS certificate")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := NewHTTPProbe().Capture(ctx, localProbeRequest(t, server.URL)); err == nil {
		t.Fatal("collector ignored cancellation")
	}
}

func TestHTTPProbeHandlerRequiresTokenAndStrictJSON(t *testing.T) {
	token := strings.Repeat("x", 32)
	handler := NewHTTPProbe().Handler(token)
	for _, test := range []struct {
		method, body, auth string
		status             int
	}{
		{"POST", `{}`, "", 401}, {"GET", `{}`, token, 405},
		{"POST", `{"arbitrary_header":"bad"}`, token, 400},
		{"POST", `{} {}`, token, 400}, {"POST", `{}`, token, 422},
	} {
		req := httptest.NewRequest(test.method, "/http-evidence", bytes.NewBufferString(test.body))
		req.Header.Set("X-Internal-Service-Token", test.auth)
		response := httptest.NewRecorder()
		handler(response, req)
		if response.Code != test.status {
			t.Fatalf("got %d, expected %d: %s", response.Code, test.status, response.Body.String())
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	body, _ := json.Marshal(localProbeRequest(t, server.URL))
	req := httptest.NewRequest("POST", "/http-evidence", bytes.NewReader(body))
	req.Header.Set("X-Internal-Service-Token", token)
	response := httptest.NewRecorder()
	handler(response, req)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
}
