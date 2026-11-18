package main

// A deliberately narrow, anonymous HTTP evidence collector. This is NOT a
// general-purpose forward proxy: the gateway supplies a fresh DNS pin, no caller
// headers or credentials are accepted, redirects are never followed, and the
// transport cannot resolve or dial any destination other than that pin.

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const maxEvidenceBody = 8192

// HTTPProbeRequest is issued only by the policy gateway after an allowlist,
// engagement-window, tool-policy and quota check. Pins are mandatory.
type HTTPProbeRequest struct {
	Target       string   `json:"target"`
	PinnedIPs    []string `json:"pinned_ips"`
	Scheme       string   `json:"scheme"`
	Port         int      `json:"port"`
	Path         string   `json:"path"`
	Method       string   `json:"method"`
	TimeoutSec   int      `json:"timeout_sec"`
	MaxBodyBytes int      `json:"max_body_bytes"`
}

type HTTPProbeResponse struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	ConnectedIP     string            `json:"connected_ip"`
	StatusCode      int               `json:"status_code"`
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	BodyPreview     string            `json:"body_preview"`
	BodyTruncated   bool              `json:"body_truncated"`
	BodyOmitted     string            `json:"body_omitted,omitempty"`
	CapturedAt      string            `json:"captured_at"`
	DurationMs      int64             `json:"duration_ms"`
}

// Only a small response-header allowlist crosses the service boundary. In
// particular Set-Cookie, WWW-Authenticate and arbitrary application headers do
// not become evidence. The gateway also redacts secret patterns in these fields.
var evidenceHeaders = []string{
	"Content-Type", "Content-Length", "Content-Encoding", "Cache-Control", "Date",
	"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
	"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy", "Location",
}

type HTTPProbe struct {
	sem  chan struct{}
	mu   sync.Mutex
	next map[string]time.Time
}

func NewHTTPProbe() *HTTPProbe {
	return &HTTPProbe{sem: make(chan struct{}, 4), next: make(map[string]time.Time)}
}

func validateHTTPProbe(req HTTPProbeRequest) (string, string, error) {
	if req.Scheme != "http" && req.Scheme != "https" {
		return "", "", errors.New("only http and https are supported")
	}
	if req.Method != http.MethodHead && req.Method != http.MethodGet {
		return "", "", errors.New("only anonymous HEAD and GET are supported")
	}
	if req.Port < 1 || req.Port > 65535 || req.TimeoutSec < 1 || req.TimeoutSec > 15 {
		return "", "", errors.New("port or timeout is outside the hard limits")
	}
	if req.MaxBodyBytes < 0 || req.MaxBodyBytes > maxEvidenceBody {
		return "", "", errors.New("body preview exceeds the hard limit")
	}
	if req.Target == "" || len(req.Target) > 253 || strings.ContainsAny(req.Target, "/\\@?#%\r\n\t ") {
		return "", "", errors.New("target must be a plain hostname or IP literal")
	}
	if net.ParseIP(req.Target) == nil {
		for _, label := range strings.Split(req.Target, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", "", errors.New("invalid hostname")
			}
			for _, c := range label {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
					return "", "", errors.New("invalid hostname")
				}
			}
		}
	}
	path, err := url.ParseRequestURI(req.Path)
	decodedPath, decodeErr := url.PathUnescape(req.Path)
	if err != nil || decodeErr != nil || path.IsAbs() || path.Host != "" || path.RawQuery != "" ||
		strings.ContainsAny(req.Path, "?#\\") || !strings.HasPrefix(req.Path, "/") ||
		strings.HasPrefix(decodedPath, "//") || len(req.Path) > 128 ||
		strings.ContainsAny(decodedPath, "\\") || strings.IndexFunc(decodedPath, unicode.IsControl) >= 0 {
		return "", "", errors.New("path must be a bounded origin-relative path without query or fragment")
	}
	if len(req.PinnedIPs) < 1 || len(req.PinnedIPs) > 16 {
		return "", "", errors.New("one to sixteen gateway-resolved IP pins are required")
	}
	for _, raw := range req.PinnedIPs {
		ip := net.ParseIP(raw)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return "", "", errors.New("invalid or prohibited destination pin")
		}
		if _, err := BuildEgressPolicy([]string{raw}, false); err != nil {
			return "", "", err
		}
	}
	// An IP-literal target cannot be redirected to a different IP by its pin.
	if targetIP := net.ParseIP(req.Target); targetIP != nil {
		for _, pin := range req.PinnedIPs {
			if !targetIP.Equal(net.ParseIP(pin)) {
				return "", "", errors.New("IP target and destination pin differ")
			}
		}
	}
	host := net.JoinHostPort(req.Target, strconv.Itoa(req.Port))
	u := &url.URL{Scheme: req.Scheme, Host: host, Path: path.Path, RawPath: path.RawPath}
	return u.String(), net.ParseIP(req.PinnedIPs[0]).String(), nil
}

// pace is a process-wide two-requests/second ceiling for each target host/port.
// It is independent of LLM prompts and includes requests made by all missions.
func (p *HTTPProbe) pace(ctx context.Context, host string) error {
	p.mu.Lock()
	now := time.Now()
	start := p.next[host]
	if start.Before(now) {
		start = now
	}
	if len(p.next) >= 512 {
		// Drop only expired entries; never evict an active host's reservation.
		for k, next := range p.next {
			if next.Before(now) {
				delete(p.next, k)
			}
		}
		if _, exists := p.next[host]; !exists && len(p.next) >= 512 {
			p.mu.Unlock()
			return errors.New("target pacing capacity reached")
		}
	}
	p.next[host] = start.Add(500 * time.Millisecond)
	p.mu.Unlock()
	timer := time.NewTimer(time.Until(start))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *HTTPProbe) Capture(ctx context.Context, req HTTPProbeRequest) (HTTPProbeResponse, error) {
	var result HTTPProbeResponse
	u, ip, err := validateHTTPProbe(req)
	if err != nil {
		return result, err
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSec)*time.Second)
	defer cancel()
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	if err := p.pace(ctx, net.JoinHostPort(req.Target, strconv.Itoa(req.Port))); err != nil {
		return result, err
	}
	dialer := &net.Dialer{Timeout: time.Duration(req.TimeoutSec) * time.Second}
	transport := &http.Transport{
		Proxy:                  nil, // Never inherit HTTP(S)_PROXY / ALL_PROXY.
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 32768,
		ResponseHeaderTimeout:  time.Duration(req.TimeoutSec) * time.Second,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != net.JoinHostPort(req.Target, strconv.Itoa(req.Port)) {
				return nil, errors.New("transport attempted an unapproved destination")
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(req.Port)))
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpReq, err := http.NewRequestWithContext(ctx, req.Method, u, nil)
	if err != nil {
		return result, err
	}
	httpReq.Header.Set("User-Agent", "RedGate/2.1 (Authorized Read-Only Assessment)")
	httpReq.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(httpReq)
	if err != nil {
		return result, fmt.Errorf("HTTP evidence request failed: %w", err)
	}
	defer resp.Body.Close()

	result = HTTPProbeResponse{
		URL: u, Method: req.Method, ConnectedIP: ip, StatusCode: resp.StatusCode,
		RequestHeaders:  map[string]string{"user-agent": httpReq.Header.Get("User-Agent"), "accept-encoding": "identity"},
		ResponseHeaders: make(map[string]string), CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	for _, name := range evidenceHeaders {
		if value := resp.Header.Get(name); value != "" {
			result.ResponseHeaders[strings.ToLower(name)] = value
		}
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	switch {
	case req.MaxBodyBytes == 0 || req.Method == http.MethodHead:
		result.BodyOmitted = "body capture not requested"
	case encoding != "" && encoding != "identity":
		result.BodyOmitted = "encoded response body not collected"
	case !(strings.HasPrefix(contentType, "text/") || strings.Contains(contentType, "json") || strings.Contains(contentType, "xml")):
		result.BodyOmitted = "non-text response body not collected"
	default:
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, int64(req.MaxBodyBytes)+1))
		if readErr != nil {
			return HTTPProbeResponse{}, fmt.Errorf("body preview incomplete: %w", readErr)
		}
		result.BodyTruncated = len(body) > req.MaxBodyBytes
		if result.BodyTruncated {
			body = body[:req.MaxBodyBytes]
		}
		result.BodyPreview = string(body)
	}
	result.DurationMs = time.Since(start).Milliseconds()
	return result, nil
}

func (p *HTTPProbe) Handler(internalToken string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Internal-Service-Token")), []byte(internalToken)) != 1 || len(internalToken) < 16 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized internal caller"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var req HTTPProbeRequest
		if err := dec.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid evidence request"})
			return
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only one JSON object is accepted"})
			return
		}
		if _, _, err := validateHTTPProbe(req); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		result, err := p.Capture(r.Context(), req)
		if err != nil {
			// Do not log/return target response content or credentials on errors.
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "HTTP evidence collection failed (timeout, connection, or TLS validation)"})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}
