package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const serviceResponseLimit = 1 << 20

// ServiceError is a bounded Connect or OAuth error from an Atol service.
// It never contains request credentials or response bodies.
type ServiceError struct {
	Status int
	Code   string
}

func (e *ServiceError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("atol service returned %d (%s)", e.Status, e.Code)
	}
	return fmt.Sprintf("atol service returned %d", e.Status)
}

func serviceBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("invalid Atol service URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !(u.Hostname() == "localhost" || strings.HasSuffix(u.Hostname(), ".localhost") || (ip != nil && ip.IsLoopback())) {
			return "", errors.New("Atol service URL requires HTTPS")
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func serviceHTTPClient(base *http.Client) *http.Client {
	var client *http.Client
	if base == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	} else {
		copy := *base
		client = &copy
	}
	// A redirect could forward a confidential OAuth secret or a signed machine
	// request to a different origin. Service endpoints never redirect.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

func serviceRequest(ctx context.Context, client *http.Client, endpoint, contentType string, body []byte, output any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create Atol service request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	if contentType == "application/json" {
		req.Header.Set("Connect-Protocol-Version", "1")
	}
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("call Atol service: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, serviceResponseLimit+1))
	if err != nil {
		return fmt.Errorf("read Atol service response: %w", err)
	}
	if len(data) > serviceResponseLimit {
		return errors.New("Atol service response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var serviceErr struct {
			Code  string `json:"code"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &serviceErr)
		code := serviceErr.Code
		if code == "" {
			code = serviceErr.Error
		}
		if !validServiceErrorCode(code) {
			code = ""
		}
		return &ServiceError{Status: response.StatusCode, Code: code}
	}
	if err := json.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode Atol service response: %w", err)
	}
	return nil
}

func validServiceErrorCode(code string) bool {
	if len(code) > 80 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
