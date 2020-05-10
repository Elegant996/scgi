// Package scgi provides a SCGI transport.
//
// SCGI queries can be sent by specifying the host and port over TCP
// or through Unix domain sockets.
//
// The URLs look like this:
//
//     http://host[:port]/path (TCP)
//     http:///tmp/domain.sock (Unix domain socket)
//
// where the absolute path is provided for Unix domain sockets.
package scgi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Transport facilitates SCGI communication.
type Transport struct {
	// The duration used to set a deadline when connecting to an upstream.
	DialTimeout time.Duration

	// The duration used to set a deadline when reading from the SCGI server.
	ReadTimeout time.Duration

	// The duration used to set a deadline when sending to the SCGI server.
	WriteTimeout time.Duration
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {	
	env, err := t.buildEnv(req)
	if err != nil {
		return nil, fmt.Errorf("building environment: %v", err)
	}

	// TODO: doesn't dialer have a Timeout field?
	ctx := req.Context()
	if t.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(t.DialTimeout))
		defer cancel()
	}

	// extract dial information from request (should have been embedded by the reverse proxy)	
	network, address := "tcp", req.URL.Host
	if dialInfo, ok := getDialInfo(req.URL); ok {
		network = dialInfo.network
		address = dialInfo.address
	}

	scgiBackend, err := DialContext(ctx, network, address)
	if err != nil {
		// TODO: wrap in a special error type if the dial failed, so retries can happen if enabled
		return nil, fmt.Errorf("dialing backend: %v", err)
	}
	// scgiBackend gets closed when response body is closed (see clientCloser)

	// read/write timeouts
	if err := scgiBackend.SetReadTimeout(t.ReadTimeout); err != nil {
		return nil, fmt.Errorf("setting read timeout: %v", err)
	}
	if err := scgiBackend.SetWriteTimeout(t.WriteTimeout); err != nil {
		return nil, fmt.Errorf("setting write timeout: %v", err)
	}

	contentLength := req.ContentLength
	if contentLength == 0 {
		contentLength, _ = strconv.ParseInt(req.Header.Get("Content-Length"), 10, 64)
	}

	var resp *http.Response
	switch req.Method {
	case http.MethodHead:
		resp, err = scgiBackend.Head(env)
	case http.MethodGet:
		resp, err = scgiBackend.Get(env, req.Body, contentLength)
	default:
		resp, err = scgiBackend.Post(env, req.Method, req.Body, contentLength)
	}

	return resp, err
}

// buildEnv returns a set of CGI environment variables for the request.
func (t Transport) buildEnv(req *http.Request) (map[string]string, error) {
	var env map[string]string

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.LastIndex(req.RemoteAddr, ":"); idx > -1 {
		ip = req.RemoteAddr[:idx]
		port = req.RemoteAddr[idx+1:]
	} else {
		ip = req.RemoteAddr
	}

	// Remove [] from IPv6 addresses
	ip = strings.Replace(ip, "[", "", 1)
	ip = strings.Replace(ip, "]", "", 1)

	reqURL := req.URL

	requestScheme := "http"

	reqHost, reqPort, err := net.SplitHostPort(req.Host)
	if err != nil {
		// whatever, just assume there was no port
		reqHost = req.Host
	}

	// Some variables are unused but cleared explicitly to prevent
	// the parent environment from interfering.
	env = map[string]string{
		// Variables defined in CGI 1.1 spec
		"AUTH_TYPE":         "", // Not used
		"CONTENT_LENGTH":    req.Header.Get("Content-Length"),
		"CONTENT_TYPE":      req.Header.Get("Content-Type"),
		"GATEWAY_INTERFACE": "CGI/1.1",
		"PATH_INFO":         "", // Not used
		"QUERY_STRING":      req.URL.RawQuery,
		"REMOTE_ADDR":       ip,
		"REMOTE_HOST":       ip, // For speed, remote host lookups disabled
		"REMOTE_PORT":       port,
		"REMOTE_IDENT":      "", // Not used
		"REMOTE_USER":       "", // TODO: once there are authentication handlers, populate this
		"REQUEST_METHOD":    req.Method,
		"REQUEST_SCHEME":    requestScheme,
		"SERVER_NAME":       reqHost,
		"SERVER_PORT":       reqPort,
		"SERVER_PROTOCOL":   req.Proto,

		// Other variables
		"HTTP_HOST":       req.Host, // added here, since not always part of headers
		"REQUEST_URI":     reqURL.RequestURI(),
		"SCGI":            "1", // Required
	}

	// Add all HTTP headers to env variables
	for field, val := range req.Header {
		header := strings.ToUpper(field)
		header = headerNameReplacer.Replace(header)
		env["HTTP_"+header] = strings.Join(val, ", ")
	}
	return env, nil
}

type DialInfo struct {
	network string
	address string
}

func getDialInfo(u *url.URL) (*DialInfo, bool) {
	if u.Host == "" {
		return &DialInfo{"unix", u.Path}, true
	}
	
	return nil, false
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")

// Interface guards
var _ http.RoundTripper = (*Transport)(nil)
