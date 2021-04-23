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
	"crypto/tls"
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
	dialTimeout time.Duration

	// The duration used to set a deadline when reading from the SCGI server.
	readTimeout time.Duration

	// The duration used to set a deadline when sending to the SCGI server.
	writeTimeout time.Duration
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {	
	env, err := t.buildEnv(r)
	if err != nil {
		return nil, fmt.Errorf("building environment: %v", err)
	}

	// TODO: doesn't dialer have a Timeout field?
	ctx := r.Context()
	if t.dialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(t.dialTimeout))
		defer cancel()
	}

	// extract dial information from request (should have been embedded by the reverse proxy)	
	network, address := "tcp", r.URL.Host
	if dialInfo, ok := getDialInfo(r.URL); ok {
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
	if err := scgiBackend.SetReadTimeout(t.readTimeout); err != nil {
		return nil, fmt.Errorf("setting read timeout: %v", err)
	}
	if err := scgiBackend.SetWriteTimeout(t.writeTimeout); err != nil {
		return nil, fmt.Errorf("setting write timeout: %v", err)
	}

	contentLength := r.ContentLength
	if contentLength == 0 {
		contentLength, _ = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	}

	var resp *http.Response
	switch r.Method {
	case http.MethodHead:
		resp, err = scgiBackend.Head(env)
	case http.MethodGet:
		resp, err = scgiBackend.Get(env, r.Body, contentLength)
	case http.MethodOptions:
		resp, err = scgiBackend.Options(env)
	default:
		resp, err = scgiBackend.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
	}

	return resp, err
}

// buildEnv returns a set of CGI environment variables for the request.
func (t Transport) buildEnv(r *http.Request) (map[string]string, error) {
	var env map[string]string

	// Separate remote IP and port; more lenient than net.SplitHostPort
	var ip, port string
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx > -1 {
		ip = r.RemoteAddr[:idx]
		port = r.RemoteAddr[idx+1:]
	} else {
		ip = r.RemoteAddr
	}

	// Remove [] from IPv6 addresses
	ip = strings.Replace(ip, "[", "", 1)
	ip = strings.Replace(ip, "]", "", 1)
	
	fpath := r.URL.Path
	scriptName := fpath

	docURI := fpath

	// Ensure the SCRIPT_NAME has a leading slash for compliance with RFC3875
	// Info: https://tools.ietf.org/html/rfc3875#section-4.1.13
	if scriptName != "" && !strings.HasPrefix(scriptName, "/") {
		scriptName = "/" + scriptName
	}

	reqURL := r.URL

	requestScheme := "http"
	if r.TLS != nil {
		requestScheme = "https"
	}

	reqHost, reqPort, err := net.SplitHostPort(r.Host)
	if err != nil {
		// whatever, just assume there was no port
		reqHost = r.Host
	}

	// Some variables are unused but cleared explicitly to prevent
	// the parent environment from interfering.
	env = map[string]string{
		// Variables defined in CGI 1.1 spec
		"AUTH_TYPE":         "", // Not used
		"CONTENT_LENGTH":    r.Header.Get("Content-Length"),
		"CONTENT_TYPE":      r.Header.Get("Content-Type"),
		"GATEWAY_INTERFACE": "CGI/1.1",
		"PATH_INFO":         "", // Not used
		"QUERY_STRING":      r.URL.RawQuery,
		"REMOTE_ADDR":       ip,
		"REMOTE_HOST":       ip, // For speed, remote host lookups disabled
		"REMOTE_PORT":       port,
		"REMOTE_IDENT":      "", // Not used
		"REMOTE_USER":       "", // Not used
		"REQUEST_METHOD":    r.Method,
		"REQUEST_SCHEME":    requestScheme,
		"SERVER_NAME":       reqHost,
		"SERVER_PROTOCOL":   r.Proto,

		// Other variables
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       r.Host, // added here, since not always part of headers
		"REQUEST_URI":     reqURL.RequestURI(),
		"SCRIPT_NAME":     scriptName,
		"SCGI":            "1", // Required
	}

	// compliance with the CGI specification requires that
	// SERVER_PORT should only exist if it's a valid numeric value.
	// Info: https://www.ietf.org/rfc/rfc3875 Page 18
	if reqPort != "" {
		env["SERVER_PORT"] = reqPort
	}

	// Some web apps rely on knowing HTTPS or not
	if r.TLS != nil {
		env["HTTPS"] = "on"
		// and pass the protocol details in a manner compatible with apache's mod_ssl
		// (which is why these have a SSL_ prefix and not TLS_).
		v, ok := tlsProtocolStrings[r.TLS.Version]
		if ok {
			env["SSL_PROTOCOL"] = v
		}
		// and pass the cipher suite in a manner compatible with apache's mod_ssl
		env["SSL_CIPHER"] = tls.CipherSuiteName(r.TLS.CipherSuite)
	}

	// Add all HTTP headers to env variables
	for field, val := range r.Header {
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

// Map of supported protocols to Apache ssl_mod format
var tlsProtocolStrings = map[uint16]string{
	tls.VersionTLS10: "TLSv1",
	tls.VersionTLS11: "TLSv1.1",
	tls.VersionTLS12: "TLSv1.2",
	tls.VersionTLS13: "TLSv1.3",
}

var headerNameReplacer = strings.NewReplacer(" ", "_", "-", "_")

// Interface guards
var _ http.RoundTripper = (*Transport)(nil)
