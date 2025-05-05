// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scgi

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Transport facilitates SCGI communication.
type Transport struct {
	// The duration used to set a deadline when connecting to an upstream.
	DialTimeout time.Duration

	// The duration used to set a deadline when reading from the SCGI server.
	ReadTimeout time.Duration

	// The duration used to set a deadline when sending to the SCGI server.
	WriteTimeout time.Duration

	logger *zap.Logger
}

// NewRoundTripper sets up t.
func NewRoundTripper(logger *zap.Logger) *Transport {
	t := &Transport{logger: logger}

	// Set a relatively short default dial timeout.
	// This is helpful to make load-balancer retries more speedy.
	if t.DialTimeout == 0 {
		t.DialTimeout = time.Duration(3 * time.Second)
	}

	return t
}

// RoundTrip implements http.RoundTripper.
func (t Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	env, err := t.buildEnv(r)
	if err != nil {
		return nil, fmt.Errorf("building environment: %v", err)
	}

	ctx := r.Context()

	// extract dial information from request
	network, address := "tcp", r.URL.Host
	if dialInfo, ok := getDialInfo(r.URL); ok {
		network = dialInfo.network
		address = dialInfo.address
	}

	logCreds := false
	loggableReq := loggableHTTPRequest{
		Request:              r,
		shouldLogCredentials: logCreds,
	}
	loggableEnv := loggableEnv{vars: env, logCredentials: logCreds}

	logger := t.logger.With(
		zap.Object("request", loggableReq),
		zap.Object("env", loggableEnv),
	)
	if c := t.logger.Check(zapcore.DebugLevel, "roundtrip"); c != nil {
		c.Write(
			zap.String("dial", address),
			zap.Object("env", loggableEnv),
			zap.Object("request", loggableReq),
		)
	}

	// connect to the backend
	dialer := net.Dialer{Timeout: time.Duration(t.DialTimeout)}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dialing backend: %v", err)
	}
	defer func() {
		// conn will be closed with the response body unless there's an error
		if err != nil {
			conn.Close()
		}
	}()

	// create the client that will facilitate the protocol
	client := client{
		rwc:    conn,
		logger: logger,
	}

	// read/write timeouts
	if err := client.SetReadTimeout(t.ReadTimeout); err != nil {
		return nil, fmt.Errorf("setting read timeout: %v", err)
	}
	if err := client.SetWriteTimeout(t.WriteTimeout); err != nil {
		return nil, fmt.Errorf("setting write timeout: %v", err)
	}

	contentLength := r.ContentLength
	if contentLength == 0 {
		contentLength, _ = strconv.ParseInt(r.Header.Get("Content-Length"), 10, 64)
	}

	var resp *http.Response
	switch r.Method {
	case http.MethodHead:
		resp, err = client.Head(env)
	case http.MethodGet:
		resp, err = client.Get(env, r.Body, contentLength)
	case http.MethodOptions:
		resp, err = client.Options(env)
	default:
		resp, err = client.Post(env, r.Method, r.Header.Get("Content-Type"), r.Body, contentLength)
	}
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// buildEnv returns a set of CGI environment variables for the request.
func (t Transport) buildEnv(r *http.Request) (envVars, error) {
	var env envVars

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
	env = envVars{
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
		"DOCUMENT_ROOT":   "", // Not used
		"DOCUMENT_URI":    docURI,
		"HTTP_HOST":       r.Host, // added here, since not always part of headers
		"REQUEST_URI":     reqURL.RequestURI(),
		"SCGI":            "1", // Required
		"SCRIPT_FILENAME": "",  // Not used
		"SCRIPT_NAME":     scriptName,
	}

	// compliance with the CGI specification requires that
	// the SERVER_PORT variable MUST be set to the TCP/IP port number on which this request is received from the client
	// even if the port is the default port for the scheme and could otherwise be omitted from a URI.
	// https://tools.ietf.org/html/rfc3875#section-4.1.15
	if reqPort != "" {
		env["SERVER_PORT"] = reqPort
	} else if requestScheme == "http" {
		env["SERVER_PORT"] = "80"
	} else if requestScheme == "https" {
		env["SERVER_PORT"] = "443"
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

// envVars is a simple type for environment variables.
type envVars map[string]string

// loggableEnv is a simple type to allow for speeding up zap log encoding.
type loggableEnv struct {
	vars           envVars
	logCredentials bool
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (env loggableEnv) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	for k, v := range env.vars {
		if !env.logCredentials {
			switch strings.ToLower(k) {
			case "http_cookie", "http_set_cookie", "http_authorization", "http_proxy_authorization":
				v = ""
			}
		}
		enc.AddString(k, v)
	}
	return nil
}

// loggableHTTPRequest makes an HTTP request loggable with zap.Object().
type loggableHTTPRequest struct {
	*http.Request

	shouldLogCredentials bool
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (r loggableHTTPRequest) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	ip, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
		port = ""
	}

	enc.AddString("remote_ip", ip)
	enc.AddString("remote_port", port)
	if varMap, ok := r.Context().Value("vars").(map[string]any); ok {
		enc.AddString("client_ip", varMap["client_ip"].(string))
	}
	enc.AddString("proto", r.Proto)
	enc.AddString("method", r.Method)
	enc.AddString("host", r.Host)
	enc.AddString("uri", r.RequestURI)
	enc.AddObject("headers", loggableHTTPHeader{
		Header:               r.Header,
		ShouldLogCredentials: r.shouldLogCredentials,
	})
	if r.TransferEncoding != nil {
		enc.AddArray("transfer_encoding", loggableStringArray(r.TransferEncoding))
	}
	if r.TLS != nil {
		enc.AddObject("tls", loggableTLSConnState(*r.TLS))
	}
	return nil
}

// loggableHTTPHeader makes an HTTP header loggable with zap.Object().
// Headers with potentially sensitive information (Cookie, Set-Cookie,
// Authorization, and Proxy-Authorization) are logged with empty values.
type loggableHTTPHeader struct {
	http.Header

	ShouldLogCredentials bool
}

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (h loggableHTTPHeader) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if h.Header == nil {
		return nil
	}
	for key, val := range h.Header {
		if !h.ShouldLogCredentials {
			switch strings.ToLower(key) {
			case "cookie", "set-cookie", "authorization", "proxy-authorization":
				val = []string{"REDACTED"}
			}
		}
		enc.AddArray(key, loggableStringArray(val))
	}
	return nil
}

// loggableStringArray makes a slice of strings marshalable for logging.
type loggableStringArray []string

// MarshalLogArray satisfies the zapcore.ArrayMarshaler interface.
func (sa loggableStringArray) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if sa == nil {
		return nil
	}
	for _, s := range sa {
		enc.AppendString(s)
	}
	return nil
}

// loggableTLSConnState makes a TLS connection state loggable with zap.Object().
type loggableTLSConnState tls.ConnectionState

// MarshalLogObject satisfies the zapcore.ObjectMarshaler interface.
func (t loggableTLSConnState) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddBool("resumed", t.DidResume)
	enc.AddUint16("version", t.Version)
	enc.AddUint16("cipher_suite", t.CipherSuite)
	enc.AddString("proto", t.NegotiatedProtocol)
	enc.AddString("server_name", t.ServerName)
	if len(t.PeerCertificates) > 0 {
		enc.AddString("client_common_name", t.PeerCertificates[0].Subject.CommonName)
		enc.AddString("client_serial", t.PeerCertificates[0].SerialNumber.String())
	}
	return nil
}

// DialInfo is a simple type containing connection info.
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
var (
	_ zapcore.ObjectMarshaler = (*loggableEnv)(nil)
	_ zapcore.ObjectMarshaler = (*loggableHTTPRequest)(nil)
	_ zapcore.ObjectMarshaler = (*loggableHTTPHeader)(nil)
	_ zapcore.ArrayMarshaler  = (*loggableStringArray)(nil)
	_ zapcore.ObjectMarshaler = (*loggableTLSConnState)(nil)

	_ http.RoundTripper = (*Transport)(nil)
)
