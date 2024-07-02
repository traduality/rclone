// Package fshttp contains the common http parts of the config, Transport and Client
package fshttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"os"
	"sync"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/lib/structs"
	"golang.org/x/net/publicsuffix"
)

const (
	separatorReq  = ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
	separatorResp = "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
)

var (
	transport    http.RoundTripper
	noTransport  = new(sync.Once)
	cookieJar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	logMutex     sync.Mutex
)

// ResetTransport resets the existing transport, allowing it to take new settings.
// Should only be used for testing.
func ResetTransport() {
	noTransport = new(sync.Once)
}

// NewTransportCustom returns an http.RoundTripper with the correct timeouts.
// The customize function is called if set to give the caller an opportunity to
// customize any defaults in the Transport.
func NewTransportCustom(ctx context.Context, customize func(*http.Transport)) http.RoundTripper {
	ci := fs.GetConfig(ctx)
	// Start with a sensible set of defaults then override.
	// This also means we get new stuff when it gets added to go
	t := new(http.Transport)
	structs.SetDefaults(t, http.DefaultTransport.(*http.Transport))
	t.Proxy = http.ProxyFromEnvironment
	t.MaxIdleConnsPerHost = 2 * (ci.Checkers + ci.Transfers + 1)
	t.MaxIdleConns = 2 * t.MaxIdleConnsPerHost
	t.TLSHandshakeTimeout = ci.ConnectTimeout
	t.ResponseHeaderTimeout = ci.Timeout
	t.DisableKeepAlives = ci.DisableHTTPKeepAlives

	// TLS Config
	t.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: ci.InsecureSkipVerify,
	}

	// Load client certs
	if ci.ClientCert != "" || ci.ClientKey != "" {
		if ci.ClientCert == "" || ci.ClientKey == "" {
			log.Fatalf("Both --client-cert and --client-key must be set")
		}
		cert, err := tls.LoadX509KeyPair(ci.ClientCert, ci.ClientKey)
		if err != nil {
			log.Fatalf("Failed to load --client-cert/--client-key pair: %v", err)
		}
		t.TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certs
	if len(ci.CaCert) != 0 {

		caCertPool := x509.NewCertPool()

		for _, cert := range ci.CaCert {
			caCert, err := os.ReadFile(cert)
			if err != nil {
				log.Fatalf("Failed to read --ca-cert file %q : %v", cert, err)
			}
			ok := caCertPool.AppendCertsFromPEM(caCert)
			if !ok {
				log.Fatalf("Failed to add certificates from --ca-cert file %q", cert)
			}
		}
		t.TLSClientConfig.RootCAs = caCertPool
	}

	t.DisableCompression = ci.NoGzip
	t.DialContext = func(reqCtx context.Context, network, addr string) (net.Conn, error) {
		return NewDialer(ctx).DialContext(reqCtx, network, addr)
	}
	t.IdleConnTimeout = 60 * time.Second
	t.ExpectContinueTimeout = ci.ExpectContinueTimeout

	if ci.Dump&(fs.DumpHeaders|fs.DumpBodies|fs.DumpAuth|fs.DumpRequests|fs.DumpResponses) != 0 {
		fs.Debugf(nil, "You have specified to dump information. Please be noted that the "+
			"Accept-Encoding as shown may not be correct in the request and the response may not show "+
			"Content-Encoding if the go standard libraries auto gzip encoding was in effect. In this case"+
			" the body of the request will be gunzipped before showing it.")
	}

	if ci.DisableHTTP2 {
		t.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}

	// customize the transport if required
	if customize != nil {
		customize(t)
	}

	// Wrap that http.Transport in our own transport
	return newTransport(ci, t)
}

// NewTransport returns an http.RoundTripper with the correct timeouts
func NewTransport(ctx context.Context) http.RoundTripper {
	(*noTransport).Do(func() {
		transport = NewTransportCustom(ctx, nil)
	})
	return transport
}

// NewClient returns an http.Client with the correct timeouts
func NewClient(ctx context.Context) *http.Client {
	ci := fs.GetConfig(ctx)
	client := &http.Client{
		Transport: NewTransport(ctx),
	}
	if ci.Cookie {
		client.Jar = cookieJar
	}
	return client
}

// Transport is our http Transport which wraps an http.Transport
// * Sets the User Agent
// * Does logging
// * Updates metrics
type Transport struct {
	*http.Transport
	dump          fs.DumpFlags
	filterRequest func(req *http.Request)
	userAgent     string
	headers       []*fs.HTTPOption
	metrics       *Metrics
}

// newTransport wraps the http.Transport passed in and logs all
// roundtrips including the body if logBody is set.
func newTransport(ci *fs.ConfigInfo, transport *http.Transport) *Transport {
	return &Transport{
		Transport: transport,
		dump:      ci.Dump,
		userAgent: ci.UserAgent,
		headers:   ci.Headers,
		metrics:   DefaultMetrics,
	}
}

// SetRequestFilter sets a filter to be used on each request
func (t *Transport) SetRequestFilter(f func(req *http.Request)) {
	t.filterRequest = f
}

// A mutex to protect this map
var checkedHostMu sync.RWMutex

// A map of servers we have checked for time
var checkedHost = make(map[string]struct{}, 1)

// Check the server time is the same as ours, once for each server
func checkServerTime(req *http.Request, resp *http.Response) {
	host := req.URL.Host
	if req.Host != "" {
		host = req.Host
	}
	checkedHostMu.RLock()
	_, ok := checkedHost[host]
	checkedHostMu.RUnlock()
	if ok {
		return
	}
	dateString := resp.Header.Get("Date")
	if dateString == "" {
		return
	}
	date, err := http.ParseTime(dateString)
	if err != nil {
		fs.Debugf(nil, "Couldn't parse Date: from server %s: %q: %v", host, dateString, err)
		return
	}
	dt := time.Since(date)
	const window = 5 * 60 * time.Second
	if dt > window || dt < -window {
		fs.Logf(nil, "Time may be set wrong - time from %q is %v different from this computer", host, dt)
	}
	checkedHostMu.Lock()
	checkedHost[host] = struct{}{}
	checkedHostMu.Unlock()
}

// cleanAuth gets rid of one authBuf header within the first 4k
func cleanAuth(buf, authBuf []byte) []byte {
	// Find how much buffer to check
	n := 4096
	if len(buf) < n {
		n = len(buf)
	}
	// See if there is an Authorization: header
	i := bytes.Index(buf[:n], authBuf)
	if i < 0 {
		return buf
	}
	i += len(authBuf)
	// Overwrite the next 4 chars with 'X'
	for j := 0; i < len(buf) && j < 4; j++ {
		if buf[i] == '\n' {
			break
		}
		buf[i] = 'X'
		i++
	}
	// Snip out to the next '\n'
	j := bytes.IndexByte(buf[i:], '\n')
	if j < 0 {
		return buf[:i]
	}
	n = copy(buf[i:], buf[i+j:])
	return buf[:i+n]
}

var authBufs = [][]byte{
	[]byte("Authorization: "),
	[]byte("X-Auth-Token: "),
}

// cleanAuths gets rid of all the possible Auth headers
func cleanAuths(buf []byte) []byte {
	for _, authBuf := range authBufs {
		buf = cleanAuth(buf, authBuf)
	}
	return buf
}

func cleanResponseBody(buf []byte) []byte {
	cleaned := make([]byte, len(buf))
	for i, b := range buf {
		if b >= 32 || b <= 126 {
			cleaned[i] = b
			continue
		}

		cleaned[i] = '?'
	}

	return cleaned
}

func gunzipData(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	var out bytes.Buffer
	_, err = out.ReadFrom(r)
	if err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// RoundTrip implements the RoundTripper interface.
func (t *Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	// Limit transactions per second if required
	accounting.LimitTPS(req.Context())
	// Force user agent
	req.Header.Set("User-Agent", t.userAgent)
	// Set user defined headers
	for _, option := range t.headers {
		req.Header.Set(option.Key, option.Value)
	}
	// Filter the request if required
	if t.filterRequest != nil {
		t.filterRequest(req)
	}

	// Logf request
	if t.dump&(fs.DumpHeaders|fs.DumpBodies|fs.DumpAuth|fs.DumpRequests|fs.DumpResponses) != 0 {
		buf, _ := httputil.DumpRequestOut(req, t.dump&(fs.DumpBodies|fs.DumpRequests) != 0)
		if t.dump&fs.DumpAuth == 0 {
			buf = cleanAuths(buf)
		}
		logMutex.Lock()
		fs.Debugf(nil, "%s", separatorReq)
		fs.Debugf(nil, "%s (req %p)", "HTTP REQUEST", req)
		fs.Debugf(nil, "%s", string(buf))
		fs.Debugf(nil, "%s", separatorReq)
		logMutex.Unlock()
	}
	// Do round trip
	resp, err = t.Transport.RoundTrip(req)

	// Logf response
	if t.dump&(fs.DumpHeaders|fs.DumpBodies|fs.DumpAuth|fs.DumpRequests|fs.DumpResponses) != 0 {
		logMutex.Lock()
		fs.Debugf(nil, "%s", separatorResp)
		fs.Debugf(nil, "%s (req %p)", "HTTP RESPONSE", req)
		if err != nil {
			fs.Debugf(nil, "Error: %v", err)
		} else {
			buf, _ := httputil.DumpResponse(resp, t.dump&(fs.DumpBodies|fs.DumpResponses) != 0)
			if t.dump&fs.DumpAuth == 0 {
				buf = cleanAuths(buf)
			}
			headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
			if headerEnd > 0 {
				header := buf[:headerEnd]

				if t.dump&(fs.DumpHeaders|fs.DumpResponses) != 0 {
					fs.Debugf(nil, "%s", "+++++ Header +++++")
					fs.Debugf(nil, "%s", string(header))
					fs.Debugf(nil, "%s", "----- Header -----")
				}

				if t.dump&fs.DumpBodies != 0 {
					if bytes.Contains(header, []byte("Content-Disposition")) {
						fs.Debugf(nil, "Attachment detected")
					}

					fs.Debugf(nil, "%s", "+++++ Body +++++")
					if len(buf) > headerEnd+4 {
						body := buf[headerEnd+4:]
						if bytes.Contains(header, []byte("Content-Encoding: gzip")) {
							body, _ = gunzipData(body)
						}

						if len(body) > 1024 {
							body = body[:1024]
						}
						fs.Debugf(nil, "%s", string(cleanResponseBody(body)))
					}
					fs.Debugf(nil, "%s", "----- Body -----")
				}
			}
		}
		fs.Debugf(nil, "%s", separatorResp)
		logMutex.Unlock()
	}
	// Update metrics
	t.metrics.onResponse(req, resp)

	if err == nil {
		checkServerTime(req, resp)
	}
	return resp, err
}
