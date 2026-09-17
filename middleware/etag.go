// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

// etagResponseWriter buffers all writes so that conditional-request logic can
// inspect the full response (status + body) before committing it to the wire.
// Methods not overridden here are delegated to the embedded gin.ResponseWriter.
type etagResponseWriter struct {
	gin.ResponseWriter
	// body accumulates what the handler writes via Write / WriteString.
	body *bytes.Buffer
	// bufHeader accumulates Set-Header calls from the handler.
	bufHeader http.Header
	// bufStatus is the status code the handler passed to WriteHeader.
	bufStatus int
	// committed is set to true once flush has sent bytes to the network.
	committed bool
}

func newETagResponseWriter(inner gin.ResponseWriter) *etagResponseWriter {
	return &etagResponseWriter{
		ResponseWriter: inner,
		body:           &bytes.Buffer{},
		bufHeader:      inner.Header().Clone(), // start with whatever headers already exist
		bufStatus:      http.StatusOK,
	}
}

// Header returns our buffered header map so handlers write into the buffer.
func (w *etagResponseWriter) Header() http.Header { return w.bufHeader }

// WriteHeader records the status without writing it to the network.
func (w *etagResponseWriter) WriteHeader(code int) {
	if code > 0 && !w.committed {
		w.bufStatus = code
	}
}

// Write buffers body bytes.
func (w *etagResponseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

// WriteString buffers string body content.
func (w *etagResponseWriter) WriteString(s string) (int, error) {
	return w.body.WriteString(s)
}

// Written returns false until we commit; this keeps Gin's internal guards happy.
func (w *etagResponseWriter) Written() bool { return w.committed }

// WriteHeaderNow is intentionally a no-op — we flush explicitly.
func (w *etagResponseWriter) WriteHeaderNow() {}

// Size returns bytes buffered so far (pre-flush).
func (w *etagResponseWriter) Size() int { return w.body.Len() }

// Status returns the buffered status code.
func (w *etagResponseWriter) Status() int { return w.bufStatus }

// Hijack passes through to the underlying writer.
func (w *etagResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("etag: underlying ResponseWriter does not implement http.Hijacker")
	}
	return h.Hijack()
}

// commitTo flushes buffered headers + body to the real underlying http.ResponseWriter.
// If overrideStatus > 0 that status is sent instead of the buffered one.
// For 304/204 the body is suppressed.
func (w *etagResponseWriter) commitTo(underlying http.ResponseWriter, overrideStatus int) {
	if w.committed {
		return
	}
	w.committed = true

	status := w.bufStatus
	if overrideStatus > 0 {
		status = overrideStatus
	}

	// Copy buffered headers to the real ResponseWriter.
	dst := underlying.Header()
	for k, vals := range w.bufHeader {
		dst[k] = vals
	}

	underlying.WriteHeader(status)

	// Suppress body for status codes that must not carry one.
	if status == http.StatusNotModified || status == http.StatusNoContent {
		return
	}
	_, _ = underlying.Write(w.body.Bytes())
}

// computeETag returns a strong ETag value derived from a SHA-256 hash of body.
func computeETag(body []byte) string {
	hash := sha256.Sum256(body)
	return fmt.Sprintf(`"sha256:%x"`, hash)
}

// unwrapHTTP walks the chain of ResponseWriter wrappers looking for the bare
// http.ResponseWriter that actually sends bytes to the network.
// For Gin's production use this is the *http.response from the stdlib.
// For tests this is *httptest.ResponseRecorder.
func unwrapHTTP(rw http.ResponseWriter) http.ResponseWriter {
	type unwrapper interface {
		Unwrap() http.ResponseWriter
	}
	for {
		u, ok := rw.(unwrapper)
		if !ok {
			return rw
		}
		rw = u.Unwrap()
	}
}

// ETag returns a Gin middleware that implements HTTP conditional request semantics.
//
// GET / HEAD responses
//
// The middleware captures the response body, computes a SHA-256 ETag, and emits the
// ETag response header. When the incoming request contains an If-None-Match header
// that matches the computed ETag, 304 Not Modified is returned instead.
//
// PUT / DELETE requests with If-Match
//
// The middleware captures the response body of a successful handler invocation,
// computes the ETag of that body, and returns 412 Precondition Failed when the
// caller's If-Match value does not match.
//
// POST and other methods are not affected.
//
// Streaming responses (Transfer-Encoding: chunked) bypass ETag logic.
func ETag() gin.HandlerFunc {
	return func(c *gin.Context) {
		method := c.Request.Method

		switch method {
		case http.MethodGet, http.MethodHead:
			etagGET(c)
		case http.MethodPut, http.MethodDelete:
			etagMutate(c)
		default:
			c.Next()
		}
	}
}

// etagGET handles GET/HEAD: generates an ETag and handles If-None-Match.
func etagGET(c *gin.Context) {
	// Keep a reference to the real underlying http.ResponseWriter before we swap.
	underlying := unwrapHTTP(c.Writer)

	bw := newETagResponseWriter(c.Writer)
	c.Writer = bw

	c.Next()

	// Skip streaming responses — chunked encoding means we can't buffer the body.
	if bw.bufHeader.Get("Transfer-Encoding") == "chunked" {
		bw.commitTo(underlying, 0)
		return
	}

	// Only generate ETags for successful responses.
	if bw.bufStatus < 200 || bw.bufStatus >= 300 {
		bw.commitTo(underlying, 0)
		return
	}

	etag := computeETag(bw.body.Bytes())

	// Return 304 when the client's cached copy is still current.
	if ifNoneMatch := c.Request.Header.Get("If-None-Match"); ifNoneMatch == etag {
		bw.commitTo(underlying, http.StatusNotModified)
		return
	}

	// Attach the ETag to the response headers before committing.
	bw.bufHeader.Set("ETag", etag)
	bw.commitTo(underlying, 0)
}

// etagMutate handles PUT/DELETE: validates If-Match against the response body ETag.
func etagMutate(c *gin.Context) {
	ifMatch := c.Request.Header.Get("If-Match")
	if ifMatch == "" {
		c.Next()
		return
	}

	underlying := unwrapHTTP(c.Writer)

	bw := newETagResponseWriter(c.Writer)
	c.Writer = bw

	c.Next()

	// Only validate on successful responses; pass errors through unmodified.
	if bw.bufStatus < 200 || bw.bufStatus >= 300 {
		bw.commitTo(underlying, 0)
		return
	}

	etag := computeETag(bw.body.Bytes())
	if ifMatch != etag {
		// The client's ETag doesn't match the resource — precondition failed.
		bw.commitTo(underlying, http.StatusPreconditionFailed)
		return
	}

	bw.commitTo(underlying, 0)
}
