package logging

import (
	"bufio"
	"net"
	"net/http"
)

// accessWriter wraps an http.ResponseWriter to capture the status code and
// total byte count written so the AccessLog middleware can report them.
// It implements http.Flusher and http.Hijacker by delegation so SSE streams
// (e.g. the admin log subscription) and any future protocol upgrades keep
// working through this wrapper.
type accessWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int
	wroteHeader  bool
}

func newAccessWriter(w http.ResponseWriter) *accessWriter {
	return &accessWriter{ResponseWriter: w, status: http.StatusOK}
}

// WriteHeader implements http.ResponseWriter, capturing the status code so
// the access record reports the response the client actually saw.
func (w *accessWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.status = code
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(code)
}

// Write implements http.ResponseWriter and tallies the bytes returned to the
// client so the access record carries an accurate bytes_out value.
func (w *accessWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		// net/http implicitly writes 200 on the first Write when no
		// explicit WriteHeader call happened — mirror that so status is
		// always non-zero in the access record.
		w.wroteHeader = true
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += n
	return n, err
}

// Flush delegates to the underlying writer's Flusher when supported, so SSE
// streams (e.g. the admin live-log endpoint) keep working through the wrap.
func (w *accessWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying writer's Hijacker when supported so
// callers that upgrade the connection (e.g. websockets) continue to work
// through the wrap.
func (w *accessWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}
