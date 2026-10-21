package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// LogEntry is one HTTP exchange with everything needed to debug it: the raw
// request and response, the decoded protocol messages, the simulations in
// force and notes explaining what the IdP decided.
type LogEntry struct {
	ID          int64       `json:"id"`
	Time        time.Time   `json:"time"`
	Tenant      string      `json:"tenant,omitempty"`
	App         string      `json:"app,omitempty"`
	Kind        string      `json:"kind"`
	Level       string      `json:"level"` // info | warn | error
	Summary     string      `json:"summary"`
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	ReqHeaders  http.Header `json:"reqHeaders,omitempty"`
	ReqBody     string      `json:"reqBody,omitempty"`
	Status      int         `json:"status"`
	RespHeaders http.Header `json:"respHeaders,omitempty"`
	RespBody    string      `json:"respBody,omitempty"`
	DurationMs  int64       `json:"durationMs"`
	Sims        []string    `json:"sims,omitempty"`
	Notes       []string    `json:"notes,omitempty"`
	Decoded     []Decoded   `json:"decoded,omitempty"`
	Run         string      `json:"run,omitempty"` // groups the calls of one SCIM run
}

type Decoded struct {
	Label string `json:"label"`
	Kind  string `json:"kind"` // xml | json | text
	Value any    `json:"value"`
}

func (e *LogEntry) note(f string, a ...any) { e.Notes = append(e.Notes, fmt.Sprintf(f, a...)) }

func (e *LogEntry) warn(f string, a ...any) {
	e.note("⚠ "+f, a...)
	if e.Level == "info" {
		e.Level = "warn"
	}
}

func (e *LogEntry) fail(f string, a ...any) {
	e.note("✗ "+f, a...)
	e.Level = "error"
}

func (e *LogEntry) decode(label, kind string, v any) {
	e.Decoded = append(e.Decoded, Decoded{label, kind, v})
}

type sseEvent struct {
	name string
	data any
}

type LogBook struct {
	mu      sync.Mutex
	max     int
	next    int64
	entries []*LogEntry
	subs    map[chan sseEvent]struct{}
}

func newLogBook(max int) *LogBook {
	return &LogBook{max: max, subs: map[chan sseEvent]struct{}{}}
}

func (b *LogBook) add(e *LogEntry) {
	b.mu.Lock()
	b.next++
	e.ID = b.next
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b.entries = append(b.entries, e)
	if len(b.entries) > b.max {
		b.entries = append([]*LogEntry(nil), b.entries[len(b.entries)-b.max:]...)
	}
	b.mu.Unlock()
	b.publish("log", e)
}

func (b *LogBook) publish(name string, data any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- sseEvent{name, data}:
		default: // a slow dashboard drops events rather than stalling the IdP
		}
	}
}

func (b *LogBook) subscribe() chan sseEvent {
	ch := make(chan sseEvent, 256)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *LogBook) unsubscribe(ch chan sseEvent) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
}

func (b *LogBook) get(id int64) *LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range b.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// list returns the newest matching entries, oldest first.
func (b *LogBook) list(tenant, kind, q, run string, after int64, limit int) []*LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	q = strings.ToLower(q)
	out := []*LogEntry{}
	for i := len(b.entries) - 1; i >= 0 && len(out) < limit; i-- {
		e := b.entries[i]
		if e.ID <= after {
			break
		}
		if (tenant != "" && e.Tenant != tenant) || (kind != "" && !strings.HasPrefix(e.Kind, kind)) || (run != "" && e.Run != run) {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Summary+" "+e.URL+" "+e.ReqBody+" "+e.RespBody+" "+strings.Join(e.Notes, " ")), q) {
			continue
		}
		out = append(out, e)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (b *LogBook) clear() {
	b.mu.Lock()
	b.entries = nil
	b.mu.Unlock()
}

type entryKey struct{}

// entry is the log entry for this request. Handlers annotate it.
func entry(r *http.Request) *LogEntry {
	if e, ok := r.Context().Value(entryKey{}).(*LogEntry); ok {
		return e
	}
	return &LogEntry{Level: "info"}
}

type recorder struct {
	http.ResponseWriter
	status int
	wrote  bool
	body   bytes.Buffer
}

func (r *recorder) WriteHeader(c int) {
	if !r.wrote {
		r.status, r.wrote = c, true
	}
	r.ResponseWriter.WriteHeader(c)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.wrote = true
	if r.body.Len() < 256<<10 {
		r.body.Write(b)
	}
	return r.ResponseWriter.Write(b)
}

// traced records the exchange in the log book.
func (s *Server) traced(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		e := &LogEntry{Kind: "http", Level: "info", Method: r.Method, URL: s.base + r.URL.RequestURI(),
			ReqHeaders: r.Header.Clone(), Tenant: r.PathValue("tenant"), App: r.PathValue("app")}
		if r.Body != nil {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(b))
			e.ReqBody = string(b)
		}
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		// Go drops a query or form it cannot parse and carries on with an
		// empty one, so a mangled SAMLRequest looked like no request at all
		// and became an IdP-initiated login. Refuse it for every endpoint.
		if err := r.ParseForm(); err != nil {
			e.fail("malformed query or form: %v", err)
			http.Error(rec, "malformed query or form: "+err.Error(), http.StatusBadRequest)
		} else {
			h(rec, r.WithContext(context.WithValue(r.Context(), entryKey{}, e)))
		}
		e.Status, e.RespHeaders, e.RespBody = rec.status, w.Header().Clone(), rec.body.String()
		e.DurationMs = time.Since(start).Milliseconds()
		if e.Status >= 400 && e.Level != "error" {
			e.Level = "error"
		}
		if e.Summary == "" {
			e.Summary = r.Method + " " + r.URL.Path
		}
		s.logs.add(e)
	})
}
