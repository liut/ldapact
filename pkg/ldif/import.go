package ldif

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/liut/ldapact/pkg/authn"
	"github.com/liut/ldapact/pkg/web"
)

// MaxImportBody is the R11 100MB import cap.
const MaxImportBody = 100 << 20

// EntryAdder is the write surface the importer needs; *ldapx.Client
// implements it.
type EntryAdder interface {
	Add(ctx context.Context, dn string, attrs map[string][]string) error
}

// ImportResult drives the F4 result page (AE5).
type ImportResult struct {
	Success   int
	Failures  int
	DryRun    bool
	ReportID  string
	Rows      []ImportRow
	Error     string
	ReportURL string
}

// ImportRow is one failed entry with the AE5 fields: line, reason, raw LDIF.
type ImportRow struct {
	Line   int
	Reason string
	Raw    string
}

// ImportHandler serves F4.
type ImportHandler struct {
	adder   EntryAdder
	render  *web.Renderer
	logger  *slog.Logger
	reports *ReportStore
	maxBody int64
}

// NewImportHandler builds the F4 handler set.
func NewImportHandler(adder EntryAdder, renderer *web.Renderer, logger *slog.Logger) *ImportHandler {
	return &ImportHandler{
		adder:   adder,
		render:  renderer,
		logger:  logger,
		reports: NewReportStore(),
		maxBody: MaxImportBody,
	}
}

// Form renders the import page.
func (h *ImportHandler) Form(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.PageAuth(w, "Import LDIF — ldapact", "import-form-content", nil, web.ActorFrom(r.Context())); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Submit handles POST /import (F4, AE5).
func (h *ImportHandler) Submit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.maxBody)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Bad Request: expected multipart form", http.StatusBadRequest)
		return
	}
	var file io.Reader
	dryRun := false
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "Bad Request: malformed multipart body", http.StatusBadRequest)
			return
		}
		switch part.FormName() {
		case "ldif":
			file = part
			// Do not drain the file part; the iterator consumes it below.
		case "dry_run":
			dryRun = true
		default:
			// Drain non-file parts so NextPart can advance.
			_, _ = io.Copy(io.Discard, part)
		}
		if file != nil {
			break
		}
	}
	if file == nil {
		http.Error(w, "Bad Request: missing ldif file part", http.StatusBadRequest)
		return
	}

	opts := DefaultOptions()
	it := NewIterator(file, opts)
	result := ImportResult{DryRun: dryRun}
	var report strings.Builder
	for {
		entry, perr, err := it.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Error = "Import aborted: " + err.Error()
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "Payload Too Large: LDIF body exceeds 100MB", http.StatusRequestEntityTooLarge)
				return
			}
			break
		}
		if perr != nil {
			result.Failures++
			row := ImportRow{Line: perr.Line, Reason: perr.Err.Error(), Raw: perr.Raw}
			result.Rows = append(result.Rows, row)
			fmt.Fprintf(&report, "line %d: %s\n%s\n---\n", perr.Line, perr.Err, perr.Raw)
			continue
		}
		if dryRun {
			result.Success++
			continue
		}
		attrs := map[string][]string{}
		for _, a := range entry.Attrs {
			attrs[a.Name] = a.Values
		}
		if err := h.adder.Add(r.Context(), entry.DN, attrs); err != nil {
			if authn.IsInvalidCredentials(err) {
				authn.InvalidCredentialsRedirect(w, r)
				return
			}
			result.Failures++
			reason := "LDAP rejected the entry: " + err.Error()
			if hint := remediationHint(err); hint != "" {
				reason += " — " + hint
			}
			row := ImportRow{Line: entry.StartLine, Reason: reason, Raw: entry.Raw}
			result.Rows = append(result.Rows, row)
			fmt.Fprintf(&report, "line %d: %s\n%s\n---\n", entry.StartLine, reason, entry.Raw)
			continue
		}
		result.Success++
	}
	if report.Len() > 0 {
		id := importReportID()
		h.reports.Save(id, report.String())
		result.ReportID = id
		result.ReportURL = "/api/import/report/" + id
	}
	if h.logger != nil {
		h.logger.Info("ldif import finished",
			"event", "ldif.import",
			"success", result.Success,
			"failures", result.Failures,
			"dry_run", dryRun)
	}
	h.renderPage(w, r, result)
}

// Report streams the stored error report (download link from AE5).
func (h *ImportHandler) Report(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	content, ok := h.reports.Get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="import-errors-%s.txt"`, id))
	_, _ = io.WriteString(w, content)
}

func (h *ImportHandler) renderPage(w http.ResponseWriter, r *http.Request, result ImportResult) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.render.PageAuth(w, "Import result — ldapact", "import-result-content", result, web.ActorFrom(r.Context())); err != nil {
		h.logger.Error("render import result", "event", "web.render_failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func remediationHint(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "65"), strings.Contains(msg, "objectclass"),
		strings.Contains(msg, "Object Class"), strings.Contains(msg, "schema"):
		return "check required attributes for this objectClass"
	case strings.Contains(msg, "68"):
		return "the entry already exists"
	default:
		return ""
	}
}

func importReportID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().Format("20060102-150405")
	}
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}

// ReportStore keeps import error reports in memory (single-admin tool; the
// plan's file is named import-errors-<timestamp>.txt on download).
type ReportStore struct {
	mu      sync.Mutex
	reports map[string]reportRecord
}

type reportRecord struct {
	Created time.Time
	Content string
}

// NewReportStore returns an empty store.
func NewReportStore() *ReportStore {
	return &ReportStore{reports: make(map[string]reportRecord)}
}

// Save stores a report, evicting reports older than one hour and capping the
// map size.
func (s *ReportStore) Save(id, content string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, rec := range s.reports {
		if now.Sub(rec.Created) > time.Hour {
			delete(s.reports, k)
		}
	}
	if len(s.reports) > 50 {
		var oldest string
		var oldestTime time.Time
		for k, rec := range s.reports {
			if oldest == "" || rec.Created.Before(oldestTime) {
				oldest = k
				oldestTime = rec.Created
			}
		}
		delete(s.reports, oldest)
	}
	s.reports[id] = reportRecord{Created: now, Content: content}
}

// Get returns a stored report.
func (s *ReportStore) Get(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.reports[id]
	if !ok {
		return "", false
	}
	return rec.Content, true
}
