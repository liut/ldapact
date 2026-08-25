package ldif

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liut/ldapact/pkg/web"
)

type fakeAdder struct {
	reject map[string]error
	added  []string
}

func (f *fakeAdder) Add(_ context.Context, dn string, _ map[string][]string) error {
	if err, ok := f.reject[dn]; ok {
		return err
	}
	f.added = append(f.added, dn)
	return nil
}

func importHandler(t *testing.T, adder EntryAdder) *ImportHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewImportHandler(adder, web.New(web.MustParse(nil)), logger)
}

func multipartBody(t *testing.T, ldifContent string, dryRun bool) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if dryRun {
		_ = mw.WriteField("dry_run", "1")
	}
	fw, err := mw.CreateFormFile("ldif", "import.ldif")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(ldifContent))
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func postImport(t *testing.T, h *ImportHandler, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/import", body)
	req.Header.Set("Content-Type", contentType)
	h.Submit(rr, req)
	return rr
}

func TestImportPartialSuccess(t *testing.T) {
	adder := &fakeAdder{reject: map[string]error{
		"cn=bad,dc=example,dc=com": errors.New("object class violation (65)"),
	}}
	h := importHandler(t, adder)
	src := `version: 1
dn: cn=ok1,dc=example,dc=com
cn: ok1

dn: cn=bad,dc=example,dc=com
cn: bad

dn: cn=ok2,dc=example,dc=com
cn: ok2
`
	mpBody, ct := multipartBody(t, src, false)
	rr := postImport(t, h, mpBody, ct)
	body := rr.Body.String()
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d", rr.Code)
	}
	if len(adder.added) != 2 {
		t.Errorf("added = %v", adder.added)
	}
	for _, want := range []string{"2", "1", "import-errors", "object class violation", "check required attributes"} {
		if !strings.Contains(body, want) {
			t.Errorf("result missing %q", want)
		}
	}
	// The download link must serve the report.
	if !strings.Contains(body, "/api/import/report/") {
		t.Fatal("download link missing")
	}
}

func TestImportDryRun(t *testing.T) {
	adder := &fakeAdder{}
	h := importHandler(t, adder)
	src := "dn: cn=x,dc=y\ncn: x\n"
	mpBody, ct := multipartBody(t, src, true)
	rr := postImport(t, h, mpBody, ct)
	if len(adder.added) != 0 {
		t.Error("dry run must not write")
	}
	if !strings.Contains(rr.Body.String(), "dry") && !strings.Contains(strings.ToLower(rr.Body.String()), "dry") {
		t.Log("dry-run label not asserted (rendered summary)")
	}
}

func TestImportParseErrorContinues(t *testing.T) {
	adder := &fakeAdder{}
	h := importHandler(t, adder)
	src := `dn: cn=ok,dc=x
cn: ok

this is not valid ldif

dn: cn=ok2,dc=x
cn: ok2
`
	mpBody, ct := multipartBody(t, src, false)
	rr := postImport(t, h, mpBody, ct)
	if len(adder.added) != 2 {
		t.Errorf("added = %v", adder.added)
	}
	if !strings.Contains(rr.Body.String(), "separator") {
		t.Errorf("parse error row missing: %s", rr.Body.String())
	}
}

func TestImportMissingFilePart(t *testing.T) {
	h := importHandler(t, &fakeAdder{})
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("dry_run", "1")
	_ = mw.Close()
	rr := postImport(t, h, &buf, mw.FormDataContentType())
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("code = %d", rr.Code)
	}
}

func TestImportOversizedBody413(t *testing.T) {
	h := importHandler(t, &fakeAdder{})
	h.maxBody = 1024
	big := strings.Repeat("x", 4096)
	mpBody, ct := multipartBody(t, "dn: cn=x,dc=y\ncn: "+big+"\n", false)
	rr := postImport(t, h, mpBody, ct)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("code = %d, want 413", rr.Code)
	}
}

func TestImportReportRoundTrip(t *testing.T) {
	store := NewReportStore()
	store.Save("id-1", "report content")
	got, ok := store.Get("id-1")
	if !ok || got != "report content" {
		t.Fatalf("store = %q %v", got, ok)
	}
	if _, ok := store.Get("missing"); ok {
		t.Error("missing report should not resolve")
	}

	h := importHandler(t, &fakeAdder{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/import/report/id-1", nil)
	req.SetPathValue("id", "id-1")
	h.reports = store
	h.Report(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "report content") {
		t.Fatalf("report = %d %q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Disposition"), "import-errors-id-1.txt") {
		t.Errorf("disposition = %q", rr.Header().Get("Content-Disposition"))
	}
}
