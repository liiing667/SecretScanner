package scan

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deepfence/SecretScanner/core"
	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/signature"
	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/deepfence/match-scanner/pkg/extractor"
)

const (
	testSimpleSecret  = "topsecret-token"
	testPatternSecret = "AKIAIOSFODNN7EXAMPLE"
)

func setupSignatures() {
	signature.ProcessSignatures([]core.ConfigSignature{
		{
			Name:  "simple-contents",
			Part:  signature.ContentsPart,
			Match: testSimpleSecret,
		},
		{
			Name:  "pattern-contents",
			Part:  signature.ContentsPart,
			Regex: `AKIA[0-9A-Z]{16}`,
		},
	})
}

type extractEntry struct {
	file extractor.ExtractedFile
	err  error
}

type fakeExtractor struct {
	entries []extractEntry
	idx     int
}

func (f *fakeExtractor) NextFile() (extractor.ExtractedFile, error) {
	if f.idx >= len(f.entries) {
		return extractor.ExtractedFile{}, io.EOF
	}
	entry := f.entries[f.idx]
	f.idx++
	return entry.file, entry.err
}

func (f *fakeExtractor) Close() error { return nil }

func fileEntry(name, content string) extractEntry {
	return extractEntry{
		file: extractor.ExtractedFile{
			Filename: name,
			Content:  strings.NewReader(content),
		},
	}
}

// errSeekReader fails every Seek call.
type errSeekReader struct {
	rs io.ReadSeeker
}

func (e errSeekReader) Read(p []byte) (int, error) { return e.rs.Read(p) }
func (e errSeekReader) Seek(int64, int) (int64, error) {
	return 0, errors.New("seek disabled")
}

func collectOutput(secrets *[]output.SecretFound) func(output.SecretFound, string) error {
	return func(secret output.SecretFound, _ string) error {
		*secrets = append(*secrets, secret)
		return nil
	}
}

func TestScanExtractorCleanSuccess(t *testing.T) {
	setupSignatures()
	extract := &fakeExtractor{entries: []extractEntry{
		fileEntry("/dir/clean.txt", "nothing to see here"),
		fileEntry("/dir/secret.txt", "token = "+testSimpleSecret),
	}}

	var secrets []output.SecretFound
	err := ScanExtractor(nil, extract, "scan-success", collectOutput(&secrets))
	if err != nil {
		t.Fatalf("expected complete success, got %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].CompleteFilename != "/dir/secret.txt" {
		t.Fatalf("unexpected secret file %q", secrets[0].CompleteFilename)
	}
}

func TestScanExtractorMultiMatch(t *testing.T) {
	setupSignatures()
	extract := &fakeExtractor{entries: []extractEntry{
		fileEntry("/dir/multi.txt", testSimpleSecret+" and "+testPatternSecret),
	}}

	var secrets []output.SecretFound
	err := ScanExtractor(nil, extract, "scan-multi", collectOutput(&secrets))
	if err != nil {
		t.Fatalf("expected complete success, got %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("expected simple and pattern matches, got %d secrets", len(secrets))
	}
}

func TestScanErrorExtractFailure(t *testing.T) {
	setupSignatures()
	extractErr := errors.New("open /dir/bad.txt: permission denied")
	extract := &fakeExtractor{entries: []extractEntry{
		fileEntry("/dir/ok.txt", "clean"),
		{err: extractErr},
	}}

	var secrets []output.SecretFound
	err := ScanExtractor(nil, extract, "scan-extract", collectOutput(&secrets))
	var partial *PartialScanError
	if !errors.As(err, &partial) {
		t.Fatalf("expected PartialScanError, got %v", err)
	}
	if len(partial.Failures) != 1 {
		t.Fatalf("expected 1 failure, got %d", len(partial.Failures))
	}
	if partial.Failures[0].Stage != StageExtract {
		t.Fatalf("expected extract stage, got %q", partial.Failures[0].Stage)
	}
	if !errors.Is(err, extractErr) {
		t.Fatalf("expected wrapped extractor error, got %v", err)
	}
}

func TestScanErrorScanFailure(t *testing.T) {
	setupSignatures()
	extract := &fakeExtractor{entries: []extractEntry{
		{file: extractor.ExtractedFile{
			Filename: "/dir/broken.txt",
			Content:  errSeekReader{rs: strings.NewReader("x " + testSimpleSecret)},
		}},
		fileEntry("/dir/ok.txt", "clean"),
	}}

	var secrets []output.SecretFound
	err := ScanExtractor(nil, extract, "scan-broken", collectOutput(&secrets))
	var partial *PartialScanError
	if !errors.As(err, &partial) {
		t.Fatalf("expected PartialScanError, got %v", err)
	}
	if len(partial.Failures) != 1 || partial.Failures[0].Stage != StageScan {
		t.Fatalf("expected 1 scan-stage failure, got %+v", partial.Failures)
	}
	failed := partial.FailedFiles()
	if len(failed) != 1 || failed[0] != "/dir/broken.txt" {
		t.Fatalf("expected /dir/broken.txt in failed files, got %v", failed)
	}
	if strings.Contains(err.Error(), testSimpleSecret) {
		t.Fatalf("error must not leak secret contents: %v", err)
	}
}

func TestScanErrorOutputCallback(t *testing.T) {
	setupSignatures()
	extract := &fakeExtractor{entries: []extractEntry{
		fileEntry("/dir/secret.txt", "token = "+testSimpleSecret),
	}}
	outputErr := errors.New("disk full")

	err := ScanExtractor(nil, extract, "scan-output",
		func(output.SecretFound, string) error { return outputErr })
	var partial *PartialScanError
	if !errors.As(err, &partial) {
		t.Fatalf("expected PartialScanError, got %v", err)
	}
	if len(partial.Failures) != 1 || partial.Failures[0].Stage != StageOutput {
		t.Fatalf("expected 1 output-stage failure, got %+v", partial.Failures)
	}
	if !errors.Is(err, outputErr) {
		t.Fatalf("expected wrapped output error, got %v", err)
	}
	failed := partial.FailedFiles()
	if len(failed) != 1 || failed[0] != "/dir/secret.txt" {
		t.Fatalf("expected /dir/secret.txt in failed files, got %v", failed)
	}
}

func TestScanErrorAggregatesFailedFiles(t *testing.T) {
	setupSignatures()
	extract := &fakeExtractor{entries: []extractEntry{
		{file: extractor.ExtractedFile{
			Filename: "/dir/broken1.txt",
			Content:  errSeekReader{rs: strings.NewReader("a " + testSimpleSecret)},
		}},
		{file: extractor.ExtractedFile{
			Filename: "/dir/broken2.txt",
			Content:  errSeekReader{rs: strings.NewReader("b " + testSimpleSecret)},
		}},
		fileEntry("/dir/ok.txt", "clean"),
	}}

	var secrets []output.SecretFound
	err := ScanExtractor(nil, extract, "scan-aggregate", collectOutput(&secrets))
	var partial *PartialScanError
	if !errors.As(err, &partial) {
		t.Fatalf("expected PartialScanError, got %v", err)
	}
	if len(partial.Failures) != 2 {
		t.Fatalf("expected 2 aggregated failures, got %d", len(partial.Failures))
	}
	for _, name := range []string{"/dir/broken1.txt", "/dir/broken2.txt"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("aggregated error should mention %s: %v", name, err)
		}
	}
}

func TestScanErrorInvalidScanType(t *testing.T) {
	setupSignatures()
	err := Scan(nil, ScanType(99), cfg.Filters{}, "", "id", "scan-invalid",
		func(output.SecretFound, string) error { return nil })
	if err == nil {
		t.Fatal("expected error for invalid scan type")
	}
	var partial *PartialScanError
	if errors.As(err, &partial) {
		t.Fatalf("setup failure should not be a PartialScanError: %v", err)
	}
}

func TestScanDirUnreadableFileError(t *testing.T) {
	setupSignatures()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("clean"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(bad, []byte("token = "+testSimpleSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o644) })

	var secrets []output.SecretFound
	err := Scan(nil, DirScan, cfg.Filters{}, "", dir, "scan-dir", collectOutput(&secrets))
	var partial *PartialScanError
	if !errors.As(err, &partial) {
		t.Fatalf("expected PartialScanError for unreadable file, got %v", err)
	}
	if len(partial.Failures) == 0 {
		t.Fatal("expected at least one aggregated failure")
	}
}

func TestScanDirCompleteSuccess(t *testing.T) {
	setupSignatures()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"),
		[]byte("token = "+testSimpleSecret), 0o644); err != nil {
		t.Fatal(err)
	}

	var secrets []output.SecretFound
	err := Scan(nil, DirScan, cfg.Filters{}, "", dir, "scan-dir-ok", collectOutput(&secrets))
	if err != nil {
		t.Fatalf("expected complete success, got %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
}
