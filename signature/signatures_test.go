package signature

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/deepfence/SecretScanner/core"
)

const (
	testSimpleSecret  = "topsecret-token"
	testPatternSecret = "AKIAIOSFODNN7EXAMPLE"
)

func setupSignatures() {
	ProcessSignatures([]core.ConfigSignature{
		{
			Name:  "simple-contents",
			Part:  ContentsPart,
			Match: testSimpleSecret,
		},
		{
			Name:  "pattern-contents",
			Part:  ContentsPart,
			Regex: `AKIA[0-9A-Z]{16}`,
		},
	})
}

// errSeekReader fails every Seek call.
type errSeekReader struct {
	rs io.ReadSeeker
}

func (e errSeekReader) Read(p []byte) (int, error) { return e.rs.Read(p) }
func (e errSeekReader) Seek(int64, int) (int64, error) {
	return 0, errors.New("seek disabled")
}

// failReadAfterSeek fails Read calls once the caller seeks to a non-zero
// offset, simulating a file that breaks mid-scan.
type failReadAfterSeek struct {
	rs       io.ReadSeeker
	failRead bool
}

func (f *failReadAfterSeek) Read(p []byte) (int, error) {
	if f.failRead {
		return 0, errors.New("read failure injected")
	}
	return f.rs.Read(p)
}

func (f *failReadAfterSeek) Seek(offset int64, whence int) (int64, error) {
	pos, err := f.rs.Seek(offset, whence)
	if whence == io.SeekStart && offset != 0 {
		f.failRead = true
	}
	return pos, err
}

func TestMatchSimpleSignaturesScan(t *testing.T) {
	setupSignatures()
	secrets, err := MatchSimpleSignatures(
		strings.NewReader("prefix "+testSimpleSecret+" suffix"),
		"/dir/a.txt", "a.txt", ".txt", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].MatchedContents != testSimpleSecret {
		t.Fatalf("unexpected match %q", secrets[0].MatchedContents)
	}
}

func TestMatchPatternSignaturesScan(t *testing.T) {
	setupSignatures()
	secrets, err := MatchPatternSignatures(
		strings.NewReader("key = "+testPatternSecret),
		"/dir/b.txt", "b.txt", ".txt", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].MatchedContents != testPatternSecret {
		t.Fatalf("unexpected match %q", secrets[0].MatchedContents)
	}
}

func TestMatchSimpleSignaturesError(t *testing.T) {
	setupSignatures()
	content := "prefix " + testSimpleSecret + " suffix"

	_, err := MatchSimpleSignatures(
		&failReadAfterSeek{rs: strings.NewReader(content)},
		"/dir/c.txt", "c.txt", ".txt", "")
	if err == nil {
		t.Fatal("expected read error to be propagated")
	}
	if strings.Contains(err.Error(), testSimpleSecret) {
		t.Fatalf("error must not leak secret contents: %v", err)
	}

	_, err = MatchSimpleSignatures(
		errSeekReader{rs: strings.NewReader(content)},
		"/dir/c.txt", "c.txt", ".txt", "")
	if err == nil {
		t.Fatal("expected seek error to be propagated")
	}
}

func TestMatchPatternSignaturesError(t *testing.T) {
	setupSignatures()
	content := "key = " + testPatternSecret

	_, err := MatchPatternSignatures(
		&failReadAfterSeek{rs: strings.NewReader(content)},
		"/dir/d.txt", "d.txt", ".txt", "")
	if err == nil {
		t.Fatal("expected read error to be propagated")
	}
	if strings.Contains(err.Error(), testPatternSecret) {
		t.Fatalf("error must not leak secret contents: %v", err)
	}

	_, err = MatchPatternSignatures(
		errSeekReader{rs: strings.NewReader(content)},
		"/dir/d.txt", "d.txt", ".txt", "")
	if err == nil {
		t.Fatal("expected seek error to be propagated")
	}
}
