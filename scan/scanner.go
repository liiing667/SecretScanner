package scan

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/deepfence/SecretScanner/output"
	"github.com/deepfence/SecretScanner/signature"
	tasks "github.com/deepfence/golang_deepfence_sdk/utils/tasks"
	"github.com/deepfence/match-scanner/pkg/extractor"

	cfg "github.com/deepfence/match-scanner/pkg/config"
	"github.com/rs/zerolog/log"
)

type ScanType int

const (
	DirScan ScanType = iota
	ImageScan
	ContainerScan
)

func ScanTypeString(st ScanType) string {
	switch st {
	case DirScan:
		return "host"
	case ImageScan:
		return "image"
	case ContainerScan:
		return "container"
	}
	return ""
}

// Stages of a per-file scan that can fail independently.
const (
	StageExtract = "extract"
	StageScan    = "scan"
	StageOutput  = "output"
)

// FileError records a single failure encountered while scanning a file.
// It never carries matched secret contents, only the file name and the
// underlying error.
type FileError struct {
	Stage    string
	Filename string
	Err      error
}

func (e FileError) Error() string {
	if e.Filename == "" {
		return fmt.Sprintf("%s: %v", e.Stage, e.Err)
	}
	return fmt.Sprintf("%s: %s: %v", e.Stage, e.Filename, e.Err)
}

func (e FileError) Unwrap() error {
	return e.Err
}

// PartialScanError is returned by Scan when one or more files could not be
// scanned or reported completely. It aggregates every per-file failure so
// callers can tell a partial scan apart from a complete, successful one.
type PartialScanError struct {
	Failures []FileError
}

func (e *PartialScanError) Error() string {
	return fmt.Sprintf("scan incomplete: %d file(s) failed: %s",
		len(e.Failures), strings.Join(e.FailedFiles(), ", "))
}

func (e *PartialScanError) Unwrap() []error {
	errs := make([]error, 0, len(e.Failures))
	for _, failure := range e.Failures {
		errs = append(errs, failure.Err)
	}
	return errs
}

// FailedFiles returns the de-duplicated list of files that did not complete.
func (e *PartialScanError) FailedFiles() []string {
	seen := make(map[string]struct{}, len(e.Failures))
	files := make([]string, 0, len(e.Failures))
	for _, failure := range e.Failures {
		name := failure.Filename
		if name == "" {
			name = "<unknown>"
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		files = append(files, name)
	}
	return files
}

func scanFile(contents io.ReadSeeker, relPath, fileName, fileExtension, layer string) ([]output.SecretFound, error) {

	simpleSecrets, err := signature.MatchSimpleSignatures(contents, relPath, fileName, fileExtension, layer)
	if err != nil {
		return simpleSecrets, fmt.Errorf("simple signature match: %w", err)
	}

	secrets, err := signature.MatchPatternSignatures(contents, relPath, fileName, fileExtension, layer)
	if err != nil {
		return append(simpleSecrets, secrets...), fmt.Errorf("pattern signature match: %w", err)
	}

	return append(simpleSecrets, secrets...), nil
}

func Scan(ctx *tasks.ScanContext,
	stype ScanType,
	filters cfg.Filters,
	namespace, id, scanID string,
	outputFn func(output.SecretFound, string) error) error {
	var (
		extract extractor.FileExtractor
		err     error
	)
	switch stype {
	case DirScan:
		extract, err = extractor.NewDirectoryExtractor(filters, id, true)
	case ImageScan:
		extract, err = extractor.NewImageExtractor(filters, namespace, id)
	case ContainerScan:
		extract, err = extractor.NewContainerExtractor(filters, namespace, id)
	default:
		err = fmt.Errorf("invalid request")
	}
	if err != nil {
		return err
	}
	defer extract.Close()

	return ScanExtractor(ctx, extract, scanID, outputFn)
}

// ScanExtractor scans every file produced by the extractor and reports
// secrets through outputFn. It returns nil only when every file was
// extracted, scanned and reported successfully; otherwise it returns a
// *PartialScanError aggregating every failed file.
func ScanExtractor(ctx *tasks.ScanContext,
	extract extractor.FileExtractor,
	scanID string,
	outputFn func(output.SecretFound, string) error) error {

	var (
		mu       sync.Mutex
		failures []FileError
	)
	recordFailure := func(stage, filename string, err error) {
		log.Info().Err(err).Str("stage", stage).Str("file", filename).
			Msg("file did not complete scan")
		mu.Lock()
		failures = append(failures, FileError{Stage: stage, Filename: filename, Err: err})
		mu.Unlock()
	}

	type scanResult struct {
		filename string
		secrets  []output.SecretFound
	}

	// results has to be 1 element max
	// to avoid overwriting the buffer entries
	results := make(chan scanResult)

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for result := range results {
			for _, secret := range result.secrets {
				if err := outputFn(secret, scanID); err != nil {
					recordFailure(StageOutput, result.filename, err)
				}
			}
		}
	}()

	for {
		file, err := extract.NextFile()
		if err == io.EOF {
			break
		}
		if err != nil {
			recordFailure(StageExtract, file.Filename, err)
			continue
		}
		if ctx != nil {
			if err := ctx.Checkpoint("scan_phase"); err != nil {
				file.Close()
				close(results)
				wg.Wait()
				return err
			}
		}
		log.Debug().Str("file", file.Filename).Msg("Scanning file")
		secrets, err := scanFile(file.Content, file.Filename,
			filepath.Base(file.Filename), filepath.Ext(file.Filename), "")
		if err != nil {
			recordFailure(StageScan, file.Filename, err)
		}
		results <- scanResult{filename: file.Filename, secrets: secrets}
		file.Close()
	}

	close(results)
	wg.Wait()

	if len(failures) > 0 {
		return &PartialScanError{Failures: failures}
	}
	return nil
}
