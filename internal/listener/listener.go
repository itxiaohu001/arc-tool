package listener

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
)

// Options represents the configuration for listing
type Options struct {
	Pattern string
	Engine  string // "glob" or "regex"
	Verbose bool
}

// Custom error types
type ArchiveError struct {
	Op  string
	Err error
}

func (e *ArchiveError) Error() string {
	return fmt.Sprintf("archive error during %s: %v", e.Op, e.Err)
}

type UnsupportedFormatError struct {
	Format string
}

func (e *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("unsupported archive format: %s", e.Format)
}

// List lists files in an archive that match the pattern
func List(archivePath string, opts *Options) error {
	// Validate options
	if err := validateOptions(opts); err != nil {
		return &ArchiveError{Op: "validation", Err: err}
	}

	// Determine archive type by file extension
	ext := strings.ToLower(filepath.Ext(archivePath))

	switch ext {
	case ".zip":
		return listZIP(archivePath, opts)
	case ".tar":
		return listTAR(archivePath, opts)
	case ".gz", ".bz2", ".xz":
		// Check if it's a .tar.gz, .tar.bz2, or .tar.xz
		if strings.HasSuffix(archivePath, ".tar.gz") ||
		   strings.HasSuffix(archivePath, ".tgz") {
			return listTARGZ(archivePath, opts)
		} else if strings.HasSuffix(archivePath, ".tar.bz2") {
			return listTARBZ2(archivePath, opts)
		} else if strings.HasSuffix(archivePath, ".tar.xz") {
			return listTARXZ(archivePath, opts)
		} else {
			// Handle .gz files that are not tar.gz
			return &UnsupportedFormatError{Format: ext}
		}
	default:
		// Try to detect by content if extension is not helpful
		return listByContent(archivePath, opts)
	}
}

// ListFromStdin lists files from stdin
func ListFromStdin(opts *Options) error {
	// Validate options
	if err := validateOptions(opts); err != nil {
		return &ArchiveError{Op: "validation", Err: err}
	}

	// For stdin, we need to detect the format by reading the first few bytes
	// We'll buffer the input to allow for format detection

	// Create a temporary file to buffer stdin
	tmpFile, err := os.CreateTemp("", "arc-tool-stdin-*")
	if err != nil {
		return &ArchiveError{Op: "create temp file", Err: err}
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Copy stdin to temporary file
	if _, err := io.Copy(tmpFile, os.Stdin); err != nil {
		return &ArchiveError{Op: "read from stdin", Err: err}
	}

	// Reset file pointer to beginning
	if _, err := tmpFile.Seek(0, 0); err != nil {
		return &ArchiveError{Op: "seek in temp file", Err: err}
	}

	// Read first few bytes to detect format
	buf := make([]byte, 4)
	if _, err := tmpFile.Read(buf); err != nil && err != io.EOF {
		return &ArchiveError{Op: "read magic bytes", Err: err}
	}

	// Reset file pointer to beginning again
	if _, err := tmpFile.Seek(0, 0); err != nil {
		return &ArchiveError{Op: "seek in temp file", Err: err}
	}

	// Detect format by magic numbers
	if buf[0] == 0x50 && buf[1] == 0x4B {
		// ZIP format
		return listZIPFromReader(tmpFile, opts)
	} else if buf[0] == 0x1F && buf[1] == 0x8B {
		// GZIP format
		gzr, err := gzip.NewReader(tmpFile)
		if err != nil {
			return &ArchiveError{Op: "create gzip reader", Err: err}
		}
		defer gzr.Close()

		// Check if it's a tar.gz by looking for TAR magic
		tarBuf := make([]byte, 262) // TAR magic is at position 257
		if _, err := gzr.Read(tarBuf); err != nil && err != io.EOF {
			return &ArchiveError{Op: "read from gzip stream", Err: err}
		}

		// Reset to beginning of gzip stream
		if _, err := tmpFile.Seek(0, 0); err != nil {
			return &ArchiveError{Op: "seek in temp file", Err: err}
		}
		gzr2, err := gzip.NewReader(tmpFile)
		if err != nil {
			return &ArchiveError{Op: "create gzip reader", Err: err}
		}
		defer gzr2.Close()

		// Simple check for TAR format
		if len(tarBuf) >= 262 && string(tarBuf[257:262]) == "ustar" {
			return processTARListing(gzr2, opts)
		}
		return &UnsupportedFormatError{Format: "gzip (non-TAR)"}
	} else if buf[0] == 0x42 && buf[1] == 0x5A {
		// BZIP2 format
		bz2r := bzip2.NewReader(tmpFile)

		// Check if it's a tar.bz2 by peeking at the decompressed data
		tarBuf := make([]byte, 262)
		if _, err := bz2r.Read(tarBuf); err != nil && err != io.EOF {
			return &ArchiveError{Op: "read from bzip2 stream", Err: err}
		}

		// For bzip2, we need to reprocess since we can't seek
		// Reset file pointer to beginning
		if _, err := tmpFile.Seek(0, 0); err != nil {
			return &ArchiveError{Op: "seek in temp file", Err: err}
		}

		bz2r2 := bzip2.NewReader(tmpFile)

		// Simple check for TAR format
		if len(tarBuf) >= 262 && string(tarBuf[257:262]) == "ustar" {
			return processTARListing(bz2r2, opts)
		}
		return &UnsupportedFormatError{Format: "bzip2 (non-TAR)"}
	} else if len(buf) >= 4 && buf[0] == 0xFD && buf[1] == 0x37 && buf[2] == 0x7A && buf[3] == 0x58 {
		// XZ format
		xzr, err := xz.NewReader(tmpFile)
		if err != nil {
			return &ArchiveError{Op: "create xz reader", Err: err}
		}

		// Check if it's a tar.xz by peeking at the decompressed data
		tarBuf := make([]byte, 262)
		if _, err := xzr.Read(tarBuf); err != nil && err != io.EOF {
			return &ArchiveError{Op: "read from xz stream", Err: err}
		}

		// For xz, we need to reprocess since we can't seek
		// Reset file pointer to beginning
		if _, err := tmpFile.Seek(0, 0); err != nil {
			return &ArchiveError{Op: "seek in temp file", Err: err}
		}

		xzr2, err := xz.NewReader(tmpFile)
		if err != nil {
			return &ArchiveError{Op: "create xz reader", Err: err}
		}

		// Simple check for TAR format
		if len(tarBuf) >= 262 && string(tarBuf[257:262]) == "ustar" {
			return processTARListing(xzr2, opts)
		}
		return &UnsupportedFormatError{Format: "xz (non-TAR)"}
	} else {
		// Assume TAR format
		return processTARListing(tmpFile, opts)
	}
}

// validateOptions validates the listener options
func validateOptions(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("options cannot be nil")
	}

	if opts.Engine != "glob" && opts.Engine != "regex" {
		return fmt.Errorf("invalid engine: %s, must be 'glob' or 'regex'", opts.Engine)
	}

	if opts.Engine == "regex" {
		if _, err := regexp.Compile(opts.Pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %v", err)
		}
	}

	return nil
}

// listByContent tries to detect archive type by content
func listByContent(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open file", Err: err}
	}
	defer file.Close()

	// Read magic numbers to detect format
	buf := make([]byte, 4)
	if _, err := file.Read(buf); err != nil {
		return &ArchiveError{Op: "read magic bytes", Err: err}
	}

	// Reset file pointer
	file.Seek(0, 0)

	// Check for ZIP magic number
	if buf[0] == 0x50 && buf[1] == 0x4B {
		return listZIP(archivePath, opts)
	}

	// Check for TAR magic (not reliable, so we'll try TAR by default for unknown formats)
	return listTAR(archivePath, opts)
}

// listZIP handles ZIP archive listing
func listZIP(archivePath string, opts *Options) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open ZIP reader", Err: err}
	}
	defer r.Close()

	// Process each file in the archive
	for _, f := range r.File {
		if matchesPattern(f.Name, opts.Pattern, opts.Engine) {
			if opts.Verbose {
				modTime := f.Modified.Format("2006-01-02 15:04:05")
				fmt.Printf("%s %10d %s %s\n", f.Mode().String(), f.UncompressedSize64, modTime, f.Name)
			} else {
				fmt.Println(f.Name)
			}
		}
	}

	return nil
}

// listZIPFromReader handles ZIP archive listing from an io.Reader
func listZIPFromReader(reader io.ReaderAt, opts *Options) error {
	// For ZIP from reader, we need the size
	tmpFile, ok := reader.(*os.File)
	if !ok {
		return &ArchiveError{Op: "type assertion", Err: fmt.Errorf("cannot list ZIP from this reader type")}
	}

	stat, err := tmpFile.Stat()
	if err != nil {
		return &ArchiveError{Op: "stat temp file", Err: err}
	}

	r, err := zip.NewReader(tmpFile, stat.Size())
	if err != nil {
		return &ArchiveError{Op: "create ZIP reader", Err: err}
	}

	// Process each file in the archive
	for _, f := range r.File {
		if matchesPattern(f.Name, opts.Pattern, opts.Engine) {
			if opts.Verbose {
				modTime := f.Modified.Format("2006-01-02 15:04:05")
				fmt.Printf("%s %10d %s %s\n", f.Mode().String(), f.UncompressedSize64, modTime, f.Name)
			} else {
				fmt.Println(f.Name)
			}
		}
	}

	return nil
}

// listTAR handles TAR archive listing
func listTAR(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR file", Err: err}
	}
	defer file.Close()

	return processTARListing(file, opts)
}

// listTARGZ handles .tar.gz archive listing
func listTARGZ(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.GZ file", Err: err}
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return &ArchiveError{Op: "create gzip reader", Err: err}
	}
	defer gzr.Close()

	return processTARListing(gzr, opts)
}

// listTARBZ2 handles .tar.bz2 archive listing
func listTARBZ2(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.BZ2 file", Err: err}
	}
	defer file.Close()

	bz2r := bzip2.NewReader(file)
	return processTARListing(bz2r, opts)
}

// listTARXZ handles .tar.xz archive listing
func listTARXZ(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.XZ file", Err: err}
	}
	defer file.Close()

	xzr, err := xz.NewReader(file)
	if err != nil {
		return &ArchiveError{Op: "create xz reader", Err: err}
	}

	return processTARListing(xzr, opts)
}

// processTARListing processes a TAR archive from an io.Reader for listing
func processTARListing(reader io.Reader, opts *Options) error {
	tr := tar.NewReader(reader)

	// Process each file in the archive
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ArchiveError{Op: "read TAR header", Err: err}
		}

		if matchesPattern(header.Name, opts.Pattern, opts.Engine) {
			if opts.Verbose {
				modTime := time.Unix(header.ModTime.Unix(), 0).Format("2006-01-02 15:04:05")
				fmt.Printf("%s %10d %s %s\n", os.FileMode(header.Mode).String(), header.Size, modTime, header.Name)
			} else {
				fmt.Println(header.Name)
			}
		}
	}

	return nil
}

// matchesPattern checks if a filename matches the given pattern
func matchesPattern(filename, pattern, engine string) bool {
	switch engine {
	case "regex":
		matched, err := regexp.MatchString(pattern, filename)
		if err != nil {
			return false
		}
		return matched
	case "glob":
		fallthrough
	default:
		matched, err := filepath.Match(pattern, filename)
		if err != nil {
			return false
		}
		return matched
	}
}