package tester

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
)

// Options represents the configuration for testing
type Options struct {
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

// Test tests the integrity of an archive
func Test(archivePath string, opts *Options) error {
	// Validate options
	if opts == nil {
		return fmt.Errorf("options cannot be nil")
	}

	// Determine archive type by file extension
	ext := strings.ToLower(filepath.Ext(archivePath))

	switch ext {
	case ".zip":
		return testZIP(archivePath, opts)
	case ".tar":
		return testTAR(archivePath, opts)
	case ".gz", ".bz2", ".xz":
		// Check if it's a .tar.gz, .tar.bz2, or .tar.xz
		if strings.HasSuffix(archivePath, ".tar.gz") ||
		   strings.HasSuffix(archivePath, ".tgz") {
			return testTARGZ(archivePath, opts)
		} else if strings.HasSuffix(archivePath, ".tar.bz2") {
			return testTARBZ2(archivePath, opts)
		} else if strings.HasSuffix(archivePath, ".tar.xz") {
			return testTARXZ(archivePath, opts)
		} else {
			// Handle .gz files that are not tar.gz
			return &UnsupportedFormatError{Format: ext}
		}
	default:
		// Try to detect by content if extension is not helpful
		return testByContent(archivePath, opts)
	}
}

// TestFromStdin tests the integrity of an archive from stdin
func TestFromStdin(opts *Options) error {
	// Validate options
	if opts == nil {
		return fmt.Errorf("options cannot be nil")
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
		return testZIPFromReader(tmpFile, opts)
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
			return processTARTesting(gzr2, opts)
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
			return processTARTesting(bz2r2, opts)
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
			return processTARTesting(xzr2, opts)
		}
		return &UnsupportedFormatError{Format: "xz (non-TAR)"}
	} else {
		// Assume TAR format
		return processTARTesting(tmpFile, opts)
	}
}

// testByContent tries to detect archive type by content
func testByContent(archivePath string, opts *Options) error {
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
		return testZIP(archivePath, opts)
	}

	// Check for TAR magic (not reliable, so we'll try TAR by default for unknown formats)
	return testTAR(archivePath, opts)
}

// testZIP handles ZIP archive testing
func testZIP(archivePath string, opts *Options) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open ZIP reader", Err: err}
	}
	defer r.Close()

	fileCount := 0
	// Count total files for progress bar
	totalFiles := 0
	for _, f := range r.File {
		if !f.FileInfo().IsDir() {
			totalFiles++
		}
	}

	// Create progress bar if we have files to test
	var bar *progressbar.ProgressBar
	if totalFiles > 0 {
		// Show progress bar for large archives (>10 files)
		if totalFiles > 10 {
			bar = progressbar.Default(int64(totalFiles), "Testing")
		}
	}

	// Process each file in the archive
	testedFiles := 0
	for _, f := range r.File {
		fileCount++
		if opts.Verbose {
			fmt.Printf("Testing %s... ", f.Name)
		}

		// Open the file from the archive
		rc, err := f.Open()
		if err != nil {
			if opts.Verbose {
				fmt.Printf("ERROR\n")
			}
			return &ArchiveError{Op: "open file in ZIP", Err: err}
		}

		// Read the entire file to check integrity
		_, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			if opts.Verbose {
				fmt.Printf("ERROR\n")
			}
			return &ArchiveError{Op: "read file in ZIP", Err: err}
		}

		if opts.Verbose {
			fmt.Printf("OK\n")
		}

		// Update progress bar
		if bar != nil && !f.FileInfo().IsDir() {
			testedFiles++
			bar.Set(testedFiles)
		}
	}

	// Finish progress bar
	if bar != nil {
		bar.Finish()
		fmt.Println()
	}

	if opts.Verbose {
		fmt.Printf("Archive is OK (%d files)\n", fileCount)
	} else {
		fmt.Println("Archive is OK")
	}

	return nil
}

// testZIPFromReader handles ZIP archive testing from an io.Reader
func testZIPFromReader(reader io.ReaderAt, opts *Options) error {
	// For ZIP from reader, we need the size
	tmpFile, ok := reader.(*os.File)
	if !ok {
		return &ArchiveError{Op: "type assertion", Err: fmt.Errorf("cannot test ZIP from this reader type")}
	}

	stat, err := tmpFile.Stat()
	if err != nil {
		return &ArchiveError{Op: "stat temp file", Err: err}
	}

	r, err := zip.NewReader(tmpFile, stat.Size())
	if err != nil {
		return &ArchiveError{Op: "create ZIP reader", Err: err}
	}

	fileCount := 0
	// Count total files for progress bar
	totalFiles := 0
	for _, f := range r.File {
		if !f.FileInfo().IsDir() {
			totalFiles++
		}
	}

	// Create progress bar if we have files to test
	var bar *progressbar.ProgressBar
	if totalFiles > 0 {
		// Show progress bar for large archives (>10 files)
		if totalFiles > 10 {
			bar = progressbar.Default(int64(totalFiles), "Testing")
		}
	}

	// Process each file in the archive
	testedFiles := 0
	for _, f := range r.File {
		fileCount++
		if opts.Verbose {
			fmt.Printf("Testing %s... ", f.Name)
		}

		// Open the file from the archive
		rc, err := f.Open()
		if err != nil {
			if opts.Verbose {
				fmt.Printf("ERROR\n")
			}
			return &ArchiveError{Op: "open file in ZIP", Err: err}
		}

		// Read the entire file to check integrity
		_, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			if opts.Verbose {
				fmt.Printf("ERROR\n")
			}
			return &ArchiveError{Op: "read file in ZIP", Err: err}
		}

		if opts.Verbose {
			fmt.Printf("OK\n")
		}

		// Update progress bar
		if bar != nil && !f.FileInfo().IsDir() {
			testedFiles++
			bar.Set(testedFiles)
		}
	}

	// Finish progress bar
	if bar != nil {
		bar.Finish()
		fmt.Println()
	}

	if opts.Verbose {
		fmt.Printf("Archive is OK (%d files)\n", fileCount)
	} else {
		fmt.Println("Archive is OK")
	}

	return nil
}

// testTAR handles TAR archive testing
func testTAR(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR file", Err: err}
	}
	defer file.Close()

	return processTARTesting(file, opts)
}

// testTARGZ handles .tar.gz archive testing
func testTARGZ(archivePath string, opts *Options) error {
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

	return processTARTesting(gzr, opts)
}

// testTARBZ2 handles .tar.bz2 archive testing
func testTARBZ2(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.BZ2 file", Err: err}
	}
	defer file.Close()

	bz2r := bzip2.NewReader(file)
	return processTARTesting(bz2r, opts)
}

// testTARXZ handles .tar.xz archive testing
func testTARXZ(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.XZ file", Err: err}
	}
	defer file.Close()

	xzr, err := xz.NewReader(file)
	if err != nil {
		return &ArchiveError{Op: "create xz reader", Err: err}
	}

	return processTARTesting(xzr, opts)
}

// processTARTesting processes a TAR archive from an io.Reader for testing
func processTARTesting(reader io.Reader, opts *Options) error {
	tr := tar.NewReader(reader)

	fileCount := 0
	var bar *progressbar.ProgressBar

	// Process each file in the archive
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ArchiveError{Op: "read TAR header", Err: err}
		}

		fileCount++
		if opts.Verbose {
			fmt.Printf("Testing %s... ", header.Name)
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			if opts.Verbose {
				fmt.Printf("OK (directory)\n")
			}
			continue
		}

		// Skip non-regular files
		if header.Typeflag != tar.TypeReg {
			if opts.Verbose {
				fmt.Printf("OK (special file)\n")
			}
			continue
		}

		// Initialize progress bar after we know we have files to process
		if fileCount == 1 {
			// We'll use a simple counter for TAR since we can't easily count total files
			// Show progress bar for ongoing testing of large archives
			bar = progressbar.DefaultBytes(-1, "Testing")
		}

		// Read the entire file to check integrity
		var reader io.Reader = tr
		if bar != nil {
			reader = io.TeeReader(tr, bar)
		}

		_, err = io.ReadAll(reader)
		if err != nil {
			if opts.Verbose {
				fmt.Printf("ERROR\n")
			}
			return &ArchiveError{Op: "read file in TAR", Err: err}
		}

		if opts.Verbose {
			fmt.Printf("OK\n")
		}
	}

	// Finish progress bar
	if bar != nil {
		bar.Finish()
		fmt.Println()
	}

	if opts.Verbose {
		fmt.Printf("Archive is OK (%d files)\n", fileCount)
	} else {
		fmt.Println("Archive is OK")
	}

	return nil
}