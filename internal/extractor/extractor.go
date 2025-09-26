package extractor

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

	"github.com/schollz/progressbar/v3"
	"github.com/ulikunitz/xz"
)

// Options represents the configuration for extraction
type Options struct {
	Pattern   string
	Engine    string // "glob" or "regex"
	OutputDir string
	Flatten   bool
	Force     bool
	Verbose   bool
	DryRun    bool
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

// Extract extracts files from an archive that match the pattern
func Extract(archivePath string, opts *Options) error {
	// Validate options
	if err := validateOptions(opts); err != nil {
		return &ArchiveError{Op: "validation", Err: err}
	}

	// Determine archive type by file extension
	ext := strings.ToLower(filepath.Ext(archivePath))

	switch ext {
	case ".zip":
		return extractZIP(archivePath, opts)
	case ".tar":
		return extractTAR(archivePath, opts)
	case ".gz", ".bz2", ".xz":
		// Check if it's a .tar.gz, .tar.bz2, or .tar.xz
		if strings.HasSuffix(archivePath, ".tar.gz") ||
		   strings.HasSuffix(archivePath, ".tgz") {
			return extractTARGZ(archivePath, opts)
		} else if strings.HasSuffix(archivePath, ".tar.bz2") {
			return extractTARBZ2(archivePath, opts)
		} else if strings.HasSuffix(archivePath, ".tar.xz") {
			return extractTARXZ(archivePath, opts)
		} else {
			// Handle .gz files that are not tar.gz
			return &UnsupportedFormatError{Format: ext}
		}
	default:
		// Try to detect by content if extension is not helpful
		return extractByContent(archivePath, opts)
	}
}

// ExtractFromStdin extracts files from stdin
func ExtractFromStdin(opts *Options) error {
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
		return extractZIPFromReader(tmpFile, opts)
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
			return processTAR(gzr2, opts)
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
			return processTAR(bz2r2, opts)
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
			return processTAR(xzr2, opts)
		}
		return &UnsupportedFormatError{Format: "xz (non-TAR)"}
	} else {
		// Assume TAR format
		return processTAR(tmpFile, opts)
	}
}

// validateOptions validates the extractor options
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

	if opts.OutputDir == "" {
		opts.OutputDir = "."
	}

	return nil
}

// extractByContent tries to detect archive type by content
func extractByContent(archivePath string, opts *Options) error {
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
		return extractZIP(archivePath, opts)
	}

	// Check for TAR magic (not reliable, so we'll try TAR by default for unknown formats)
	return extractTAR(archivePath, opts)
}

// extractZIP handles ZIP archive extraction
func extractZIP(archivePath string, opts *Options) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open ZIP reader", Err: err}
	}
	defer r.Close()

	// Count total files that match pattern for progress bar
	totalFiles := 0
	for _, f := range r.File {
		if matchesPattern(f.Name, opts.Pattern, opts.Engine) && !f.FileInfo().IsDir() {
			totalFiles++
		}
	}

	// Create progress bar if we have files to extract
	var bar *progressbar.ProgressBar
	if totalFiles > 0 && !opts.DryRun {
		// Show progress bar for large archives (>10 files)
		if totalFiles > 10 {
			bar = progressbar.Default(int64(totalFiles), "Extracting")
		}
	}

	// Process each file in the archive
	extractedFiles := 0
	for _, f := range r.File {
		if matchesPattern(f.Name, opts.Pattern, opts.Engine) {
			if opts.Verbose {
				fmt.Printf("Processing %s\n", f.Name)
			}

			if err := extractZIPFile(f, opts); err != nil {
				return &ArchiveError{Op: "extract ZIP file", Err: err}
			}

			// Update progress bar
			if bar != nil && !f.FileInfo().IsDir() {
				extractedFiles++
				bar.Set(extractedFiles)
			}
		}
	}

	// Finish progress bar
	if bar != nil {
		bar.Finish()
		fmt.Println()
	}

	return nil
}

// extractZIPFromReader handles ZIP archive extraction from an io.Reader
func extractZIPFromReader(reader io.ReaderAt, opts *Options) error {
	// For ZIP from reader, we need the size
	tmpFile, ok := reader.(*os.File)
	if !ok {
		return &ArchiveError{Op: "type assertion", Err: fmt.Errorf("cannot extract ZIP from this reader type")}
	}

	stat, err := tmpFile.Stat()
	if err != nil {
		return &ArchiveError{Op: "stat temp file", Err: err}
	}

	r, err := zip.NewReader(tmpFile, stat.Size())
	if err != nil {
		return &ArchiveError{Op: "create ZIP reader", Err: err}
	}

	// Count total files that match pattern for progress bar
	totalFiles := 0
	for _, f := range r.File {
		if matchesPattern(f.Name, opts.Pattern, opts.Engine) && !f.FileInfo().IsDir() {
			totalFiles++
		}
	}

	// Create progress bar if we have files to extract
	var bar *progressbar.ProgressBar
	if totalFiles > 0 && !opts.DryRun {
		// Show progress bar for large archives (>10 files)
		if totalFiles > 10 {
			bar = progressbar.Default(int64(totalFiles), "Extracting")
		}
	}

	// Process each file in the archive
	extractedFiles := 0
	for _, f := range r.File {
		if matchesPattern(f.Name, opts.Pattern, opts.Engine) {
			if opts.Verbose {
				fmt.Printf("Processing %s\n", f.Name)
			}

			if err := extractZIPFile(f, opts); err != nil {
				return &ArchiveError{Op: "extract ZIP file", Err: err}
			}

			// Update progress bar
			if bar != nil && !f.FileInfo().IsDir() {
				extractedFiles++
				bar.Set(extractedFiles)
			}
		}
	}

	// Finish progress bar
	if bar != nil {
		bar.Finish()
		fmt.Println()
	}

	return nil
}

// extractZIPFile extracts a single file from a ZIP archive
func extractZIPFile(f *zip.File, opts *Options) error {
	// Open the file from the archive
	rc, err := f.Open()
	if err != nil {
		return &ArchiveError{Op: "open file in ZIP", Err: err}
	}
	defer rc.Close()

	// Determine output path
	outputPath := filepath.Join(opts.OutputDir, f.Name)
	if opts.Flatten {
		outputPath = filepath.Join(opts.OutputDir, filepath.Base(f.Name))
	}

	// Create directory structure if needed
	if !opts.Flatten && f.FileInfo().IsDir() {
		if opts.DryRun {
			fmt.Printf("[DRY RUN] Would create directory: %s\n", outputPath)
			return nil
		}
		return os.MkdirAll(outputPath, f.Mode())
	}

	// Skip directories for file processing
	if f.FileInfo().IsDir() {
		return nil
	}

	// Check if file exists and handle force option
	if !opts.Force {
		if _, err := os.Stat(outputPath); err == nil {
			if opts.Verbose {
				fmt.Printf("Skipping existing file: %s\n", outputPath)
			}
			return nil
		}
	}

	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return &ArchiveError{Op: "create output directory", Err: err}
	}

	// Handle dry run
	if opts.DryRun {
		fmt.Printf("[DRY RUN] Would extract: %s -> %s\n", f.Name, outputPath)
		return nil
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return &ArchiveError{Op: "create output file", Err: err}
	}
	defer outFile.Close()

	// Copy file contents
	_, err = io.Copy(outFile, rc)
	if err != nil {
		return &ArchiveError{Op: "copy file contents", Err: err}
	}

	// Set file permissions
	if err := os.Chmod(outputPath, f.Mode()); err != nil {
		return &ArchiveError{Op: "set file permissions", Err: err}
	}

	if opts.Verbose {
		fmt.Printf("Extracted: %s -> %s\n", f.Name, outputPath)
	}

	return nil
}

// extractTAR handles TAR archive extraction
func extractTAR(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR file", Err: err}
	}
	defer file.Close()

	return processTAR(file, opts)
}

// extractTARGZ handles .tar.gz archive extraction
func extractTARGZ(archivePath string, opts *Options) error {
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

	return processTAR(gzr, opts)
}

// extractTARBZ2 handles .tar.bz2 archive extraction
func extractTARBZ2(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.BZ2 file", Err: err}
	}
	defer file.Close()

	bz2r := bzip2.NewReader(file)
	return processTAR(bz2r, opts)
}

// extractTARXZ handles .tar.xz archive extraction
func extractTARXZ(archivePath string, opts *Options) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return &ArchiveError{Op: "open TAR.XZ file", Err: err}
	}
	defer file.Close()

	xzr, err := xz.NewReader(file)
	if err != nil {
		return &ArchiveError{Op: "create xz reader", Err: err}
	}

	return processTAR(xzr, opts)
}

// processTAR processes a TAR archive from an io.Reader
func processTAR(reader io.Reader, opts *Options) error {
	tr := tar.NewReader(reader)

	// For progress bar, we need to count files first
	// This is a bit tricky with TAR since we can't easily seek back
	// We'll create a simple counter for large archives

	// Process each file in the archive
	fileCount := 0
	var bar *progressbar.ProgressBar

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return &ArchiveError{Op: "read TAR header", Err: err}
		}

		if matchesPattern(header.Name, opts.Pattern, opts.Engine) {
			// Initialize progress bar after we know we have files to process
			if fileCount == 0 && !opts.DryRun {
				// We'll use a simple counter for TAR since we can't easily count total files
				// Show progress bar for ongoing extraction of large archives
				bar = progressbar.DefaultBytes(-1, "Extracting")
			}

			if opts.Verbose {
				fmt.Printf("Processing %s\n", header.Name)
			}

			if err := extractTARFile(tr, header, opts, bar); err != nil {
				return &ArchiveError{Op: "extract TAR file", Err: err}
			}

			fileCount++
		}
	}

	// Finish progress bar
	if bar != nil {
		bar.Finish()
		fmt.Println()
	}

	return nil
}

// extractTARFile extracts a single file from a TAR archive
func extractTARFile(tr *tar.Reader, header *tar.Header, opts *Options, bar *progressbar.ProgressBar) error {
	// Determine output path
	outputPath := filepath.Join(opts.OutputDir, header.Name)
	if opts.Flatten {
		outputPath = filepath.Join(opts.OutputDir, filepath.Base(header.Name))
	}

	// Handle directories
	if header.Typeflag == tar.TypeDir {
		if opts.DryRun {
			fmt.Printf("[DRY RUN] Would create directory: %s\n", outputPath)
			return nil
		}
		return os.MkdirAll(outputPath, os.FileMode(header.Mode))
	}

	// Skip non-regular files
	if header.Typeflag != tar.TypeReg {
		return nil
	}

	// Check if file exists and handle force option
	if !opts.Force {
		if _, err := os.Stat(outputPath); err == nil {
			if opts.Verbose {
				fmt.Printf("Skipping existing file: %s\n", outputPath)
			}
			return nil
		}
	}

	// Create output directory if needed
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return &ArchiveError{Op: "create output directory", Err: err}
	}

	// Handle dry run
	if opts.DryRun {
		fmt.Printf("[DRY RUN] Would extract: %s -> %s\n", header.Name, outputPath)
		return nil
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return &ArchiveError{Op: "create output file", Err: err}
	}
	defer outFile.Close()

	// Copy file contents
	var writer io.Writer = outFile
	if bar != nil {
		writer = io.MultiWriter(outFile, bar)
	}

	_, err = io.Copy(writer, tr)
	if err != nil {
		return &ArchiveError{Op: "copy file contents", Err: err}
	}

	// Set file permissions
	if err := os.Chmod(outputPath, os.FileMode(header.Mode)); err != nil {
		return &ArchiveError{Op: "set file permissions", Err: err}
	}

	if opts.Verbose {
		fmt.Printf("Extracted: %s -> %s\n", header.Name, outputPath)
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