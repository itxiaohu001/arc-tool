# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a powerful command-line tool called `arc-tool` for handling various archive formats with advanced extraction capabilities. The tool can extract, list, and test archive files with support for pattern matching using both Glob and Regex engines.

## Code Architecture

The project follows a modular architecture with the following structure:

### Main Components

1. **Main Entry Point** (`main.go`) - Initializes and executes the CLI
2. **CLI Layer** (`cmd/`) - Contains Cobra command definitions for:
   - `extract` (or `x`) - Extract files from archives
   - `list` (or `l`) - List files in archives
   - `test` (or `t`) - Test archive integrity
3. **Business Logic Layer** (`internal/`) - Contains core functionality:
   - `extractor/` - Archive extraction logic
   - `listener/` - Archive listing logic
   - `tester/` - Archive integrity testing logic

### Supported Formats

- ZIP archives
- TAR archives
- Compressed TAR formats: .tar.gz, .tar.bz2, .tar.xz

### Key Features

- File pattern matching with Glob (default) and Regex engines
- Output directory specification with flatten option
- Force overwrite capability
- Verbose output and dry-run modes
- Progress bars for large archives
- stdin support for all operations
- Comprehensive error handling with custom error types

## Common Development Tasks

### Building the Project

```bash
cd arc-tool
go build -o arc-tool .
```

### Adding a New Feature

1. Define new command flags in the appropriate file in `cmd/`
2. Implement the core logic in the corresponding package in `internal/`
3. Add any new dependencies with `go get`
4. Test the feature by building and running the tool

### Testing the Application

Create test archives and run commands like:
```bash
# Extract files matching a pattern
./arc-tool extract -p "*.txt" archive.zip

# List files with verbose output
./arc-tool list -v -p "*.go" archive.tar.gz

# Test archive integrity
./arc-tool test archive.zip
```

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `github.com/schollz/progressbar/v3` - Progress bar UI
- `github.com/ulikunitz/xz` - XZ compression support
- Standard library packages for archive handling (`archive/zip`, `archive/tar`, `compress/gzip`, `compress/bzip2`)