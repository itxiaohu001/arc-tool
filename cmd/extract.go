package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/user/arc-tool/internal/extractor"
)

var (
	pattern      string
	engine       string
	outputDir    string
	flatten      bool
	force        bool
	verbose      bool
	dryRun       bool
	extractCmd = &cobra.Command{
		Use:   "extract [archive]",
		Short: "Extract files from an archive",
		Long: `Extract files from an archive that match the specified pattern.
The pattern can be a Glob pattern (default) or a Regex pattern.
If reading from stdin, use "-" as the archive path.`,
		Aliases: []string{"x"},
		Args:    cobra.ExactArgs(1),
		RunE:    runExtract,
	}
)

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.Flags().StringVarP(&pattern, "pattern", "p", "*", "Pattern to match files (Glob or Regex)")
	extractCmd.Flags().StringVar(&engine, "engine", "glob", "Pattern engine: glob or regex")
	extractCmd.Flags().StringVarP(&outputDir, "output", "o", ".", "Output directory")
	extractCmd.Flags().BoolVar(&flatten, "flatten", false, "Flatten directory structure")
	extractCmd.Flags().BoolVarP(&force, "force", "f", false, "Force overwrite existing files")
	extractCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	extractCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be extracted without actually doing it")

	// Mark pattern as required
	extractCmd.MarkFlagRequired("pattern")
}

func runExtract(cmd *cobra.Command, args []string) error {
	archivePath := args[0]

	// Validate engine
	if engine != "glob" && engine != "regex" {
		return fmt.Errorf("invalid engine: %s, must be 'glob' or 'regex'", engine)
	}

	// Validate regex pattern if using regex engine
	if engine == "regex" {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %v", err)
		}
	}

	// Validate output directory
	if outputDir == "" {
		outputDir = "."
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Get absolute path for output directory
	absOutputDir, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for output directory: %v", err)
	}

	// Prepare extractor options
	opts := &extractor.Options{
		Pattern:     pattern,
		Engine:      engine,
		OutputDir:   absOutputDir,
		Flatten:     flatten,
		Force:       force,
		Verbose:     verbose,
		DryRun:      dryRun,
	}

	// Handle stdin input
	if archivePath == "-" {
		return extractor.ExtractFromStdin(opts)
	}

	// Validate archive file
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("archive file does not exist: %s", archivePath)
	}

	// Extract archive
	if verbose {
		fmt.Printf("Extracting from %s...\n", archivePath)
	}

	return extractor.Extract(archivePath, opts)
}