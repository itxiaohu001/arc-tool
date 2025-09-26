package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "arc-tool",
	Short: "A powerful archive tool for extracting, listing, and testing various archive formats",
	Long: `arc-tool is a CLI tool that can extract, list, and test various archive formats
including ZIP, TAR, and compressed TAR files (.tar.gz, .tar.bz2, .tar.xz).
It supports pattern matching with both Glob and Regex engines.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}