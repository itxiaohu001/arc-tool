package cmd

import (
	"fmt"
	"os"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/user/arc-tool/internal/listener"
)

var (
	listPattern string
	listEngine  string
	listVerbose bool
	listCmd = &cobra.Command{
		Use:   "list [archive]",
		Short: "List files in an archive",
		Long: `List files in an archive that match the specified pattern.
The pattern can be a Glob pattern (default) or a Regex pattern.
If reading from stdin, use "-" as the archive path.`,
		Aliases: []string{"l"},
		Args:    cobra.ExactArgs(1),
		RunE:    runList,
	}
)

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVarP(&listPattern, "pattern", "p", "*", "Pattern to match files (Glob or Regex)")
	listCmd.Flags().StringVar(&listEngine, "engine", "glob", "Pattern engine: glob or regex")
	listCmd.Flags().BoolVarP(&listVerbose, "verbose", "v", false, "Verbose output")

	// Mark pattern as required
	listCmd.MarkFlagRequired("pattern")
}

func runList(cmd *cobra.Command, args []string) error {
	archivePath := args[0]

	// Validate engine
	if listEngine != "glob" && listEngine != "regex" {
		return fmt.Errorf("invalid engine: %s, must be 'glob' or 'regex'", listEngine)
	}

	// Validate regex pattern if using regex engine
	if listEngine == "regex" {
		if _, err := regexp.Compile(listPattern); err != nil {
			return fmt.Errorf("invalid regex pattern: %v", err)
		}
	}

	// Prepare listener options
	opts := &listener.Options{
		Pattern: listPattern,
		Engine:  listEngine,
		Verbose: listVerbose,
	}

	// Handle stdin input
	if archivePath == "-" {
		return listener.ListFromStdin(opts)
	}

	// Validate archive file
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("archive file does not exist: %s", archivePath)
	}

	// List archive contents
	return listener.List(archivePath, opts)
}