package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/arc-tool/internal/tester"
)

var (
	testVerbose bool
	testCmd = &cobra.Command{
		Use:   "test [archive]",
		Short: "Test archive integrity",
		Long: `Test the integrity of an archive file.
If reading from stdin, use "-" as the archive path.`,
		Aliases: []string{"t"},
		Args:    cobra.ExactArgs(1),
		RunE:    runTest,
	}
)

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().BoolVarP(&testVerbose, "verbose", "v", false, "Verbose output")
}

func runTest(cmd *cobra.Command, args []string) error {
	archivePath := args[0]

	// Prepare tester options
	opts := &tester.Options{
		Verbose: testVerbose,
	}

	// Handle stdin input
	if archivePath == "-" {
		return tester.TestFromStdin(opts)
	}

	// Validate archive file
	if _, err := os.Stat(archivePath); os.IsNotExist(err) {
		return fmt.Errorf("archive file does not exist: %s", archivePath)
	}

	// Test archive integrity
	return tester.Test(archivePath, opts)
}