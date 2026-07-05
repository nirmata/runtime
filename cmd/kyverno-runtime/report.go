package main

import (
	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Report command (placeholder)",
	RunE:  runReport,
}

func runReport(cmd *cobra.Command, args []string) error {
	// TODO: Implement report command
	return nil
}
