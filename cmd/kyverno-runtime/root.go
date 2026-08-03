package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kyverno-runtime",
	Short: "Nirmata Runtime",
	Long:  "Nirmata Runtime - a runtime policy enforcement engine",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(daemonCmd)
}
