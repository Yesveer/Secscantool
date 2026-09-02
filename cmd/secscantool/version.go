package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the secscantool version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("secscantool " + version)
	},
}
