package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "rachel_layers",
	Short: "Rachel Layers gets vulnerabilities for a specific image without it's base image vulnerabilities using RachelAnalyzer",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func fail(err error) {
	fmt.Println(err)
	os.Exit(1)
}
