package cmd

import "github.com/spf13/cobra"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:          "iping",
		Short:        "Ping hosts using various protocols",
		SilenceUsage: true,
	}
	root.AddCommand(newTCPCmd(), newTLSCmd())
	return root
}
