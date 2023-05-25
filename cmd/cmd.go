package cmd

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {

	otoken := &cobra.Command{
		Use:   "otoken",
		Short: "otken is a cli to get oauth2 access token",
	}

	addAppAuth(otoken)
	addDevAuth(otoken)

	return otoken
}
