package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"authelia.com/tools/ac/consts"
)

func main() {
	ctx := &cmdctx{
		Context: context.Background(),
	}

	cmd := &cobra.Command{
		Use:   "ac",
		Short: "The Authelia CLI",
	}

	cmd.PersistentFlags().StringSlice(consts.Config, []string{"config.yml"}, "path to the configuration files")
	cmd.PersistentFlags().String("storage", "storage.yml", "path to the storage file")
	cmd.PersistentFlags().String("authelia-url", "", "authelia root url to use for all commands")

	cmd.AddCommand(
		newConfigCmd(ctx),
		newOAuth2Cmd(ctx),
	)

	if err := cmd.Execute(); err != nil {
		fmt.Println(err.Error())
	}
}
