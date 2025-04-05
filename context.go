package main

import (
	"authelia.com/tools/ac/store"
	"context"

	"github.com/spf13/cobra"

	"authelia.com/tools/ac/config"
	"authelia.com/tools/ac/consts"
)

type cmdctx struct {
	context.Context

	config  *config.Configuration
	storage *store.Storage
}

func (ctx *cmdctx) handleLoadConfigPreRunE(prefix string) func(cmd *cobra.Command, args []string) (err error) {
	return func(cmd *cobra.Command, args []string) (err error) {
		var (
			configs []string
		)

		if configs, err = cmd.Flags().GetStringSlice(consts.Config); err != nil {
			return err
		}

		if ctx.config, err = config.Load(configs, cmd.Flags(), prefix); err != nil {
			return err
		}

		if err = ctx.config.Validate(); err != nil {
			return err
		}

		switch prefix {
		case consts.OAuth2Bearer:
			if err = ctx.config.OAuth2.Bearer.Validate(); err != nil {
				return err
			}
		}

		if ctx.storage, err = store.Load(ctx.config.Storage); err != nil {
			return err
		}

		return nil
	}
}
