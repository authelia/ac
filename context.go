package main

import (
	"context"

	"github.com/spf13/cobra"
)

type cmdctx struct {
	context.Context

	config  *Schema
	storage *Store
}

func (ctx *cmdctx) handleLoadConfigPreRunE(prefix string) func(cmd *cobra.Command, args []string) (err error) {
	return func(cmd *cobra.Command, args []string) (err error) {
		var (
			config string
		)

		if config, err = cmd.Flags().GetString(strConfig); err != nil {
			return err
		}

		if ctx.config, err = loadConfig(config, cmd.Flags(), prefix); err != nil {
			return err
		}

		if err = ctx.config.validate(); err != nil {
			return err
		}

		switch prefix {
		case strOAuth2Bearer:
			if err = ctx.config.OAuth2.Bearer.validate(); err != nil {
				return err
			}
		}

		if ctx.storage, err = loadStorage(ctx.config.Storage); err != nil {
			return err
		}

		return nil
	}
}
