package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/spf13/cobra"

	"authelia.com/tools/ac/consts"
)

func newConfigCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "config",
		Short: "Perform Config operations",
	}

	cmd.AddCommand(newConfigGenerateCmd(ctx))

	return cmd
}

func newConfigGenerateCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "generate [path]",
		Short: "Generate a config from the templates",
		Args:  cobra.MaximumNArgs(1),
		RunE:  ctx.handleConfigGenerateRunE,
	}

	return cmd
}

func (ctx *cmdctx) handleConfigGenerateRunE(cmd *cobra.Command, args []string) (err error) {
	var pathOut string

	if pathOut, err = ctx.getConfigPathSingle(cmd, args); err != nil {
		switch {
		case errors.Is(err, errConfigNoPath), errors.Is(err, errConfigPathMoreThanOne):
			return fmt.Errorf("error generating config: %w: specifying a path argument will avoid this error", err)
		default:
			return err
		}
	}

	var (
		f    *os.File
		data []byte
	)

	switch ext := filepath.Ext(pathOut); ext {
	case ".json":
		if data, err = internalFS.ReadFile(path.Join("embed", "config", "config.json")); err != nil {
			return err
		}
	case ".yml", ".yaml":
		if data, err = internalFS.ReadFile(path.Join("embed", "config", "config.yaml")); err != nil {
			return err
		}
	case ".tml", ".toml":
		if data, err = internalFS.ReadFile(path.Join("embed", "config", "config.toml")); err != nil {
			return err
		}
	default:
		return fmt.Errorf("error generating config: extension '%s' for file '%s' is not supported", ext, pathOut)
	}

	if f, err = os.OpenFile(pathOut, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640); err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}

	return nil
}

func (ctx *cmdctx) getConfigPathSingle(cmd *cobra.Command, args []string) (path string, err error) {
	if len(args) == 1 {
		return args[0], nil
	}

	var configs []string

	if configs, err = cmd.Flags().GetStringSlice(consts.Config); err != nil {
		return "", err
	}

	switch len(configs) {
	case 0:
		return "", errConfigNoPath
	case 1:
		return configs[0], nil
	default:
		return "", errConfigPathMoreThanOne
	}
}

var (
	errConfigPathMoreThanOne = fmt.Errorf("error determining config output path: nore than one config path specified")
	errConfigNoPath          = fmt.Errorf("error determining config output path: no config paths specified")
)
