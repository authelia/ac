package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"authelia.com/tools/ac/config"
	"authelia.com/tools/ac/consts"
	"authelia.com/tools/ac/utilities"
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

	cmd.Flags().String("name", "example", "Name for the example client")

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

	name, err := cmd.Flags().GetString("name")
	if err != nil {
		return err
	}

	rawAutheliaURL, err := cmd.Flags().GetString("authelia-url")
	if err != nil {
		return err
	}

	if len(rawAutheliaURL) == 0 {
		rawAutheliaURL = "https://auth.example.com"
	}

	autheliaURL, err := url.Parse(rawAutheliaURL)
	if err != nil {
		return err
	}

	id, err := utilities.GetRandomBytes(80, utilities.CharsetAlphaNumeric)
	if err != nil {
		return fmt.Errorf("error generating config: error generating client id: %w", err)
	}

	secret, err := utilities.GetRandomBytes(100, utilities.CharsetAlphaNumeric)
	if err != nil {
		return fmt.Errorf("error generating config: error generating client secret: %w", err)
	}

	c := &config.Configuration{
		AutheliaURL: config.NewURL(autheliaURL),
		Storage:     "storage.yml",
		OAuth2: config.OAuth2{
			DefaultClient: name,
			Clients: map[string]config.OAuth2Client{
				name: {
					ID:                      string(id),
					Secret:                  string(secret),
					PAR:                     true,
					Scope:                   []string{"offline_access", "authelia.bearer.authz"},
					Audience:                []string{"https://app.example.com"},
					GrantType:               "authorization_code",
					TokenEndpointAuthMethod: "client_secret_post",
					OfflineAccess:           true,
				},
			},
		},
		Server: config.Server{
			Port: 9091,
		},
	}

	var (
		f    *os.File
		data []byte
	)

	if data, err = utilities.AutoMarshal(c, filepath.Ext(pathOut)); err != nil {
		return fmt.Errorf("error generating config: %w", err)
	}

	if f, err = os.OpenFile(pathOut, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0640); err != nil {
		return err
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		return err
	}

	_, _ = fmt.Fprintf(os.Stdout, "\nGenerated config: %s\n", pathOut)

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
