package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"authelia.com/client/oauth2"
	"authelia.com/client/oauth2/clientcredentials"
	"authelia.com/client/oauth2/endpoints"
	"github.com/spf13/cobra"

	"authelia.com/tools/ac/config"
	"authelia.com/tools/ac/consts"
	"authelia.com/tools/ac/store"
	"authelia.com/tools/ac/utilities"
)

func newOAuth2Cmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "oauth2",
		Short: "Perform OAuth 2.0 operations",
	}

	cmd.AddCommand(
		newOAuth2ClientCmd(ctx),
		newOAuth2RequestCmd(ctx),
		newOAuth2RefreshCmd(ctx),
		newOAuth2RevokeCmd(ctx),
	)

	return cmd
}

func newOAuth2ClientCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "client",
		Short: "Perform OAuth 2.0 client operations",
	}

	cmd.AddCommand(
		newOAuth2ClientDefaultCmd(ctx),
		newOAuth2ClientNewCmd(ctx),
	)

	return cmd
}

func newOAuth2ClientNewCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "new <name>",
		Short:   "Create a new OAuth 2.0 client",
		PreRunE: ctx.handleLoadConfigPreRunE(consts.OAuth2),
		RunE:    ctx.handleOAuth2ClientNewRunE,
		Args:    cobra.ExactArgs(1),
	}

	cmd.Flags().Bool("par", true, "use pushed auth requests")
	cmd.Flags().StringSlice("audience", []string{"https://app.example.com"}, "requested audience")
	cmd.Flags().StringSlice("scope", []string{"authelia.bearer.authz"}, "requested scopes")
	cmd.Flags().String("grant-type", "authorization_code", "requested grant type")
	cmd.Flags().String("token-endpoint-auth-method", "client_secret_post", "authentication method for the token endpoint")
	cmd.Flags().Bool("offline-access", false, "enables refresh tokens")
	cmd.Flags().Bool("default", false, "sets this client as the default")

	return cmd
}

func (ctx *cmdctx) handleOAuth2ClientNewRunE(cmd *cobra.Command, args []string) (err error) {
	var pathOut string

	if pathOut, err = ctx.getConfigPathSingle(cmd, nil); err != nil {
		switch {
		case errors.Is(err, errConfigNoPath), errors.Is(err, errConfigPathMoreThanOne):
			return fmt.Errorf("error updating config: %w: specifying a config argument will avoid this error", err)
		default:
			return err
		}
	}

	name := args[0]

	if _, ok := ctx.config.OAuth2.Clients[name]; ok {
		return fmt.Errorf("error creating a new oauth2 client: client '%s' already exists", name)
	}

	id, err := utilities.GetRandomBytes(80, utilities.CharsetAlphaNumeric)
	if err != nil {
		return fmt.Errorf("error generating config: error generating client id: %w", err)
	}

	secret, err := utilities.GetRandomBytes(100, utilities.CharsetAlphaNumeric)
	if err != nil {
		return fmt.Errorf("error generating config: error generating client secret: %w", err)
	}

	var (
		par, offline          bool
		audience, scope       []string
		grantType, authMethod string
	)

	if par, err = cmd.Flags().GetBool("par"); err != nil {
		return err
	}

	if offline, err = cmd.Flags().GetBool("offline-access"); err != nil {
		return err
	}

	if audience, err = cmd.Flags().GetStringSlice("audience"); err != nil {
		return err
	}

	if scope, err = cmd.Flags().GetStringSlice("scope"); err != nil {
		return err
	}

	if grantType, err = cmd.Flags().GetString("grant-type"); err != nil {
		return err
	}

	if authMethod, err = cmd.Flags().GetString("token-endpoint-auth-method"); err != nil {
		return err
	}

	if offline && !utilities.IsStringInSlice("offline_access", scope) {
		scope = append(scope, "offline_access")
	}

	client := config.OAuth2Client{
		ID:                      string(id),
		Secret:                  string(secret),
		PAR:                     par,
		Audience:                audience,
		Scope:                   scope,
		GrantType:               grantType,
		TokenEndpointAuthMethod: authMethod,
		OfflineAccess:           offline,
	}

	ctx.config.OAuth2.Clients[name] = client

	if isDefault, err := cmd.Flags().GetBool("default"); err == nil && isDefault {
		ctx.config.OAuth2.DefaultClient = name
	}

	return ctx.config.Save(pathOut)
}

func newOAuth2ClientDefaultCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "default <name>",
		Short:   "Set the default OAuth 2.0 client",
		PreRunE: ctx.handleLoadConfigPreRunE(consts.OAuth2),
		RunE:    ctx.handleOAuth2ClientDefaultRunE,
		Args:    cobra.ExactArgs(1),
	}

	return cmd
}

func (ctx *cmdctx) handleOAuth2ClientDefaultRunE(cmd *cobra.Command, args []string) (err error) {
	var pathOut string

	if pathOut, err = ctx.getConfigPathSingle(cmd, nil); err != nil {
		switch {
		case errors.Is(err, errConfigNoPath), errors.Is(err, errConfigPathMoreThanOne):
			return fmt.Errorf("error updating config: %w: specifying a config argument will avoid this error", err)
		default:
			return err
		}
	}

	if _, ok := ctx.config.OAuth2.Clients[args[0]]; !ok {
		return fmt.Errorf("error setting the default oauth2 client: client '%s' does not exist", args[0])
	}

	ctx.config.OAuth2.DefaultClient = args[0]

	return ctx.config.Save(pathOut)
}

func newOAuth2RequestCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "request [name]",
		Short:   "Request a bearer token via OAuth 2.0",
		PreRunE: ctx.handleLoadConfigPreRunE(consts.OAuth2),
		RunE:    ctx.handleOAuth2RequestRunE,
		Args:    cobra.MaximumNArgs(1),
	}

	return cmd
}

func (ctx *cmdctx) handleOAuth2RequestRunE(cmd *cobra.Command, args []string) (err error) {
	var name string

	if len(args) != 0 {
		name = args[0]
	} else {
		name = ctx.config.OAuth2.DefaultClient
	}

	if len(name) == 0 {
		return fmt.Errorf("no oauth2 client specified")
	}

	client, ok := ctx.config.OAuth2.Clients[name]

	if !ok {
		return fmt.Errorf("no oauth2 client '%s' doesn't exist", name)
	}

	switch client.GrantType {
	case consts.AuthorizationCode:
		return ctx.handleOAuth2BearerAuthorizationCodeFlowSubRunE(name, client)
	case consts.ClientCredentials:
		return ctx.handleOAuth2BearerClientCredentialsFlowSubRunE(name, client)
	case consts.RefreshToken:
		return ctx.handleOAuth2BearerRefreshTokenFlowSubRunE(name, client)
	default:
		return fmt.Errorf("error occurred performing flow: uknonwn grant type '%s'", client.GrantType)
	}
}

func (ctx *cmdctx) handleOAuth2BearerAuthorizationCodeFlowSubRunE(name string, client config.OAuth2Client) (err error) {
	state, err := utilities.GetRandomBytes(100, utilities.CharsetRFC3986Unreserved)
	if err != nil {
		return fmt.Errorf("error occurred generating state value: %w", err)
	}

	pkce, err := oauth2.NewPKCE()
	if err != nil {
		return fmt.Errorf("error occurred generating PKCE: %w", err)
	}

	config := handleGetConfig(ctx.config, client)

	var authURL *url.URL

	opts := []oauth2.AuthCodeOption{
		pkce.AuthCodeOptionChallenge(),
		oauth2.SetAuthURLParam(consts.Audience, strings.Join(client.Audience, " ")),
		oauth2.SetAuthURLParam(consts.ResponseMode, consts.FormPost),
	}

	if client.PAR {
		if authURL, _, err = config.PushedAuth(ctx, string(state), opts...); err != nil {
			return fmt.Errorf("error occurred performing pushed authorization request: %w", err)
		}
	} else {
		if authURL, err = config.ParsedAuthCodeURL(string(state), opts...); err != nil {
			return fmt.Errorf("error occurred obtaining authorization request uri: %w", err)
		}
	}

	_, _ = fmt.Fprintf(os.Stdout, "Visit the following URL to provide consent: %s\n", authURL)

	var r *http.Request

	if r, err = handleCallback(fmt.Sprintf("localhost:%d", ctx.config.Server.Port), "POST", "/callback"); err != nil {
		return fmt.Errorf("error occurred handling callback: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(r.FormValue(consts.State)), state) == 0 {
		return fmt.Errorf("error occurred handling callback: the state parameter did not match")
	}

	return ctx.handleTokenRetrieved(name, client)(config.Exchange(ctx, r.FormValue(consts.Code), pkce.AuthCodeOptionVerifier()))
}

func (ctx *cmdctx) handleOAuth2BearerClientCredentialsFlowSubRunE(name string, client config.OAuth2Client) (err error) {
	params := url.Values{}

	params.Set(consts.Audience, strings.Join(client.Audience, " "))
	params.Set(consts.RedirectURI, fmt.Sprintf("https://localhost:%d/callback", ctx.config.Server.Port))

	config := &clientcredentials.Config{
		ClientID:       client.ID,
		ClientSecret:   client.Secret,
		TokenURL:       endpoints.Authelia((*url.URL)(ctx.config.AutheliaURL)).TokenURL,
		Scopes:         client.Scope,
		EndpointParams: params,
		AuthStyle:      oauth2.ClientSecretPost,
	}

	return ctx.handleTokenRetrieved(name, client)(config.Token(ctx))
}

func newOAuth2RefreshCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "refresh [name]",
		Short:   "Refresh a bearer token via OAuth 2.0",
		PreRunE: ctx.handleLoadConfigPreRunE(consts.OAuth2),
		RunE:    ctx.handleOAuth2RefreshRunE,
		Args:    cobra.MaximumNArgs(1),
	}

	return cmd
}

func (ctx *cmdctx) handleOAuth2RefreshRunE(cmd *cobra.Command, args []string) (err error) {
	var name string

	if len(args) != 0 {
		name = args[0]
	} else {
		name = ctx.config.OAuth2.DefaultClient
	}

	if len(name) == 0 {
		return fmt.Errorf("no oauth2 client specified")
	}

	client, ok := ctx.config.OAuth2.Clients[name]

	if !ok {
		return fmt.Errorf("no oauth2 client '%s' doesn't exist", name)
	}

	return ctx.handleOAuth2BearerRefreshTokenFlowSubRunE(name, client)
}

func newOAuth2RevokeCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "revoke [name]",
		Short:   "Revoke a bearer token via OAuth 2.0",
		PreRunE: ctx.handleLoadConfigPreRunE(consts.OAuth2),
		RunE:    ctx.handleOAuth2RevokeRunE,
		Args:    cobra.MaximumNArgs(1),
	}

	return cmd
}

func (ctx *cmdctx) handleOAuth2RevokeRunE(cmd *cobra.Command, args []string) (err error) {
	var name string

	if len(args) != 0 {
		name = args[0]
	} else {
		name = ctx.config.OAuth2.DefaultClient
	}

	if len(name) == 0 {
		return fmt.Errorf("no oauth2 client specified")
	}

	client, ok := ctx.config.OAuth2.Clients[name]

	if !ok {
		return fmt.Errorf("no oauth2 client '%s' doesn't exist", name)
	}

	var (
		token store.Token
	)

	if token, ok = ctx.storage.Tokens[name]; !ok || (len(token.RefreshToken) == 0 && len(token.AccessToken) == 0) {
		return fmt.Errorf("The Revoke Token Flow requires a stored token for the client but none was found.")
	}

	config := handleGetConfig(ctx.config, client)

	var opts []oauth2.RevocationOption

	t := &oauth2.Token{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		Expiry:       token.Expiry,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
	}

	if err = config.RevokeToken(ctx, t, opts...); err != nil {
		return err
	}

	delete(ctx.storage.Tokens, name)

	if err = ctx.storage.Save(ctx.config.Storage); err != nil {
		return fmt.Errorf("error occurred saving updated tokens: %w", err)
	}

	return nil
}

func (ctx *cmdctx) handleOAuth2BearerRefreshTokenFlowSubRunE(name string, client config.OAuth2Client) (err error) {
	var (
		token store.Token
		ok    bool
	)

	if token, ok = ctx.storage.Tokens[name]; !ok || len(token.RefreshToken) == 0 {
		return fmt.Errorf("The Refresh Token Flow requires a stored refresh token for the client but none was found.")
	}

	config := handleGetConfig(ctx.config, client)

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(consts.Audience, strings.Join(client.Audience, " ")),
		oauth2.SetAuthURLParam(consts.ResponseMode, consts.FormPost),
		oauth2.SetAuthURLParam(consts.GrantType, consts.RefreshToken),
		oauth2.SetAuthURLParam(consts.RefreshToken, token.RefreshToken),
	}

	scope := strings.Join(config.Scopes, " ")

	if token.Scope != scope {
		opts = append(opts, oauth2.SetAuthURLParam(consts.Scope, scope))
	}

	return ctx.handleTokenRetrieved(name, client)(config.Token(ctx, opts...))
}

func handleGetConfig(config *config.Configuration, client config.OAuth2Client) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     client.ID,
		ClientSecret: client.Secret,
		Endpoint:     endpoints.Authelia((*url.URL)(config.AutheliaURL)),
		RedirectURL:  fmt.Sprintf("http://localhost:%d/callback", config.Server.Port),
		Scopes:       client.Scope,
	}
}

func (ctx *cmdctx) handleTokenRetrieved(name string, client config.OAuth2Client) func(token *oauth2.Token, err error) error {
	return func(token *oauth2.Token, err error) error {
		if err != nil {
			return fmt.Errorf("error occurred retrieving token: %w", err)
		}

		tokenstore := store.Token{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			IDToken:      token.IDToken,
			TokenType:    token.Type(),
			Scope:        handleTokenGetString(consts.Scope, token),
			Expiry:       token.Expiry,
		}

		var extras []string

		if len(tokenstore.RefreshToken) != 0 {
			extras = append(extras, "Refresh Token")
		}

		if len(tokenstore.IDToken) != 0 {
			extras = append(extras, "ID Token")
		}

		_, _ = fmt.Fprintf(os.Stdout, "\n\nToken retrieval sucessful.\n\n\tAccess Token: %s\n\tType: %s\n\tScope: %s\n\tExpires: %s\n", tokenstore.AccessToken, tokenstore.TokenType, tokenstore.Scope, tokenstore.Expiry)

		if len(extras) != 0 {
			_, _ = fmt.Fprintf(os.Stdout, "\tExtra Tokens: %s\n", strings.Join(extras, ", "))
		}

		_, _ = fmt.Fprintf(os.Stdout, "\n")

		ctx.storage.Tokens[name] = tokenstore

		if err = ctx.storage.Save(ctx.config.Storage); err != nil {
			return fmt.Errorf("error occurred saving updated tokens: %w", err)
		}

		return nil
	}
}

func handleCallback(addr, method, path string) (req *http.Request, err error) {
	server := &http.Server{
		Addr: addr,
	}

	http.HandleFunc(path, func(wr http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			return
		}

		r.ParseMultipartForm(1 << 20)

		req = r

		wr.Write([]byte("OK"))

		go func() {
			_ = server.Shutdown(context.Background())
		}()
	})

	if err = server.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return req, nil
		}

		return nil, fmt.Errorf("error occurred listening: %w", err)
	}

	return
}

func handleTokenGetString(key string, token *oauth2.Token) string {
	if value, ok := token.Extra(key).(string); ok {
		return value
	}

	return ""
}
