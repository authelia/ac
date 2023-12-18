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
	"gopkg.in/yaml.v3"
)

func newOAuth2Cmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "oauth2",
		Short: "Perform OAuth 2.0 operations",
	}

	cmd.AddCommand(newOAuth2BearerCmd(ctx))

	return cmd
}

func newOAuth2BearerCmd(ctx *cmdctx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:     "bearer",
		Short:   "Request a bearer token via OAuth 2.0",
		PreRunE: ctx.handleLoadConfigPreRunE(strOAuth2Bearer),
		RunE:    ctx.handleOAuth2BearerRunE,
	}

	cmd.Flags().String(strID, "", "The client id")
	cmd.Flags().String(strSecret, "", "The client secret")
	cmd.Flags().String("grant-type", strAuthorizationCode, "The grant type to use which dictates the flow, options are 'authorization_code', 'client_credentials', or 'refresh_token'")
	cmd.Flags().StringSlice(strScope, nil, "The scopes to request")
	cmd.Flags().StringSlice(strAudience, nil, "The audience to request")
	cmd.Flags().Bool("offline-access", false, "In addition to the scopes automatically includes the scope required for a Refresh Token for the Authorization Code FLow")
	cmd.Flags().String("token-endpoint-auth-method", strClientSecretPost, "The authentication method for the token endpoint, options are 'none', 'client_secret_post', and 'client_secret_basic'")
	cmd.Flags().Bool("par", false, "Perform RFC916 Pushed Authorization Requests for the Authorization Code Flow")

	return cmd
}

func (ctx *cmdctx) handleOAuth2BearerRunE(cmd *cobra.Command, args []string) (err error) {
	switch ctx.config.OAuth2.Bearer.GrantType {
	case strAuthorizationCode:
		return ctx.handleOAuth2BearerAuthorizationCodeFlowRunE(cmd, args)
	case strClientCredentials:
		return ctx.handleOAuth2BearerClientCredentialsFlowRunE(cmd, args)
	case strRefreshToken:
		return ctx.handleOAuth2BearerRefreshTokenFlowRunE(cmd, args)
	default:
		return fmt.Errorf("error occurred performing flow: uknonwn grant type '%s'", ctx.config.OAuth2.Bearer.GrantType)
	}
}

func (ctx *cmdctx) handleOAuth2BearerAuthorizationCodeFlowRunE(cmd *cobra.Command, args []string) (err error) {
	state, err := getRandomBytes(100, charsetRFC3986Unreserved)
	if err != nil {
		return fmt.Errorf("error occurred generating state value: %w", err)
	}

	pkce, err := oauth2.NewPKCE()
	if err != nil {
		return fmt.Errorf("error occurred generating PKCE: %w", err)
	}

	config := handleGetConfig(ctx.config)

	var authURL *url.URL

	opts := []oauth2.AuthCodeOption{
		pkce.AuthCodeOptionChallenge(),
		oauth2.SetAuthURLParam(strAudience, strings.Join(ctx.config.OAuth2.Bearer.Audience, " ")),
		oauth2.SetAuthURLParam(strResponseMode, strFormPost),
	}

	if ctx.config.OAuth2.Bearer.PAR {
		if authURL, _, err = config.PushedAuth(ctx, string(state), opts...); err != nil {
			return fmt.Errorf("error occurred performing pushed authorization request: %w", err)
		}
	} else {
		if authURL, err = config.ParsedAuthCodeURL(string(state), opts...); err != nil {
			return fmt.Errorf("error occurred obtaining authorization request uri: %w", err)
		}
	}

	fmt.Printf("Visit the following URL to provide consent: %s\n", authURL)

	var r *http.Request

	if r, err = handleCallback("localhost:9019", "POST", "/callback"); err != nil {
		return fmt.Errorf("error occurred handling callback: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(r.FormValue(strState)), state) == 0 {
		return fmt.Errorf("error occurred handling callback: the state parameter did not match")
	}

	return ctx.handleTokenRetrieved(config.Exchange(ctx, r.FormValue(strCode), pkce.AuthCodeOptionVerifier()))
}

func (ctx *cmdctx) handleOAuth2BearerClientCredentialsFlowRunE(cmd *cobra.Command, args []string) (err error) {
	params := url.Values{}

	params.Set(strAudience, strings.Join(ctx.config.OAuth2.Bearer.Audience, " "))
	params.Set("redirect_uri", "https://localhost:9019/callback")

	config := &clientcredentials.Config{
		ClientID:       ctx.config.OAuth2.Bearer.ID,
		ClientSecret:   ctx.config.OAuth2.Bearer.Secret,
		TokenURL:       endpoints.Authelia(ctx.config.AutheliaURL.String()).TokenURL,
		Scopes:         ctx.config.OAuth2.Bearer.Scope,
		EndpointParams: params,
		AuthStyle:      oauth2.ClientSecretPost,
	}

	return ctx.handleTokenRetrieved(config.Token(ctx))
}

func (ctx *cmdctx) handleOAuth2BearerRefreshTokenFlowRunE(cmd *cobra.Command, args []string) (err error) {
	var (
		store TokenStore
		ok    bool
	)

	if store, ok = ctx.storage.Tokens[ctx.config.OAuth2.Bearer.ID]; !ok || len(store.RefreshToken) == 0 {
		return fmt.Errorf("The Refresh Token Flow requires a stored refresh token for the client but none was found.")
	}

	config := handleGetConfig(ctx.config)

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam(strAudience, strings.Join(ctx.config.OAuth2.Bearer.Audience, " ")),
		oauth2.SetAuthURLParam(strResponseMode, strFormPost),
		oauth2.SetAuthURLParam(strGrantType, strRefreshToken),
		oauth2.SetAuthURLParam(strRefreshToken, store.RefreshToken),
	}

	scope := strings.Join(config.Scopes, " ")

	if store.Scope != scope {
		opts = append(opts, oauth2.SetAuthURLParam(strScope, scope))
	}

	return ctx.handleTokenRetrieved(config.Token(ctx, opts...))
}

func handleGetConfig(config *Schema) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     config.OAuth2.Bearer.ID,
		ClientSecret: config.OAuth2.Bearer.Secret,
		Endpoint:     endpoints.Authelia(config.AutheliaURL.String()),
		RedirectURL:  "http://localhost:9019/callback",
		Scopes:       config.OAuth2.Bearer.Scope,
	}
}

func (ctx *cmdctx) handleTokenRetrieved(token *oauth2.Token, err error) error {
	if err != nil {
		return fmt.Errorf("error occurred retrieving token: %w", err)
	}

	store := TokenStore{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      handleTokenGetString("id_token", token),
		TokenType:    token.Type(),
		Scope:        handleTokenGetString(strScope, token),
		Expiry:       token.Expiry,
	}

	var extras []string

	if len(store.RefreshToken) != 0 {
		extras = append(extras, "Refresh Token")
	}

	if len(store.IDToken) != 0 {
		extras = append(extras, "ID Token")
	}

	fmt.Printf("\n\nToken retrieval sucessful.\n\n\tAccess Token: %s\n\tType: %s\n\tScope: %s\n\tExpires: %s\n", store.AccessToken, store.TokenType, store.Scope, store.Expiry)

	if len(extras) != 0 {
		fmt.Printf("\tExtra Tokens: %s\n", strings.Join(extras, ", "))
	}

	fmt.Println()

	ctx.storage.Tokens[ctx.config.OAuth2.Bearer.ID] = store

	data, err := yaml.Marshal(ctx.storage)
	if err != nil {
		return fmt.Errorf("error occurred attempting to marshal the updated storage to store the retrieved tokens: %w", err)
	}

	if err = os.WriteFile(ctx.config.Storage, data, 0600); err != nil {
		return fmt.Errorf("error occurred attempting to store the retrieved tokens: %w", err)
	}

	return nil
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
