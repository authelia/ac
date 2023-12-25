## Install

1. Install the latest version of [golang](https://go.dev/) for your operating system.
2. Use the `go install authelia.com/tools/ac` command to install the `ac` command to your go bin directory.
3. Run `go env` and add the `${GOPATH}/bin` env to your systems search path variable (usually `PATH`).

## TODO

- [ ] Documentation.
- [ ] Automatic / Prompted Refresh.
- [ ] Embed example configuration.
- [ ] Simple Refresh Token requests.
- Support for:
  - [RFC7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
  - [RFC7009: OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
  - [RFC7523: OAuth 2.0 JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)
  - [RFC7521: OAuth 2.0 Assertion Framework for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)
  - [RFC9207: OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207) 
  - [RFC9101: OAuth 2.0 JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)
  - [OAuth 2.0 JWT-Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html)
- [ ] Versioning.