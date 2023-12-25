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
  - [RFC9207: OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207) 
  - [RFC9101: OAuth 2.0 JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)
  - [OAuth 2.0 JWT-Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html)
- [ ] Versioning.