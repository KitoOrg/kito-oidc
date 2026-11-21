# kito-oidc

Signing in to a [Kito](https://github.com/KitoOrg/kito) server with
OpenID Connect: your organization's own sign-on (Google, Okta, Microsoft
Entra, Keycloak, Auth0 and the like). A plugin of the server: it says
who somebody is, and nothing else. Who may use which repository, and
what they may do there, stays the server's.

```console
$ kito-server oidc setup https://accounts.google.com 1234.apps.googleusercontent.com --secret-from secret.txt
$ kito-server user add bob --identity oidc:bob@example.com --role write
bob added: whoever signs in as oidc:bob@example.com is bob. No token.

$ kito connect kito.example.com:7421 shop --sign-in oidc --fingerprint sha256:…
To sign in with oidc, open https://www.google.com/device
and enter the code ABCD-EFGH
Waiting until you have...
shop is connected to `shop` on kito.example.com:7421 as bob.
```

In a browser, `https://<the server>/-/sign-in/oidc` goes to the provider
and comes back signed in.

## Setting it up

1. **A client at the provider** (an "application", an "app
   registration"):
   - *Redirect URI*: `https://<the server's HTTP address>/-/sign-in/
     oidc/callback`, for signing in with a browser.
   - For `kito connect --sign-in oidc`, the provider must give codes to
     enter (the *device authorization grant*, RFC 8628), and the client
     must be allowed to use it. Not every provider has it; `kito-server
     oidc status` says whether this one does.
   - It asks for `openid profile email`.
2. **The plugin on the server**:

   ```console
   $ scripts/build.sh --dist
   $ kito-server plugin add --path plugin
   $ kito-server plugin enable oidc
   $ kito-server oidc setup <issuer> <client id> [--secret-from <file>]
   ```

   The issuer is the provider as it names itself
   (`https://accounts.google.com`, `https://<tenant>.okta.com`,
   `https://login.microsoftonline.com/<tenant>/v2.0`,
   `https://<host>/realms/<realm>`). It is asked when you set it up: one
   that is not an issuer is said then. The secret comes from a file, so
   that it is on no command line; a client without one (a public
   client) needs none.
3. **People**: `kito-server user add <name> --identity
   oidc:<their email>`.

## Who somebody is: their email, or the provider's name for them

By default the server knows a person by their **email**, in small
letters, and only if the provider says it was verified
(`email_verified`). That is what an administrator knows of a person
before they have ever signed in.

- A provider that does not say whether an email was verified (Microsoft
  Entra does not) is refused, unless you say `--trust-email`. Say it
  only for a provider that is your organization's alone and where people
  cannot set their own email: with a provider anybody can register at,
  an unverified email lets one person sign in as another.
- `--subject sub` knows people by the provider's own name for them
  (`sub`) instead: it never changes and is never given to another, and
  it is a string nobody knows by heart. `--identity oidc:<sub>`.

## What it checks, and what it keeps

- **The provider is reached by https, always** (but for one on this
  machine, for tests), and must name itself as it was set up.
- **The ID token comes from the provider's token endpoint itself**, over
  that connection: this is what says it is the provider's, as the
  specification allows (OpenID Connect Core 3.1.3.7). Its signature is
  not checked again. It must be from the issuer, for this client, not
  run out, and, for a browser, carry what the sign-in was started with
  (`nonce`).
- **A browser's code is redeemed with PKCE**: a code somebody else got
  hold of is worth nothing to them.
- The tokens are used once and kept nowhere. What is kept, under the
  server's directory and for the server's user only:
  `plugins/oidc/config.toml` (the issuer, the client, its secret if
  any) and `plugins/oidc/key` (a random key of the plugin's own, from
  which what goes with a browser on its way out is made: the plugin
  keeps nothing between its two steps).
- It never sees a token or a session of the Kito server, and is given
  nothing of any repository (`permissions = ["sign_in",
  "server_admin"]`; `server_admin` is for `kito-server oidc`).

## Development

```console
$ cargo test
```

The tests ask a provider that is a few lines of `tests/oidc.rs`; nothing
leaves the machine. The last one runs the plugin under Kito itself, and
wants `kito`, `kitod` and `kito-server` in `KITO_BIN` or in
`../kito/target/debug`.

Not tried yet with a real client at a real provider: only what a
provider says of itself has been read from one.

## License

MIT or Apache-2.0, at your option.
