//! Signing in to a Kito server with OpenID Connect: a plugin (ADR 0006
//! of Kito), for a company's own sign-on (Google, Okta, Entra, Keycloak,
//! Auth0 and the like).
//!
//! It says who somebody is, and nothing else. The server runs it once
//! for each step, with JSON on its input, and reads the last line it
//! prints:
//!
//! - `kito-oidc sign-in begin`: where the person goes. For a command
//!   line (`{"kind": "device"}`), an address and a code (RFC 8628); for
//!   a browser (`{"kind": "browser", "redirect": …}`), the provider's
//!   page, which sends the browser back with a code (with PKCE).
//! - `kito-oidc sign-in finish`: who that was, `{"wait": seconds}`
//!   while they have not done it, or `{"refused": why}`.
//! - `kito-oidc sign-in ready`: whether it is set up (`{"ready": true}`,
//!   or `false` with `why`): the server asks before it offers it (Kito
//!   0.39.1).
//! - `kito-oidc sign-in lookup <who>`: the identity the server keeps for
//!   `kito-server user add --identity oidc:<who>`.
//!
//! The ID token comes straight from the provider's token endpoint, over
//! a connection whose certificate was checked: that is what says it is
//! the provider's (OpenID Connect Core 3.1.3.7), and its signature is
//! not checked again. So the provider is reached by https, always. The
//! tokens are used once and kept nowhere.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// The way to sign in this plugin is: what the server keeps before the `:`.
const METHOD: &str = "oidc";
const CONFIG_FILE: &str = "config.toml";
const KEY_FILE: &str = "key";
/// The server's directory, as Kito says it.
const ENV_SERVER_DIR: &str = "KITO_SERVER_DIR";

/// The client this server is at the provider, and what of a person the
/// server keeps.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Config {
    /// `https://accounts.google.com`.
    issuer: String,
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    /// What is asked for beside `openid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    /// Which claim says who somebody is for the server: `email` (what an
    /// administrator knows of a person) or `sub` (what the provider
    /// never gives to another).
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    /// Take an email the provider does not say it verified: for a
    /// provider that says nothing either way, and is the company's own.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    trust_email: bool,
}

fn dir() -> Result<PathBuf, String> {
    let dir = std::env::var_os(ENV_SERVER_DIR)
        .filter(|dir| !dir.is_empty())
        .ok_or(
            "KITO_SERVER_DIR is not set: this is a plugin of a Kito server, run by `kito-server`",
        )?;
    Ok(PathBuf::from(dir).join("plugins").join(METHOD))
}

/// Writes a file of the plugin for the server's user only.
fn keep(name: &str, text: &str) -> Result<PathBuf, String> {
    use std::io::Write;
    let path = dir()?.join(name);
    let said = |e: std::io::Error| format!("{}: {e}", path.display());
    std::fs::create_dir_all(path.parent().unwrap_or(&path)).map_err(said)?;
    let staged = path.with_extension("new");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(&staged)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .and_then(|()| std::fs::rename(&staged, &path))
        .map_err(said)?;
    Ok(path)
}

/// `true` for an address that is encrypted, or on this machine (a
/// provider under test).
fn safe(url: &str) -> bool {
    let local = ["http://127.0.0.1", "http://localhost", "http://[::1]"];
    url.starts_with("https://")
        || local.iter().any(|at| {
            url.strip_prefix(at)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        })
}

impl Config {
    fn load() -> Result<Config, String> {
        let path = dir()?.join(CONFIG_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn save(&self) -> Result<PathBuf, String> {
        keep(
            CONFIG_FILE,
            &toml::to_string(self).map_err(|e| e.to_string())?,
        )
    }

    fn issuer(&self) -> &str {
        self.issuer.trim().trim_end_matches('/')
    }

    /// `Err` while the plugin is not set up, in words for whoever reads it.
    fn ready(&self) -> Result<(), String> {
        if self.issuer().is_empty() || self.client_id.trim().is_empty() {
            return Err(
                "signing in with OpenID Connect is not set up on this server: an admin runs \
                        `kito-server oidc setup <issuer> <client id>`"
                    .to_owned(),
            );
        }
        match safe(self.issuer()) {
            true => Ok(()),
            false => Err(format!(
                "{} is not an https address: the provider is reached encrypted, always",
                self.issuer()
            )),
        }
    }

    fn secret(&self) -> Option<&str> {
        self.client_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
    }

    fn scope(&self) -> String {
        let more = self.scope.as_deref().unwrap_or("profile email");
        let mut words: Vec<&str> = vec!["openid"];
        words.extend(more.split_whitespace().filter(|word| *word != "openid"));
        words.join(" ")
    }

    /// By their email, or by the provider's own name for them.
    fn by_email(&self) -> bool {
        self.subject.as_deref() != Some("sub")
    }
}

fn agent() -> ureq::Agent {
    // The server waits a minute for a step: answer well within it.
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("kito-oidc/", env!("CARGO_PKG_VERSION")))
        .build()
}

/// What the provider answered, as JSON, whatever the status: its errors
/// are JSON too. `Err` is for a provider that could not be asked.
fn answer_of(asked: Result<ureq::Response, ureq::Error>) -> Result<(u16, Value), String> {
    let response = match asked {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(e) => return Err(format!("the provider could not be asked: {e}")),
    };
    let status = response.status();
    Ok((status, response.into_json().unwrap_or(Value::Null)))
}

// ------------------------------------------------------------- encodings

const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(bytes: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (at, byte)| n | u32::from(*byte) << (16 - 8 * at));
        for at in 0..=chunk.len() {
            out.push(alphabet[(n >> (18 - 6 * at) & 63) as usize] as char);
        }
        for _ in chunk.len()..3 {
            if pad {
                out.push('=');
            }
        }
    }
    out
}

/// What base64 for addresses holds (a part of a token).
fn from_base64url(text: &str) -> Option<Vec<u8>> {
    let (mut out, mut held, mut bits) = (Vec::with_capacity(text.len() * 3 / 4), 0u32, 0u32);
    for byte in text.trim_end_matches('=').bytes() {
        let value = URL.iter().position(|known| *known == byte)? as u32;
        held = held << 6 | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((held >> bits) as u8);
            held &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn random_hex(bytes: usize) -> Result<String, String> {
    let mut random = vec![0u8; bytes];
    getrandom::getrandom(&mut random).map_err(|e| format!("no randomness: {e}"))?;
    Ok(hex(&random))
}

/// What goes with a browser on its way out and is needed again when it
/// is back, made from what the server hands back (`state`) and a key
/// only this plugin has: the plugin keeps nothing between its two steps,
/// and neither the browser nor the provider can make these.
fn bound(what: &str, state: &str) -> Result<String, String> {
    use hmac::{Hmac, Mac};
    let path = dir()?.join(KEY_FILE);
    let key = match std::fs::read_to_string(&path) {
        Ok(key) if key.trim().len() >= 32 => key.trim().to_owned(),
        _ => {
            let key = random_hex(32)?;
            keep(KEY_FILE, &key)?;
            key
        }
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|e| e.to_string())?;
    mac.update(what.as_bytes());
    mac.update(b":");
    mac.update(state.as_bytes());
    Ok(hex(&mac.finalize().into_bytes()))
}

// -------------------------------------------------------------- provider

/// What the provider says of itself.
struct Provider {
    authorize: Option<String>,
    token: String,
    device: Option<String>,
    userinfo: Option<String>,
    /// The secret goes in the form, where the provider says it takes it
    /// there; otherwise as the specification has it by default.
    secret_in_form: bool,
}

fn discover(config: &Config) -> Result<Provider, String> {
    config.ready()?;
    let issuer = config.issuer();
    let asked = agent()
        .get(&format!("{issuer}/.well-known/openid-configuration"))
        .call();
    let (status, found) = answer_of(asked)?;
    if status != 200 || !found.is_object() {
        return Err(format!(
            "{issuer} does not say how to sign in with it (status {status}): is it the issuer?"
        ));
    }
    // A provider that says it is another is not the one that was set up.
    let says = found["issuer"]
        .as_str()
        .unwrap_or_default()
        .trim_end_matches('/');
    if says != issuer {
        return Err(format!(
            "{issuer} says it is `{says}`: set the issuer up as the provider names itself"
        ));
    }
    let address = |key: &str| -> Result<Option<String>, String> {
        match found[key].as_str() {
            Some(url) if safe(url) => Ok(Some(url.to_owned())),
            Some(url) => Err(format!(
                "the provider's `{key}` is not an https address: {url}"
            )),
            None => Ok(None),
        }
    };
    let methods = found["token_endpoint_auth_methods_supported"].as_array();
    Ok(Provider {
        authorize: address("authorization_endpoint")?,
        token: address("token_endpoint")?.ok_or("the provider names no token endpoint")?,
        device: address("device_authorization_endpoint")?,
        userinfo: address("userinfo_endpoint")?,
        secret_in_form: methods
            .is_some_and(|methods| methods.iter().any(|method| method == "client_secret_post")),
    })
}

/// Posts a form as this server's client: with its secret, if it has one.
fn post(
    config: &Config,
    provider: &Provider,
    url: &str,
    fields: &[(&str, &str)],
) -> Result<(u16, Value), String> {
    let client_id = config.client_id.trim();
    let mut fields: Vec<(&str, &str)> = fields.to_vec();
    let mut request = agent().post(url).set("Accept", "application/json");
    match config.secret() {
        Some(secret) if provider.secret_in_form => {
            fields.push(("client_id", client_id));
            fields.push(("client_secret", secret));
        }
        Some(secret) => {
            let both = format!("{}:{}", escaped(client_id), escaped(secret));
            request = request.set(
                "Authorization",
                &format!("Basic {}", base64(both.as_bytes(), STANDARD, true)),
            );
        }
        None => fields.push(("client_id", client_id)),
    }
    answer_of(request.send_form(&fields))
}

fn refused(why: impl Into<String>) -> Value {
    json!({ "refused": why.into() })
}

/// What the provider says when it gives no token, in words for the person.
fn no_token(answer: &Value) -> Value {
    let about = answer["error_description"].as_str().unwrap_or_default();
    match answer["error"].as_str().unwrap_or_default() {
        "access_denied" => refused("it was refused at the provider"),
        "expired_token" => refused("the code ran out before it was entered: start again"),
        "invalid_grant" => refused("the provider no longer takes that code: start again"),
        "invalid_client" | "unauthorized_client" => refused(
            "the provider does not take this server as the client that was set up: an admin checks the \
             client id, its secret, and what the client may do there",
        ),
        "" => refused("the provider gave no answer that says who signed in"),
        other => refused(format!("the provider said `{other}`: {about}")),
    }
}

/// What a token says, read without checking its signature: it came from
/// the provider's token endpoint itself.
fn claims_of(token: &str) -> Option<Value> {
    let payload = token.split('.').nth(1)?;
    serde_json::from_slice(&from_base64url(payload)?).ok()
}

/// Who the tokens the provider just gave are for. `nonce`: what a
/// browser's sign-in was started with, which the token must carry.
fn whose(
    config: &Config,
    provider: &Provider,
    tokens: &Value,
    nonce: Option<&str>,
) -> Result<Value, String> {
    let Some(mut claims) = tokens["id_token"]
        .as_str()
        .and_then(claims_of)
        .filter(Value::is_object)
    else {
        return Ok(refused(
            "the provider gave no ID token: an admin checks that the client may ask for `openid`",
        ));
    };
    let client_id = config.client_id.trim();
    let for_us = match &claims["aud"] {
        Value::String(one) => one == client_id,
        Value::Array(many) => many.iter().any(|one| one == client_id),
        _ => false,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    // A minute of grace for two clocks that are not the same.
    let live = claims["exp"]
        .as_f64()
        .is_some_and(|until| until as u64 + 60 > now);
    let ours = claims["iss"]
        .as_str()
        .is_some_and(|issuer| issuer.trim_end_matches('/') == config.issuer());
    if !(ours && for_us && live) {
        return Err("the ID token is not one the provider made for this server now".to_owned());
    }
    if nonce.is_some_and(|nonce| claims["nonce"] != nonce) {
        return Err("the ID token is not for the sign-in that was started".to_owned());
    }
    let Some(sub) = claims["sub"]
        .as_str()
        .filter(|sub| !sub.is_empty())
        .map(str::to_owned)
    else {
        return Err("the ID token names nobody".to_owned());
    };
    // Some providers say little in the token, and the rest when asked.
    let thin = claims["email"].is_null() || claims["name"].is_null();
    if let (true, Some(url), Some(access)) =
        (thin, &provider.userinfo, tokens["access_token"].as_str())
    {
        let asked = agent()
            .get(url)
            .set("Authorization", &format!("Bearer {access}"))
            .call();
        if let Ok((200, more)) = answer_of(asked) {
            // About the same person, or about nobody.
            if more["sub"] == sub.as_str() {
                for key in ["email", "email_verified", "name", "preferred_username"] {
                    if claims[key].is_null() && !more[key].is_null() {
                        claims[key] = more[key].clone();
                    }
                }
            }
        }
    }
    let email = claims["email"]
        .as_str()
        .filter(|email| email.contains('@'))
        .map(str::to_lowercase);
    let subject = if config.by_email() {
        let Some(email) = email.clone() else {
            return Ok(refused(
                "the provider did not say your email: an admin checks that the client may ask for `email`",
            ));
        };
        let verified = claims["email_verified"] == true || claims["email_verified"] == "true";
        if !verified && !config.trust_email {
            return Ok(refused(format!(
                "the provider does not say that {email} was verified, and this server knows people by their email"
            )));
        }
        email
    } else {
        sub
    };
    // The login is what the server shows and what `user add` is given:
    // the same words as the subject.
    let mut identity = json!({ "provider": METHOD, "subject": subject, "login": subject });
    if let Some(name) = claims["name"].as_str().filter(|name| !name.is_empty()) {
        identity["name"] = name.into();
    }
    if let Some(email) = email {
        identity["email"] = email.into();
    }
    Ok(json!({ "identity": identity }))
}

// ----------------------------------------------------------------- steps

fn begin(config: &Config, told: &Value) -> Result<Value, String> {
    let provider = discover(config)?;
    let scope = config.scope();
    if told["kind"] == "browser" {
        let redirect = told["redirect"]
            .as_str()
            .ok_or("the server did not say where to come back to")?;
        let Some(authorize) = &provider.authorize else {
            return Ok(refused("the provider has no page to sign in at"));
        };
        let state = random_hex(24)?;
        let challenge = base64(
            &Sha256::digest(bound("pkce", &state)?.as_bytes()),
            URL,
            false,
        );
        let join = if authorize.contains('?') { '&' } else { '?' };
        let open = format!(
            "{authorize}{join}response_type=code&client_id={}&redirect_uri={}&scope={}&state={state}&nonce={}\
             &code_challenge={challenge}&code_challenge_method=S256",
            escaped(config.client_id.trim()),
            escaped(redirect),
            escaped(&scope),
            bound("nonce", &state)?,
        );
        return Ok(json!({ "open": open, "state": state }));
    }
    let Some(device) = &provider.device else {
        return Ok(refused(
            "the provider gives no code to enter (it has no device authorization): sign in with a browser, at the \
             server's own address",
        ));
    };
    let (status, answer) = post(config, &provider, device, &[("scope", &scope)])?;
    // Google says `verification_url`.
    let open = [
        "verification_uri_complete",
        "verification_uri",
        "verification_url",
    ]
    .iter()
    .find_map(|key| answer[*key].as_str());
    match (
        answer["device_code"].as_str(),
        answer["user_code"].as_str(),
        open,
    ) {
        (Some(device), Some(code), Some(open)) => Ok(json!({
            "open": open,
            "code": code,
            // The server keeps it, and hands it back to `finish`.
            "state": device,
            "interval": answer["interval"].as_u64().unwrap_or(5),
        })),
        _ if answer["error"].is_string() => Ok(no_token(&answer)),
        _ => Ok(refused(format!(
            "the provider gave no code to enter (status {status})"
        ))),
    }
}

fn finish(config: &Config, told: &Value) -> Result<Value, String> {
    let provider = discover(config)?;
    if told["kind"] == "browser" {
        let query = &told["query"];
        if let Some(error) = query["error"].as_str() {
            return Ok(no_token(
                &json!({ "error": error, "error_description": query["error_description"] }),
            ));
        }
        let Some(code) = query["code"].as_str().filter(|code| !code.is_empty()) else {
            return Ok(refused("the provider sent nobody back: start again"));
        };
        let state = told["state"]
            .as_str()
            .ok_or("the server did not hand back what `begin` gave it")?;
        let redirect = told["redirect"].as_str().unwrap_or_default();
        let (verifier, nonce) = (bound("pkce", state)?, bound("nonce", state)?);
        let fields = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect),
            ("code_verifier", verifier.as_str()),
        ];
        let answer = post(config, &provider, &provider.token, &fields)?.1;
        return match answer["id_token"].is_string() {
            true => whose(config, &provider, &answer, Some(&nonce)),
            false => Ok(no_token(&answer)),
        };
    }
    let device = told["state"]
        .as_str()
        .ok_or("the server did not hand back what `begin` gave it")?;
    let fields = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", device),
    ];
    let answer = post(config, &provider, &provider.token, &fields)?.1;
    match answer["error"].as_str() {
        Some("authorization_pending") => Ok(json!({ "wait": 5 })),
        // Asked too often: slower from now on.
        Some("slow_down") => Ok(json!({ "wait": answer["interval"].as_u64().unwrap_or(10) })),
        Some(_) => Ok(no_token(&answer)),
        None => whose(config, &provider, &answer, None),
    }
}

/// Nobody can be looked up at a provider: the identity is what the
/// administrator wrote, as the provider will say it.
fn lookup(config: &Config, who: &str) -> Result<Value, String> {
    config.ready()?;
    let who = who.trim();
    let plain = !who.is_empty()
        && who.len() <= 320
        && !who.chars().any(|c| c.is_whitespace() || c.is_control());
    if config.by_email() {
        let email = who.to_lowercase();
        let fits = plain
            && email
                .split_once('@')
                .is_some_and(|(name, at)| !name.is_empty() && at.contains('.'));
        return Ok(match fits {
            true => json!({ "identity": { "provider": METHOD, "subject": email, "login": email, "email": email } }),
            false => refused(format!(
                "`{who}` is not an email: this server knows people by their email (`--identity oidc:bob@example.com`)"
            )),
        });
    }
    Ok(match plain {
        true => json!({ "identity": { "provider": METHOD, "subject": who, "login": who } }),
        false => refused(format!(
            "`{who}` is not what a provider calls somebody (its `sub`)"
        )),
    })
}

// ----------------------------------------------------------------- admin

/// `kito-server oidc setup | status`: the client this server is.
fn admin(args: &[String]) -> Result<(), String> {
    let mut config = Config::load()?;
    match args.first().map(String::as_str) {
        Some("setup") => {
            let mut rest = args[1..].iter();
            let mut named = Vec::new();
            while let Some(arg) = rest.next() {
                let mut value =
                    |what: &str| rest.next().cloned().ok_or(format!("{arg} wants {what}"));
                match arg.as_str() {
                    // From a file: a secret is not written on a command line.
                    "--secret-from" => {
                        let file = value("a file")?;
                        let text =
                            std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
                        config.client_secret =
                            Some(text.trim().to_owned()).filter(|secret| !secret.is_empty());
                    }
                    "--no-secret" => config.client_secret = None,
                    "--scope" => {
                        config.scope = Some(value("what to ask for, as in \"profile email\"")?)
                    }
                    "--subject" => match value("`email` or `sub`")?.as_str() {
                        "email" => config.subject = None,
                        "sub" => config.subject = Some("sub".to_owned()),
                        other => {
                            return Err(format!("--subject is `email` or `sub`, not `{other}`"))
                        }
                    },
                    "--trust-email" => config.trust_email = true,
                    "--verified-email" => config.trust_email = false,
                    other if other.starts_with('-') => {
                        return Err(format!("unknown option `{other}`"))
                    }
                    other => named.push(other.to_owned()),
                }
            }
            match named.as_slice() {
                [issuer, client_id] => {
                    config.issuer = issuer.trim_end_matches('/').to_owned();
                    config.client_id = client_id.clone();
                }
                [] if !config.issuer.is_empty() => {}
                _ => {
                    return Err(
                        "it is `kito-server oidc setup <issuer> <client id>`, as in `setup \
                                 https://accounts.google.com 1234.apps.googleusercontent.com`"
                            .to_owned(),
                    )
                }
            }
            // Asked now: an issuer that is not one is said here, not to
            // the first person who signs in.
            let provider = discover(&config)?;
            let path = config.save()?;
            println!(
                "Signing in with OpenID Connect is set up ({}).",
                path.display()
            );
            status(&config, Some(&provider));
            Ok(())
        }
        Some("status") | None => {
            let provider = match config.ready() {
                Ok(()) => Some(discover(&config)?),
                Err(_) => None,
            };
            status(&config, provider.as_ref());
            Ok(())
        }
        Some(other) => Err(format!(
            "`{other}`? It is `kito-server oidc setup <issuer> <client id> | status`"
        )),
    }
}

fn status(config: &Config, provider: Option<&Provider>) {
    let Some(provider) = provider else {
        println!("Signing in with OpenID Connect is not set up: `kito-server oidc setup <issuer> <client id>`.");
        return;
    };
    println!("Provider: {}", config.issuer());
    println!(
        "Client: {}{}",
        config.client_id.trim(),
        if config.secret().is_some() {
            " (with a secret)"
        } else {
            ""
        }
    );
    match (config.by_email(), config.trust_email) {
        (false, _) => println!("People are known by the provider's own name for them (`sub`): `--identity oidc:<sub>`."),
        (true, false) => println!("People are known by their verified email: `--identity oidc:bob@example.com`."),
        (true, true) => println!(
            "People are known by their email, verified or not (--trust-email): `--identity oidc:bob@example.com`."
        ),
    }
    match provider.device {
        Some(_) => println!("From a command line (`kito connect … --sign-in oidc`): yes."),
        None => println!("From a command line: no. The provider gives no code to enter (no device authorization)."),
    }
    match provider.authorize {
        Some(_) => {
            println!("In a browser: yes. The client's redirect is <the server's address>/-/sign-in/oidc/callback.")
        }
        None => println!("In a browser: no. The provider names no page to sign in at."),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let done = match words.as_slice() {
        ["sign-in", step, rest @ ..] => {
            let told: Value = serde_json::from_reader(std::io::stdin()).unwrap_or(Value::Null);
            let answer = Config::load().and_then(|config| match (*step, rest) {
                ("begin", _) => begin(&config, &told),
                ("finish", _) => finish(&config, &told),
                // Whether it can be used, as the server asks before it offers it (Kito 0.39.1).
                ("ready", _) => Ok(match config.ready() {
                    Ok(()) => json!({ "ready": true }),
                    Err(why) => json!({ "ready": false, "why": why }),
                }),
                ("lookup", [who, ..]) => lookup(&config, who),
                _ => Err("it is `sign-in begin | finish | ready | lookup <who>`".to_owned()),
            });
            answer.map(|answer| println!("{answer}"))
        }
        // As a command of the server, it is given its own name first.
        ["oidc", ..] => admin(&args[1..]),
        ["--version"] => {
            println!("kito-oidc {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err("this is a plugin of a Kito server: `kito-server plugin add --path <dir>`, then `kito-server \
                  plugin enable oidc`"
            .to_owned()),
    };
    match done {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("kito-oidc: {why}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_is_written_and_read() {
        assert_eq!(
            base64(b"any carnal pleas", STANDARD, true),
            "YW55IGNhcm5hbCBwbGVhcw=="
        );
        assert_eq!(
            base64(b"any carnal pleasu", URL, false),
            "YW55IGNhcm5hbCBwbGVhc3U"
        );
        assert_eq!(base64(&[0xfb, 0xff], URL, false), "-_8");
        for text in ["", "a", "ab", "abc", "{\"sub\":\"1\"}"] {
            assert_eq!(
                from_base64url(&base64(text.as_bytes(), URL, false)).unwrap(),
                text.as_bytes()
            );
        }
        assert!(from_base64url("a+b").is_none());
    }

    #[test]
    fn only_encrypted_addresses_and_this_machine_are_safe() {
        assert!(
            safe("https://accounts.google.com")
                && safe("http://127.0.0.1:9000/x")
                && safe("http://localhost")
        );
        assert!(
            !safe("http://accounts.google.com")
                && !safe("http://127.0.0.1.evil.example")
                && !safe("ftp://x")
        );
    }
}
