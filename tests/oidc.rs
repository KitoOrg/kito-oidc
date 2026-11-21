//! `kito-oidc`, asked as a Kito server asks it, with a provider that is
//! a few lines of this file: what it sends there, and what it makes of
//! the answers.
//!
//! The last test runs it under Kito itself, and needs `kito`, `kitod` and
//! `kito-server` in `KITO_BIN` or in `../kito/target/debug` (`cargo build
//! -p kito-cli -p kitod -p kito-server` there).

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};

/// What the provider of the tests does next, and what it was asked.
#[derive(Default)]
struct Fake {
    /// How many times it still says that nobody entered the code.
    pending: u32,
    denied: bool,
    slow: bool,
    /// It takes a client's secret in the form, and says so.
    secret_in_form: bool,
    /// It says it is another issuer than the one asked.
    lies: bool,
    /// What its ID tokens say, and what it says when asked who that is.
    claims: Value,
    userinfo: Value,
    /// `METHOD path | authorization | body`, one for each request.
    seen: Vec<String>,
}

struct Provider {
    host: String,
    fake: Arc<Mutex<Fake>>,
}

fn base64url(bytes: &[u8]) -> String {
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (at, byte)| n | u32::from(*byte) << (16 - 8 * at));
        for at in 0..=chunk.len() {
            out.push(URL[(n >> (18 - 6 * at) & 63) as usize] as char);
        }
    }
    out
}

/// A token as a provider makes one, signed by nobody.
fn token(claims: &Value) -> String {
    format!(
        "{}.{}.c2ln",
        base64url(b"{\"alg\":\"RS256\"}"),
        base64url(claims.to_string().as_bytes())
    )
}

fn in_ten_minutes() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 600
}

impl Provider {
    fn start() -> Provider {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let host = format!("http://{}", listener.local_addr().unwrap());
        let fake = Arc::new(Mutex::new(Fake {
            claims: json!({
                "iss": host,
                "aud": "app-1",
                "exp": in_ten_minutes(),
                "sub": "u-1",
                "email": "Bob@Example.com",
                "email_verified": true,
                "name": "Bob",
            }),
            ..Fake::default()
        }));
        let (state, site) = (fake.clone(), host.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let (mut length, mut authorization) = (0usize, String::from("-"));
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let line = line.trim().to_owned();
                    if line.is_empty() {
                        break;
                    }
                    let (name, value) = line.split_once(':').unwrap_or((&line, ""));
                    match name.to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap_or(0),
                        "authorization" => authorization = value.trim().to_owned(),
                        _ => {}
                    }
                }
                let mut body = vec![0u8; length];
                reader.read_exact(&mut body).unwrap();
                let body = String::from_utf8_lossy(&body).into_owned();
                let mut parts = first.split(' ');
                let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let mut fake = state.lock().unwrap();
                fake.seen
                    .push(format!("{method} {path} | {authorization} | {body}"));
                let has = |field: &str| body.split('&').any(|pair| pair == field);
                let tokens = |fake: &Fake| json!({ "access_token": "at-1", "id_token": token(&fake.claims) });
                let (status, answer) = match (method, path) {
                    ("GET", "/.well-known/openid-configuration") => {
                        let mut says = json!({
                            "issuer": if fake.lies { "https://another.example".to_owned() } else { site.clone() },
                            "authorization_endpoint": format!("{site}/authorize"),
                            "token_endpoint": format!("{site}/token"),
                            "device_authorization_endpoint": format!("{site}/device"),
                            "userinfo_endpoint": format!("{site}/userinfo"),
                        });
                        if fake.secret_in_form {
                            says["token_endpoint_auth_methods_supported"] =
                                json!(["client_secret_post"]);
                        }
                        (200, says)
                    }
                    ("POST", "/device") => (
                        200,
                        json!({
                            "device_code": "dev-1",
                            "user_code": "ABCD-EFGH",
                            "verification_uri": format!("{site}/activate"),
                            "verification_uri_complete": format!("{site}/activate?user_code=ABCD-EFGH"),
                            "interval": 0,
                        }),
                    ),
                    ("POST", "/token") if has("device_code=dev-1") => {
                        if fake.denied {
                            (400, json!({ "error": "access_denied" }))
                        } else if fake.slow {
                            (400, json!({ "error": "slow_down" }))
                        } else if fake.pending > 0 {
                            fake.pending -= 1;
                            (400, json!({ "error": "authorization_pending" }))
                        } else {
                            (200, tokens(&fake))
                        }
                    }
                    ("POST", "/token")
                        if has("grant_type=authorization_code") && has("code=good") =>
                    {
                        (200, tokens(&fake))
                    }
                    ("POST", "/token") => (400, json!({ "error": "invalid_grant" })),
                    ("GET", "/userinfo") if authorization == "Bearer at-1" => {
                        (200, fake.userinfo.clone())
                    }
                    _ => (404, json!({ "error": "not_found" })),
                };
                drop(fake);
                let answer = answer.to_string();
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: \
                     close\r\n\r\n",
                    answer.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(answer.as_bytes());
            }
        });
        Provider { host, fake }
    }

    fn seen(&self, start: &str) -> Vec<String> {
        self.fake
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|line| line.starts_with(start))
            .cloned()
            .collect()
    }

    fn change(&self, change: impl FnOnce(&mut Fake)) {
        change(&mut self.fake.lock().unwrap());
    }
}

/// A server's directory where the plugin is set up for the provider of
/// the tests, with more of its configuration.
fn set_up(dir: &Path, provider: &Provider, more: &str) {
    let plugin = dir.join("plugins/oidc");
    std::fs::create_dir_all(&plugin).unwrap();
    let text = format!(
        "issuer = \"{}\"\nclient_id = \"app-1\"\n{more}",
        provider.host
    );
    std::fs::write(plugin.join("config.toml"), text).unwrap();
}

/// Runs the plugin as the server does: the server's directory in the
/// environment, what it is told on its input.
fn plugin(dir: &Path, args: &[&str], told: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_kito-oidc"))
        .args(args)
        .env("KITO_SERVER_DIR", dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(told.to_string().as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// What the plugin answered: the last line it printed.
fn answer(dir: &Path, args: &[&str], told: &Value) -> Value {
    let out = plugin(dir, args, told);
    let (said, errors) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "kito-oidc {args:?}: {said}{errors}");
    serde_json::from_str(said.lines().last().unwrap_or_default())
        .unwrap_or_else(|e| panic!("{e}: {said}"))
}

/// Why the plugin failed: what it wrote for whoever runs the server.
fn failure(dir: &Path, args: &[&str], told: &Value) -> String {
    let out = plugin(dir, args, told);
    assert!(
        !out.status.success(),
        "kito-oidc {args:?}: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn bob() -> Value {
    json!({ "identity": {
        "provider": "oidc",
        "subject": "bob@example.com",
        "login": "bob@example.com",
        "name": "Bob",
        "email": "bob@example.com",
    }})
}

#[test]
fn a_code_entered_at_the_provider_says_who_signs_in_from_a_command_line() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider::start();
    let device = json!({ "kind": "device" });
    let why = failure(tmp.path(), &["sign-in", "begin"], &device);
    assert!(
        why.contains("not set up on this server") && why.contains("kito-server oidc setup"),
        "{why}"
    );

    set_up(tmp.path(), &provider, "");
    assert_eq!(
        answer(tmp.path(), &["sign-in", "begin"], &device),
        json!({
            "open": format!("{}/activate?user_code=ABCD-EFGH", provider.host),
            "code": "ABCD-EFGH",
            "state": "dev-1",
            "interval": 0,
        })
    );
    // Asked as the client that was set up, for who the person is.
    assert_eq!(
        provider.seen("POST /device"),
        ["POST /device | - | scope=openid+profile+email&client_id=app-1"]
    );

    // Nobody entered it yet; then somebody has. The email is who they
    // are, in small letters however the provider writes it.
    provider.change(|fake| fake.pending = 1);
    let finish = json!({ "kind": "device", "state": "dev-1" });
    assert_eq!(
        answer(tmp.path(), &["sign-in", "finish"], &finish),
        json!({ "wait": 5 })
    );
    assert_eq!(answer(tmp.path(), &["sign-in", "finish"], &finish), bob());
    let asked = provider.seen("POST /token").pop().unwrap();
    assert!(
        asked.ends_with(
            "| - | grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=dev-1&client_id=app-1"
        ),
        "{asked}"
    );

    // Asked too often, slower; refused there is refused here.
    provider.change(|fake| fake.slow = true);
    assert_eq!(
        answer(tmp.path(), &["sign-in", "finish"], &finish),
        json!({ "wait": 10 })
    );
    provider.change(|fake| fake.denied = true);
    assert_eq!(
        answer(tmp.path(), &["sign-in", "finish"], &finish),
        json!({ "refused": "it was refused at the provider" })
    );
}

#[test]
fn a_token_says_who_only_if_it_is_the_provider_s_for_this_server_now() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider::start();
    set_up(tmp.path(), &provider, "");
    let finish = json!({ "kind": "device", "state": "dev-1" });
    let with = |change: &dyn Fn(&mut Value)| {
        let mut claims = json!({
            "iss": provider.host, "aud": "app-1", "exp": in_ten_minutes(), "sub": "u-1",
            "email": "bob@example.com", "email_verified": true, "name": "Bob",
        });
        change(&mut claims);
        provider.change(|fake| fake.claims = claims);
    };

    // For another client, from another issuer, or of another time.
    for change in [
        (&|claims: &mut Value| claims["aud"] = json!("another-app")) as &dyn Fn(&mut Value),
        &|claims| claims["iss"] = json!("https://another.example"),
        &|claims| claims["exp"] = json!(1_000_000),
    ] {
        with(change);
        let why = failure(tmp.path(), &["sign-in", "finish"], &finish);
        assert!(
            why.contains("not one the provider made for this server now"),
            "{why}"
        );
    }
    with(&|claims| claims["aud"] = json!(["another-app", "app-1"]));
    assert_eq!(answer(tmp.path(), &["sign-in", "finish"], &finish), bob());

    // An email the provider does not vouch for is nobody's, unless the
    // administrator said to take it.
    with(&|claims| claims["email_verified"] = json!(false));
    let unverified = answer(tmp.path(), &["sign-in", "finish"], &finish);
    assert!(
        unverified["refused"]
            .as_str()
            .unwrap()
            .contains("bob@example.com was verified"),
        "{unverified}"
    );
    set_up(tmp.path(), &provider, "trust_email = true\n");
    assert_eq!(answer(tmp.path(), &["sign-in", "finish"], &finish), bob());
    set_up(tmp.path(), &provider, "");

    // A token that says little: the rest is asked, about the same person.
    with(&|claims| {
        claims
            .as_object_mut()
            .unwrap()
            .retain(|key, _| !["email", "email_verified", "name"].contains(&key.as_str()));
    });
    provider.change(|fake| {
        fake.userinfo = json!({ "sub": "u-1", "email": "bob@example.com", "email_verified": true, "name": "Bob" });
    });
    assert_eq!(answer(tmp.path(), &["sign-in", "finish"], &finish), bob());
    assert_eq!(provider.seen("GET /userinfo").len(), 1);
    provider.change(|fake| fake.userinfo["sub"] = json!("somebody-else"));
    let nobody = answer(tmp.path(), &["sign-in", "finish"], &finish);
    assert!(
        nobody["refused"]
            .as_str()
            .unwrap()
            .contains("did not say your email"),
        "{nobody}"
    );

    // Known by the provider's own name for them instead.
    set_up(tmp.path(), &provider, "subject = \"sub\"\n");
    assert_eq!(
        answer(tmp.path(), &["sign-in", "finish"], &finish),
        json!({ "identity": { "provider": "oidc", "subject": "u-1", "login": "u-1" } })
    );
}

/// The value of a parameter of an address.
fn parameter<'a>(url: &'a str, name: &str) -> &'a str {
    let query = url.split_once('?').unwrap().1;
    query
        .split('&')
        .find_map(|pair| {
            pair.strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
        })
        .unwrap()
}

#[test]
fn a_browser_that_comes_back_from_the_provider_says_who_signs_in() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider::start();
    set_up(tmp.path(), &provider, "client_secret = \"shh\"\n");
    let back = "https://kito.example.com/-/sign-in/oidc/callback";
    let leaving = json!({ "kind": "browser", "redirect": back });

    let begun = answer(tmp.path(), &["sign-in", "begin"], &leaving);
    let (open, state) = (
        begun["open"].as_str().unwrap(),
        begun["state"].as_str().unwrap(),
    );
    assert!(
        state.len() == 48 && state.bytes().all(|b| b.is_ascii_hexdigit()),
        "{state}"
    );
    assert!(
        open.starts_with(&format!(
            "{}/authorize?response_type=code&client_id=app-1&redirect_uri=https%3A%2F%2Fkito.example.com%2F-%2F\
             sign-in%2Foidc%2Fcallback&scope=openid%20profile%20email&state={state}&nonce=",
            provider.host
        )),
        "{open}"
    );
    assert_eq!(parameter(open, "code_challenge_method"), "S256");
    let (nonce, challenge) = (
        parameter(open, "nonce").to_owned(),
        parameter(open, "code_challenge").to_owned(),
    );
    // Another time, another state, and what goes with it.
    let other = answer(tmp.path(), &["sign-in", "begin"], &leaving);
    assert_ne!(other["state"], begun["state"]);
    assert_ne!(parameter(other["open"].as_str().unwrap(), "nonce"), nonce);

    // A token that is not for this sign-in is nobody's.
    let came = |query: Value| json!({ "kind": "browser", "state": state, "redirect": back, "query": query });
    let good = came(json!({ "code": "good", "state": state }));
    let why = failure(tmp.path(), &["sign-in", "finish"], &good);
    assert!(
        why.contains("not for the sign-in that was started"),
        "{why}"
    );
    provider.change(|fake| fake.claims["nonce"] = json!(nonce));
    assert_eq!(answer(tmp.path(), &["sign-in", "finish"], &good), bob());

    // The code is redeemed by whoever started: the verifier is the one
    // the challenge was made from, and the secret goes as the
    // specification has it by default.
    let asked = provider.seen("POST /token").pop().unwrap();
    let verifier = asked
        .split('&')
        .find_map(|pair| pair.strip_prefix("code_verifier="))
        .unwrap();
    assert_eq!(base64url(&Sha256::digest(verifier.as_bytes())), challenge);
    assert!(asked.contains(
        "| Basic YXBwLTE6c2ho | grant_type=authorization_code&code=good&redirect_uri=https%3A"
    ));
    assert!(!asked.contains("client_secret"), "{asked}");
    // In the form, for a provider that says it takes it there.
    provider.change(|fake| fake.secret_in_form = true);
    assert_eq!(answer(tmp.path(), &["sign-in", "finish"], &good), bob());
    let asked = provider.seen("POST /token").pop().unwrap();
    assert!(
        asked.contains("| - |") && asked.ends_with("&client_id=app-1&client_secret=shh"),
        "{asked}"
    );

    // A code the provider does not take, a person who said no, nobody.
    let stale = answer(
        tmp.path(),
        &["sign-in", "finish"],
        &came(json!({ "code": "old" })),
    );
    assert_eq!(
        stale,
        json!({ "refused": "the provider no longer takes that code: start again" })
    );
    let no = answer(
        tmp.path(),
        &["sign-in", "finish"],
        &came(json!({ "error": "access_denied" })),
    );
    assert_eq!(no, json!({ "refused": "it was refused at the provider" }));
    let nobody = answer(tmp.path(), &["sign-in", "finish"], &came(json!({})));
    assert_eq!(
        nobody,
        json!({ "refused": "the provider sent nobody back: start again" })
    );
    // Nothing of a token or of the secret's use is kept: the key is the plugin's own.
    let kept: Vec<String> = std::fs::read_dir(tmp.path().join("plugins/oidc"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(kept.len(), 2, "{kept:?}");
}

#[test]
fn a_provider_is_reached_encrypted_and_is_who_it_was_set_up_as() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider::start();
    let device = json!({ "kind": "device" });
    set_up(tmp.path(), &provider, "");
    provider.change(|fake| fake.lies = true);
    let why = failure(tmp.path(), &["sign-in", "begin"], &device);
    assert!(
        why.contains("says it is `https://another.example`"),
        "{why}"
    );

    // In the clear, nothing is asked at all.
    let plugin_dir = tmp.path().join("plugins/oidc");
    std::fs::write(
        plugin_dir.join("config.toml"),
        "issuer = \"http://sso.example.com\"\nclient_id = \"app-1\"\n",
    )
    .unwrap();
    let why = failure(tmp.path(), &["sign-in", "begin"], &device);
    assert!(
        why.contains("http://sso.example.com is not an https address"),
        "{why}"
    );
}

#[test]
fn an_administrator_writes_who_somebody_is_as_the_provider_will_say_it() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider::start();
    set_up(tmp.path(), &provider, "");
    let lookup = |who: &str| {
        answer(
            tmp.path(),
            &["sign-in", "lookup", who],
            &json!({ "login": who }),
        )
    };
    assert_eq!(
        lookup("Bob@Example.com"),
        json!({ "identity": {
            "provider": "oidc", "subject": "bob@example.com", "login": "bob@example.com", "email": "bob@example.com",
        }})
    );
    assert!(lookup("bob")["refused"]
        .as_str()
        .unwrap()
        .contains("is not an email"));
    set_up(tmp.path(), &provider, "subject = \"sub\"\n");
    assert_eq!(
        lookup("u-1"),
        json!({ "identity": { "provider": "oidc", "subject": "u-1", "login": "u-1" } })
    );
}

#[test]
fn an_administrator_says_which_provider_and_client_are_the_server_s() {
    let tmp = tempfile::tempdir().unwrap();
    let provider = Provider::start();
    let run = |args: &[&str]| {
        let out = plugin(tmp.path(), args, &Value::Null);
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), said)
    };
    assert!(run(&["oidc", "status"])
        .1
        .contains("is not set up: `kito-server oidc setup <issuer> <client id>`"));
    assert!(!run(&["oidc", "setup", &provider.host]).0);
    let file = tmp.path().join("plugins/oidc/config.toml");

    // The provider is asked when it is set up: one that is not the
    // issuer it was named as is said now, and nothing is written.
    provider.change(|fake| fake.lies = true);
    let (ok, said) = run(&["oidc", "setup", &provider.host, "app-1"]);
    assert!(
        !ok && said.contains("says it is") && !file.exists(),
        "{said}"
    );
    provider.change(|fake| fake.lies = false);

    let (ok, said) = run(&["oidc", "setup", &format!("{}/", provider.host), "app-1"]);
    assert!(ok, "{said}");
    assert!(
        said.contains(&format!("Provider: {}\n", provider.host))
            && said.contains("Client: app-1\n"),
        "{said}"
    );
    assert!(
        said.contains("known by their verified email") && said.contains("From a command line"),
        "{said}"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("issuer = \"{}\"\nclient_id = \"app-1\"\n", provider.host)
    );

    // More is said without naming the provider again; the secret comes
    // from a file, and the file it is kept in is the server's user's only.
    let secret = tmp.path().join("secret");
    std::fs::write(&secret, "s3cret\n").unwrap();
    let (ok, said) = run(&[
        "oidc",
        "setup",
        "--secret-from",
        secret.to_str().unwrap(),
        "--subject",
        "sub",
    ]);
    assert!(
        ok && said.contains("Client: app-1 (with a secret)") && !said.contains("s3cret"),
        "{said}"
    );
    assert!(
        said.contains("the provider's own name for them (`sub`)"),
        "{said}"
    );
    let kept = std::fs::read_to_string(&file).unwrap();
    assert!(
        kept.contains("client_secret = \"s3cret\"") && kept.contains("subject = \"sub\""),
        "{kept}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert!(!run(&["oidc", "setup", "--subject", "name"]).0);
    assert!(
        run(&["oidc", "setup", "--subject", "email", "--trust-email"])
            .1
            .contains("verified or not")
    );
}

fn kito_bin() -> PathBuf {
    let dir = std::env::var_os("KITO_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../kito/target/debug"));
    let server = dir.join(format!("kito-server{}", std::env::consts::EXE_SUFFIX));
    assert!(
        server.is_file(),
        "{} is not there: this test runs kito-oidc under Kito. Build it (`cargo build -p kito-cli -p kitod -p \
         kito-server` in the kito repository) or set KITO_BIN to where `kito`, `kitod` and `kito-server` are",
        server.display()
    );
    dir
}

#[test]
fn a_kito_server_signs_people_in_with_it() {
    let bin = kito_bin();
    let exe = |name: &str| bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let (dir, config) = (base.join("server"), base.join("config"));
    let provider = Provider::start();
    let server = |args: &[&str]| {
        let mut command = Command::new(exe("kito-server"));
        command
            .arg("--dir")
            .arg(&dir)
            .args(args)
            .env("KITOD_BIN", exe("kitod"))
            .env("KITO_AUTHOR", "the server")
            .env("KITO_CONFIG_DIR", &config);
        command
    };
    let ok = |args: &[&str]| {
        let out = server(args).output().unwrap();
        let (said, errors) = (
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        assert!(out.status.success(), "kito-server {args:?}: {said}{errors}");
        said.into_owned()
    };

    // The plugin as a download leaves it: its program and its manifest.
    let source = base.join("kito-oidc");
    std::fs::create_dir_all(&source).unwrap();
    let program = format!("kito-oidc{}", std::env::consts::EXE_SUFFIX);
    std::fs::copy(env!("CARGO_BIN_EXE_kito-oidc"), source.join(&program)).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("kito-plugin.toml"),
        source.join("kito-plugin.toml"),
    )
    .unwrap();

    ok(&["init", dir.to_str().unwrap()]);
    ok(&["repo", "add", "shop"]);
    ok(&["plugin", "add", "--path", source.to_str().unwrap()]);
    let enabled = ok(&["plugin", "enable", "oidc"]);
    assert!(
        enabled.contains("It may: sign_in, server_admin.")
            && enabled.contains("signing in with oidc"),
        "{enabled}"
    );
    // Its command is the server's.
    assert!(ok(&["oidc", "status"]).contains("is not set up"));
    assert!(ok(&["oidc", "setup", &provider.host, "app-1"]).contains("From a command line"));

    // An administrator adds bob by his email.
    let added = ok(&[
        "user",
        "add",
        "bob",
        "--identity",
        "oidc:Bob@Example.com",
        "--repo",
        "shop:write",
    ]);
    assert!(
        added.contains("whoever signs in as oidc:bob@example.com is bob. No token."),
        "{added}"
    );
    let kept = std::fs::read_to_string(dir.join("server.toml")).unwrap();
    assert!(
        kept.contains("identities = [\"oidc:bob@example.com\"]"),
        "{kept}"
    );
    let ghost = server(&["user", "add", "ghost", "--identity", "oidc:ghost"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&ghost.stderr).contains("`ghost` is not an email"));

    struct Serving(std::process::Child);
    impl Drop for Serving {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut serving = Serving(
        server(&["serve", "--plain", "--listen", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut line = String::new();
    BufReader::new(serving.0.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let address = line
        .trim()
        .strip_prefix("kito-server: listening on ")
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .to_owned();

    // bob connects by signing in: the code is entered while kito waits.
    provider.change(|fake| fake.pending = 1);
    let desk = base.join("desk");
    let kito = |args: &[&str]| {
        Command::new(exe("kito"))
            .args(args)
            .current_dir(&base)
            .env("KITOD_BIN", exe("kitod"))
            .env("KITO_NO_CLAUDE", "1")
            .env("KITO_AUTHOR", "bob")
            .env("KITO_CONFIG_DIR", base.join("bob-config"))
            .output()
            .unwrap()
    };
    let connected = kito(&[
        "connect",
        &address,
        "shop",
        desk.to_str().unwrap(),
        "--plain",
        "--sign-in",
        "oidc",
    ]);
    let (said, asked) = (
        String::from_utf8_lossy(&connected.stdout),
        String::from_utf8_lossy(&connected.stderr),
    );
    assert!(connected.status.success(), "{said}{asked}");
    let open = format!(
        "To sign in with oidc, open {}/activate?user_code=ABCD-EFGH",
        provider.host
    );
    assert!(
        asked.contains(&open) && asked.contains("and enter the code ABCD-EFGH"),
        "{asked}"
    );
    assert!(
        said.contains("is connected to `shop` on") && said.contains("as bob."),
        "{said}"
    );
    assert_eq!(
        provider.fake.lock().unwrap().pending,
        0,
        "kito waited until the code was entered"
    );

    // Somebody the provider knows and the server does not is nobody here.
    provider.change(|fake| fake.claims["email"] = json!("eve@example.com"));
    let eve = kito(&[
        "connect",
        &address,
        "shop",
        "eve-desk",
        "--plain",
        "--sign-in",
        "oidc",
    ]);
    assert!(!eve.status.success());
    let why = String::from_utf8_lossy(&eve.stderr).into_owned();
    assert!(
        why.contains("oidc:eve@example.com is nobody on this server"),
        "{why}"
    );

    let _ = kito(&["--repo", desk.to_str().unwrap(), "daemon", "stop"]);
    let _ = kito(&[
        "--repo",
        dir.join("repos/shop").to_str().unwrap(),
        "daemon",
        "stop",
    ]);
}
