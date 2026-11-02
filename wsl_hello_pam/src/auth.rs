use bindings::*;
use libc::{c_char, c_int};
use openssl;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier;
use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, prelude::*, SeekFrom};
use std::path::Path;
use std::process::{Command, Stdio};
use std::ptr;

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    flags: c_int,
    _: c_int,
    _: *mut *const c_char,
) -> c_int {
    authenticate_via_hello(pamh).unwrap_or_else(|err| {
        if (flags & PAM_SILENT) == 0 {
            println!("WSL Hello error: {}", err);
        }
        match err {
            HelloAuthenticationError::PublicKeyFileError(ref err)
                if err.kind() == io::ErrorKind::NotFound =>
            {
                PAM_USER_UNKNOWN
            }
            HelloAuthenticationError::AuthenticatorLaunchError(_) => PAM_AUTHINFO_UNAVAIL,
            HelloAuthenticationError::AuthenticatorConnectionError(_) => PAM_AUTHINFO_UNAVAIL,
            HelloAuthenticationError::AuthenticatorSignalled => PAM_AUTHINFO_UNAVAIL,
            _ => PAM_AUTH_ERR,
        }
    })
}

fn get_user(pamh: *mut pam_handle_t, prompt: Option<&str>) -> Result<Cow<'_, str>, i32> {
    let mut c_user: *const c_char = ptr::null();
    let tmp_prompt_str: CString;
    let c_prompt = match prompt {
        Some(prompt_str) => {
            tmp_prompt_str = CString::new(prompt_str).unwrap();
            tmp_prompt_str.as_ptr()
        }
        None => ptr::null(),
    };
    let err;
    unsafe {
        err = pam_get_user(pamh, &mut c_user, c_prompt);
    }
    match err {
        PAM_SUCCESS => unsafe {
            let c_user_str = CStr::from_ptr(c_user);
            Ok(c_user_str.to_string_lossy())
        },
        err => Err(err),
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum ConfigError {
    Io(io::Error),
    MissingField(String),
    InvalidValueType(String),
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> ConfigError {
        ConfigError::Io(err)
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::Io(ref ioerr) => write!(f, "{}", ioerr),
            ConfigError::MissingField(ref field) => write!(f, "field: '{}' is not found", field),
            ConfigError::InvalidValueType(ref field) => {
                write!(f, "field: '{}' has an invalid value type", field)
            }
        }
    }
}

/// Reads `key = "value"` from /etc/pam_wsl_hello/config.
/// The file holds only such lines; blank lines and `#` comments are skipped.
/// Values are plain strings without escapes.
fn get_config_value(key: &str) -> Result<String, ConfigError> {
    let mut config_file = File::open("/etc/pam_wsl_hello/config")?;
    let mut config = String::new();
    config_file.read_to_string(&mut config)?;
    parse_config_value(&config, key)
}

fn parse_config_value(config: &str, key: &str) -> Result<String, ConfigError> {
    for line in config.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        if k.trim() != key {
            continue;
        }
        let v = v.trim();
        return match v.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
            Some(inner) if !inner.contains('"') && !inner.contains('\\') => Ok(inner.to_owned()),
            _ => Err(ConfigError::InvalidValueType(key.to_owned())),
        };
    }
    Err(ConfigError::MissingField(key.to_owned()))
}

fn get_authenticator_path() -> Result<String, ConfigError> {
    get_config_value("authenticator_path")
}

fn get_win_mnt() -> Result<String, ConfigError> {
    get_config_value("win_mnt")
}

#[derive(Debug)]
#[allow(dead_code)]
enum HelloAuthenticationError {
    GetUserError(i32),
    ConfigError(ConfigError),
    PublicKeyFileError(io::Error),
    Io(io::Error),
    InvalidPublicKey(openssl::error::ErrorStack),
    OpenSslError(openssl::error::ErrorStack),
    AuthenticatorLaunchError(io::Error),
    AuthenticatorConnectionError(io::Error),
    AuthenticatorSignalled,
    HelloAuthenticationFail(String),
    SignAuthenticationFail,
}

impl From<io::Error> for HelloAuthenticationError {
    fn from(err: io::Error) -> HelloAuthenticationError {
        HelloAuthenticationError::Io(err)
    }
}

impl From<ConfigError> for HelloAuthenticationError {
    fn from(err: ConfigError) -> HelloAuthenticationError {
        HelloAuthenticationError::ConfigError(err)
    }
}

impl fmt::Display for HelloAuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HelloAuthenticationError::ConfigError(ref err) => write!(f, "config error; {}", err),
            HelloAuthenticationError::PublicKeyFileError(ref err) => match err.kind() {
                io::ErrorKind::NotFound => {
                    write!(f, "cannot find the credential public key for this user")
                }
                _ => write!(f, "{}", err),
            },
            HelloAuthenticationError::Io(ref err) => write!(f, "{}", err),
            HelloAuthenticationError::InvalidPublicKey(_) => {
                write!(f, "the pem file of the public key is invalid")
            }
            HelloAuthenticationError::AuthenticatorLaunchError(ref err) => {
                write!(f, "cannot launch Windows Hello; {}", err)
            }
            HelloAuthenticationError::AuthenticatorConnectionError(ref err) => {
                write!(f, "cannot communicate with Windows Hello; {}", err)
            }
            HelloAuthenticationError::HelloAuthenticationFail(ref msg) => {
                write!(f, "authentication failed; {}", msg)
            }
            HelloAuthenticationError::SignAuthenticationFail => write!(
                f,
                "the result of signature verification of the credential is failure"
            ),
            ref err => write!(f, "internal error; {:?}", err),
        }
    }
}

fn authenticate_via_hello(pamh: *mut pam_handle_t) -> Result<i32, HelloAuthenticationError> {
    let user_name = get_user(pamh, None).map_err(HelloAuthenticationError::GetUserError)?;
    let credential_key_name = format!("pam_wsl_hello_{}", user_name);

    let mut hello_public_key_file = File::open(format!(
        "/etc/pam_wsl_hello/public_keys/{}.pem",
        credential_key_name
    ))
    .map_err(HelloAuthenticationError::PublicKeyFileError)?;
    let mut key_str = String::new();
    hello_public_key_file.read_to_string(&mut key_str)?;
    let hello_public_key = PKey::public_key_from_pem(key_str.as_bytes())
        .map_err(HelloAuthenticationError::InvalidPublicKey)?;

    let mut nonce = [0u8; 16];
    openssl::rand::rand_bytes(&mut nonce).map_err(HelloAuthenticationError::OpenSslError)?;
    let nonce_hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
    let challenge = format!("pam_wsl_hello:{}:{}", user_name, nonce_hex);

    let auth_res;
    let challenge_tmpfile_path = &format!("/tmp/{}", challenge);
    {
        // Since there seems to be a bug that C# applications cannot read from pipes on WSL,
        // we create a temporary file to redirect
        let mut challenge_tmpfile = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(challenge_tmpfile_path)?;
        challenge_tmpfile.write_all(challenge.as_bytes())?;
        challenge_tmpfile.seek(SeekFrom::Start(0))?;

        let challenge_tmpfile_in = Stdio::from(challenge_tmpfile);

        let authenticator_path = get_authenticator_path()?;
        let authenticator = Command::new(authenticator_path)
            .arg("authenticator")
            .arg(credential_key_name)
            .current_dir(Path::new(&get_win_mnt()?))
            .stdin(challenge_tmpfile_in)
            .stdout(Stdio::piped())
            .spawn()
            .map_err(HelloAuthenticationError::AuthenticatorLaunchError)?;

        auth_res = authenticator
            .wait_with_output()
            .map_err(HelloAuthenticationError::AuthenticatorConnectionError)?;
    }
    fs::remove_file(challenge_tmpfile_path)?;

    match auth_res.status.code() {
        Some(0) => { /* Success */ }
        Some(_) => {
            return Err(HelloAuthenticationError::HelloAuthenticationFail(
                String::from_utf8(auth_res.stdout)
                    .unwrap_or_else(|_| "invalid utf8 output".to_string()),
            ))
        }
        None => return Err(HelloAuthenticationError::AuthenticatorSignalled),
    }
    let signature = auth_res.stdout;

    let mut verifier = Verifier::new(MessageDigest::sha256(), &hello_public_key).unwrap();
    verifier
        .update(challenge.as_bytes())
        .map_err(HelloAuthenticationError::OpenSslError)?;

    match verifier
        .verify(&signature)
        .map_err(HelloAuthenticationError::OpenSslError)?
    {
        true => Ok(PAM_SUCCESS),
        false => Err(HelloAuthenticationError::SignAuthenticationFail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = "authenticator_path = \"/mnt/c/Users/me/wsl-hello-sudo/WindowsHelloBridge.exe\"\n\
                          # comment\n\
                          \n\
                          win_mnt = \"/mnt/c\"\n";

    #[test]
    fn reads_both_keys() {
        assert_eq!(
            parse_config_value(CONFIG, "authenticator_path").unwrap(),
            "/mnt/c/Users/me/wsl-hello-sudo/WindowsHelloBridge.exe"
        );
        assert_eq!(parse_config_value(CONFIG, "win_mnt").unwrap(), "/mnt/c");
    }

    #[test]
    fn missing_key_is_an_error() {
        assert!(matches!(
            parse_config_value(CONFIG, "nope"),
            Err(ConfigError::MissingField(_))
        ));
    }

    #[test]
    fn unquoted_or_escaped_values_are_rejected() {
        for bad in ["win_mnt = /mnt/c", "win_mnt = \"/mnt/c", "win_mnt = \"a\\\\b\"", "win_mnt = \"a\"b\""] {
            assert!(
                matches!(parse_config_value(bad, "win_mnt"), Err(ConfigError::InvalidValueType(_))),
                "{}", bad
            );
        }
    }

    #[test]
    fn key_must_match_exactly() {
        assert!(parse_config_value("win_mnt_x = \"/x\"", "win_mnt").is_err());
    }
}
