use std::path::PathBuf;

fn main() {
    embed_object_store_credential();
    tauri_build::try_build(tauri_build_attributes()).expect("failed to run Tauri build script")
}

fn tauri_build_attributes() -> tauri_build::Attributes {
    #[cfg(windows)]
    {
        embed_windows_app_manifest();
        tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest())
    }

    #[cfg(not(windows))]
    tauri_build::Attributes::new()
}

/// Tauri's resource compiler attaches its default Common Controls v6
/// manifest to the app binary, but not to the lib unit-test executable.
/// Applying the same manifest as a linker input covers both targets. The
/// Tauri copy is disabled above so the app binary never gets two manifests.
#[cfg(windows)]
fn embed_windows_app_manifest() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
}

/// Optionally overrides the object-store credential at compile time.
///
/// Public source checkouts do not carry a real object-store credential.
/// This hook exists so a release build can ship a key from CI secrets, a
/// rotated key, or a per-customer key without editing source. When it finds
/// nothing, the app falls back to its runtime bootstrap and, failing that,
/// the settings dialog.
///
/// The override is injected at build time from, in priority order:
///
/// 1. `YLX_OSS_ACCESS_KEY` / `YLX_OSS_SECRET_KEY` environment variables
///    (both required) -- how CI/release builds should supply it.
/// 2. The JSON file named by `YLX_OSS_CREDENTIALS_FILE`, defaulting to
///    `~/.config/ylx-transfer/credentials.json`, in the same
///    `{"accessKeyId": ..., "secretAccessKey": ...}` shape the Aliyun
///    console hands out. This is what makes a plain `cargo build` on a
///    provisioned developer machine produce a ready-to-run binary.
///
/// When neither source is present the build still succeeds and simply
/// embeds nothing; the app then falls back to its runtime bootstrap and,
/// failing that, to the settings dialog. A build must never fail because a
/// developer has no credentials -- that would make the repo unbuildable
/// for anyone outside the team.
///
/// SECURITY: anything embedded here is extractable from the binary by
/// anyone who has it (`strings` is enough). Only ever inject a credential
/// whose blast radius you accept losing -- for this app, a RAM user scoped
/// to the single recordings bucket. Never an account-level key.
fn embed_object_store_credential() {
    println!("cargo:rerun-if-env-changed=YLX_OSS_ACCESS_KEY");
    println!("cargo:rerun-if-env-changed=YLX_OSS_SECRET_KEY");
    println!("cargo:rerun-if-env-changed=YLX_OSS_CREDENTIALS_FILE");

    let path = credentials_file_path();
    if let Some(path) = &path {
        // Declared even when the file is absent, so creating it later
        // actually triggers a rebuild instead of silently reusing a
        // credential-less binary.
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let embedded = credential_from_env().or_else(|| {
        let path = path.as_ref()?;
        let raw = std::fs::read_to_string(path).ok()?;
        credential_from_json(&raw)
    });

    let Some((access_key, secret_key)) = embedded else {
        // Not a warning: no build-time override is the normal public-checkout
        // case. The app can still receive a credential at runtime.
        return;
    };

    // `composition.rs` reads these back with `option_env!`.
    println!("cargo:rustc-env=YLX_EMBEDDED_OSS_ACCESS_KEY={access_key}");
    println!("cargo:rustc-env=YLX_EMBEDDED_OSS_SECRET_KEY={secret_key}");
}

fn credential_from_env() -> Option<(String, String)> {
    let access_key = std::env::var("YLX_OSS_ACCESS_KEY").ok()?;
    let secret_key = std::env::var("YLX_OSS_SECRET_KEY").ok()?;
    if access_key.trim().is_empty() || secret_key.trim().is_empty() {
        return None;
    }
    Some((access_key.trim().to_string(), secret_key))
}

fn credentials_file_path() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("YLX_OSS_CREDENTIALS_FILE") {
        if !explicit.trim().is_empty() {
            return Some(PathBuf::from(explicit));
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("ylx-transfer")
            .join("credentials.json"),
    )
}

/// Rejects a half-filled file rather than embedding a credential that
/// cannot sign anything -- that would turn "please configure storage" into
/// a confusing auth failure at upload time.
fn credential_from_json(raw: &str) -> Option<(String, String)> {
    let parsed: serde_json::Value = serde_json::from_str(raw).ok()?;
    let access_key = parsed.get("accessKeyId")?.as_str()?;
    let secret_key = parsed.get("secretAccessKey")?.as_str()?;
    if access_key.trim().is_empty() || secret_key.trim().is_empty() {
        return None;
    }
    // A newline anywhere would corrupt the `cargo:rustc-env=` directive,
    // which is line-oriented -- refuse rather than emit a broken build
    // instruction that fails much later and much more confusingly.
    if access_key.contains('\n') || secret_key.contains('\n') {
        println!("cargo:warning=object-store credential contains a newline; ignoring it");
        return None;
    }
    Some((access_key.trim().to_string(), secret_key.to_string()))
}
