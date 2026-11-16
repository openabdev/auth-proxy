//! S1 file store, the Broker admission rules, and the "no Debug for secrets"
//! guarantees.

mod support;

use ap_broker::{
    Binding, Broker, FileStore, HelloOk, LocalBroker, PlaneConfig, Secret, SessionPlane, Store,
    StoreError,
};
use ap_core::{Code, CredentialSource};
use std::fmt::{Debug, Display};
use std::fs;
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use support::*;

fn k8s(secret: &str, key: &str) -> CredentialSource {
    CredentialSource::K8s {
        secret: secret.into(),
        key: key.into(),
    }
}

fn write_at(path: &Path, content: &str, n: u64) {
    fs::write(path, content).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + n))
        .unwrap();
}

fn value(s: &Arc<Secret>) -> String {
    String::from_utf8(s.expose().to_vec()).unwrap()
}

#[test]
fn reads_and_trims_the_trailing_newline() {
    let d = tmpdir("read");
    fs::create_dir_all(d.join("auth-proxy-kiro")).unwrap();
    write_at(&d.join("auth-proxy-kiro/api_key"), "sk-test-1\n", 1);
    let st = FileStore::new(&d);
    assert_eq!(
        value(&st.resolve(&k8s("auth-proxy-kiro", "api_key")).unwrap()),
        "sk-test-1"
    );
    write_at(&d.join("auth-proxy-kiro/api_key"), "sk-test-2\r\n\n", 2);
    assert_eq!(
        value(&st.resolve(&k8s("auth-proxy-kiro", "api_key")).unwrap()),
        "sk-test-2"
    );
    // file: sources read the path as given
    let abs = d.join("plain");
    write_at(&abs, "plain-value", 1);
    assert_eq!(
        value(&st.resolve(&CredentialSource::File(abs)).unwrap()),
        "plain-value"
    );
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn reread_on_change_and_unavailable_on_removal_empty_or_env() {
    let d = tmpdir("change");
    let f = d.join("s/key");
    fs::create_dir_all(d.join("s")).unwrap();
    write_at(&f, "one", 1);
    let st = FileStore::new(&d);
    let src = k8s("s", "key");
    assert_eq!(value(&st.resolve(&src).unwrap()), "one");
    // same pointer while unchanged
    let (a, b) = (st.resolve(&src).unwrap(), st.resolve(&src).unwrap());
    assert!(Arc::ptr_eq(&a, &b));
    // changed size
    write_at(&f, "three", 2);
    assert_eq!(value(&st.resolve(&src).unwrap()), "three");
    // changed mtime only (same size)
    write_at(&f, "THREE", 3);
    assert_eq!(value(&st.resolve(&src).unwrap()), "THREE");
    // removed: unavailable, never the cached value
    fs::remove_file(&f).unwrap();
    assert!(matches!(st.resolve(&src), Err(StoreError::Unavailable(_))));
    // restored
    write_at(&f, "back", 4);
    assert_eq!(value(&st.resolve(&src).unwrap()), "back");
    // emptied (and whitespace-only): unavailable
    write_at(&f, "", 5);
    assert!(matches!(st.resolve(&src), Err(StoreError::Unavailable(_))));
    write_at(&f, "\n\n", 6);
    assert!(matches!(st.resolve(&src), Err(StoreError::Unavailable(_))));
    // too large
    write_at(&f, &"x".repeat(64 * 1024 + 1), 7);
    assert!(matches!(st.resolve(&src), Err(StoreError::Unavailable(_))));
    write_at(&f, &"x".repeat(64 * 1024), 8);
    assert!(st.resolve(&src).is_ok());
    // other missing secret / key
    assert!(matches!(
        st.resolve(&k8s("nope", "key")),
        Err(StoreError::Unavailable(_))
    ));
    assert!(matches!(
        st.resolve(&k8s("s", "nope")),
        Err(StoreError::Unavailable(_))
    ));
    // a directory is not a credential
    fs::create_dir_all(d.join("s/dir")).unwrap();
    assert!(matches!(
        st.resolve(&k8s("s", "dir")),
        Err(StoreError::Unavailable(_))
    ));
    // env: parses in the policy but this store does not resolve it
    assert_eq!(
        st.resolve(&CredentialSource::Env("X".into())).err(),
        Some(StoreError::Unsupported)
    );
    assert!(!FileStore::supports(&CredentialSource::Env("X".into())));
    assert!(FileStore::supports(&src));
    let _ = fs::remove_dir_all(&d);
}

/// Kubernetes Secret volume layout: `key -> ..data/key`, `..data -> ..<ts>`,
/// kubelet flips `..data` with a rename.
#[cfg(unix)]
#[test]
fn atomic_symlink_swap_is_picked_up_even_with_same_size_and_mtime() {
    use std::os::unix::fs::symlink;
    let d = tmpdir("swap");
    let sdir = d.join("auth-proxy-kiro");
    fs::create_dir_all(sdir.join("..v1")).unwrap();
    fs::create_dir_all(sdir.join("..v2")).unwrap();
    write_at(&sdir.join("..v1/api_key"), "key-AAAA", 1);
    write_at(&sdir.join("..v2/api_key"), "key-BBBB", 1);
    symlink("..v1", sdir.join("..data")).unwrap();
    symlink("..data/api_key", sdir.join("api_key")).unwrap();

    let st = FileStore::new(&d);
    let src = k8s("auth-proxy-kiro", "api_key");
    assert_eq!(value(&st.resolve(&src).unwrap()), "key-AAAA");
    symlink("..v2", sdir.join("..data_tmp")).unwrap();
    fs::rename(sdir.join("..data_tmp"), sdir.join("..data")).unwrap();
    assert_eq!(value(&st.resolve(&src).unwrap()), "key-BBBB");

    // the volume is removed (pod mount torn down): nothing is served
    fs::remove_file(sdir.join("..data")).unwrap();
    assert!(matches!(st.resolve(&src), Err(StoreError::Unavailable(_))));
    let _ = fs::remove_dir_all(&d);
}

// ---------------------------------------------------------------- Broker

struct Rig {
    broker: LocalBroker,
    plane: Arc<SessionPlane>,
    token: String,
    dir: std::path::PathBuf,
}

fn rig(tag: &str) -> Rig {
    let dir = tmpdir(tag);
    for (secret, key, v) in [
        ("auth-proxy-kiro", "api_key", "kiro-secret"),
        ("auth-proxy-anthropic", "api_key", "ant-secret"),
    ] {
        fs::create_dir_all(dir.join(secret)).unwrap();
        write_at(&dir.join(secret).join(key), v, 1);
    }
    let (_clock, plane) = plane_with(PlaneConfig::default());
    let plane = Arc::new(plane);
    let token = plane.hello().unwrap().authority_token;
    let broker = LocalBroker::new(plane.clone(), Arc::new(FileStore::new(&dir)));
    Rig {
        broker,
        plane,
        token,
        dir,
    }
}

#[test]
fn admit_follows_the_pipeline_codes() {
    let r = rig("admit");
    let pol = policy();
    r.plane
        .register(&r.token, &pol, &req("s1", 7, 1, &["kiro"]))
        .unwrap();
    r.plane
        .register(&r.token, &pol, &req("s2", 1, 2, &["anthropic"]))
        .unwrap();

    let b = r.broker.admit(&hash(1), "kiro-krs", &pol).unwrap();
    assert_eq!(
        b,
        Binding {
            session: "s1".into(),
            generation: 7,
            credentials: vec!["kiro".into()]
        }
    );
    assert_eq!(
        r.broker
            .admit(&hash(1), "kiro-q", &pol)
            .unwrap()
            .credentials,
        ["kiro"]
    );
    // a surrogate bound to credentials that do not reach this route
    assert_eq!(
        r.broker.admit(&hash(1), "anthropic", &pol),
        Err(Code::SurrogateWrongRoute)
    );
    assert_eq!(
        r.broker.admit(&hash(2), "kiro-krs", &pol),
        Err(Code::SurrogateWrongRoute)
    );
    assert_eq!(
        r.broker.admit(&hash(1), "no-such-route", &pol),
        Err(Code::SurrogateWrongRoute)
    );
    // unknown, revoked
    assert_eq!(
        r.broker.admit(&hash(99), "kiro-krs", &pol),
        Err(Code::SurrogateUnknown)
    );
    r.plane.revoke(&r.token, "s1", 7).unwrap();
    assert_eq!(
        r.broker.admit(&hash(1), "kiro-krs", &pol),
        Err(Code::SurrogateRevoked)
    );
    // the policy now names another identity: not this session's owner
    assert_eq!(
        r.broker
            .admit(&hash(2), "anthropic", &policy_for_identity("pty-team-b")),
        Err(Code::SurrogateWrongCaller)
    );
    let _ = fs::remove_dir_all(&r.dir);
}

#[test]
fn admit_uses_the_credentials_of_the_current_policy() {
    // a credential dropped from the policy after registration no longer
    // counts for any route
    let r = rig("admit-drop");
    let pol = policy();
    r.plane
        .register(&r.token, &pol, &req("s1", 1, 1, &["kiro"]))
        .unwrap();
    let slimmed = ap_core::Policy::parse(
        ap_core::testing::sample_toml()
            .replace(
                "routes = [\"kiro-cps\", \"kiro-krs\", \"kiro-cw\", \"kiro-q\"]",
                "routes = [\"kiro-krs\"]",
            )
            .replace(
                "route = \"kiro-cps\"\nmethods",
                "route = \"kiro-krs\"\nmethods",
            )
            .as_bytes(),
    )
    .unwrap();
    assert!(r.broker.admit(&hash(1), "kiro-krs", &slimmed).is_ok());
    assert_eq!(
        r.broker.admit(&hash(1), "kiro-q", &slimmed),
        Err(Code::SurrogateWrongRoute)
    );
    let _ = fs::remove_dir_all(&r.dir);
}

#[test]
fn secret_comes_from_the_store_every_time_and_fails_closed() {
    let r = rig("secret");
    let pol = policy();
    assert_eq!(
        value(&r.broker.secret("kiro", &pol).unwrap()),
        "kiro-secret"
    );
    assert_eq!(
        value(&r.broker.secret("anthropic", &pol).unwrap()),
        "ant-secret"
    );
    // rotation: the next request sees the new value
    write_at(&r.dir.join("auth-proxy-kiro/api_key"), "rotated!!!!", 2);
    assert_eq!(
        value(&r.broker.secret("kiro", &pol).unwrap()),
        "rotated!!!!"
    );
    // the store goes away after a good request: broker_unavailable, no stale value
    fs::remove_file(r.dir.join("auth-proxy-kiro/api_key")).unwrap();
    assert_eq!(
        r.broker.secret("kiro", &pol).err(),
        Some(Code::BrokerUnavailable)
    );
    assert_eq!(
        value(&r.broker.secret("anthropic", &pol).unwrap()),
        "ant-secret"
    );
    // unknown credential id
    assert_eq!(
        r.broker.secret("ghost", &pol).err(),
        Some(Code::BrokerUnavailable)
    );
    // env: source
    let env_pol = ap_core::Policy::parse(
        ap_core::testing::sample_toml()
            .replace("k8s:auth-proxy-anthropic:api_key", "env:ANTHROPIC_API_KEY")
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        r.broker.secret("anthropic", &env_pol).err(),
        Some(Code::BrokerUnavailable)
    );
    let _ = fs::remove_dir_all(&r.dir);
}

// ---------------------------------------------------------------- no Debug for secrets

/// Inherent associated consts win when their bounds hold, so `IS` is true
/// exactly when `T` implements the trait. Compile-time proof, no runtime state.
struct Probe<T>(PhantomData<T>);
trait Fallback {
    const DEBUG: bool = false;
    const DISPLAY: bool = false;
    const CLONE: bool = false;
}
impl<T> Fallback for Probe<T> {}
impl<T: Debug> Probe<T> {
    const DEBUG: bool = true;
}
impl<T: Display> Probe<T> {
    const DISPLAY: bool = true;
}
impl<T: Clone> Probe<T> {
    const CLONE: bool = true;
}

#[test]
fn secret_values_have_no_debug_display_or_clone() {
    const { assert!(!Probe::<Secret>::DEBUG) };
    const { assert!(!Probe::<Secret>::DISPLAY) };
    const { assert!(!Probe::<Secret>::CLONE) };
    // holders of secrets do not leak them through Debug either
    const { assert!(!Probe::<FileStore>::DEBUG) };
    const { assert!(!Probe::<LocalBroker>::DEBUG) };
    // the probe itself works
    const { assert!(Probe::<String>::DEBUG && Probe::<String>::DISPLAY && Probe::<String>::CLONE) };
}

#[test]
fn hello_debug_redacts_the_token() {
    let (_, p) = plane();
    let h: HelloOk = p.hello().unwrap();
    let shown = format!("{h:?}");
    assert!(!shown.contains(&h.authority_token));
    assert!(!shown.contains("apt_"));
    assert!(shown.contains("redacted"));
    let e = format!(
        "{:?}",
        p.register(&h.authority_token, &policy(), &req("s", 1, 1, &["ghost"]))
    );
    assert!(!e.contains("apt_"));
}
