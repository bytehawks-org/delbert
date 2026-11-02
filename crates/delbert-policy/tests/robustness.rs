//! Hostile YAML: policies come from tenants and from git sources, so the parser must neither
//! panic nor take unbounded time or memory on what an attacker can fit in a request body
//! (2 MiB by default). docs/SECURITY-REVIEW.md F-10.

use std::time::{Duration, Instant};

use delbert_policy::{MAX_FLOW_BRACKETS, PolicyError, from_yaml, parse_yaml};

const HEAD: &str = "apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: x, tenant: t }\nspec:\n  vars:\n    deep: ";
const VALID: &str = include_str!("../../../examples/quickstart.yaml");

/// Run `f` on its own thread; fail if it panics or does not finish in `limit`.
fn bounded<T: Send + 'static>(what: &str, limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> (T, Duration) {
    let started = Instant::now();
    let handle = std::thread::Builder::new().name(what.into()).stack_size(8 * 1024 * 1024).spawn(f).unwrap();
    while !handle.is_finished() {
        assert!(started.elapsed() < limit, "{what}: still running after {limit:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
    (handle.join().unwrap_or_else(|_| panic!("{what}: panicked")), started.elapsed())
}

#[test]
fn deeply_nested_flow_collections_are_refused_before_the_parser_sees_them() {
    // Unbounded, these took 15 s (80 KB) to 37 s (320 KB) in a release build, quadratically.
    for body in ["[".repeat(2_000_000), "{a: ".repeat(500_000), format!("{}{}", "[".repeat(1_000_000), "]".repeat(1_000_000))] {
        let doc = format!("{HEAD}{body}\n");
        let (result, took) = bounded("nesting", Duration::from_secs(2), move || from_yaml(&doc));
        assert!(matches!(result, Err(PolicyError::TooComplex(_))), "{result:?}");
        assert!(took < Duration::from_millis(500), "refusal took {took:?}");
    }
}

#[test]
fn what_the_limit_still_admits_is_cheap_to_parse() {
    // At the limit (every character a bracket, unbalanced) the parser must still be quick.
    let doc = format!("{HEAD}{}\n", "[".repeat(MAX_FLOW_BRACKETS - 3));
    let (result, took) = bounded("at-the-limit", Duration::from_secs(5), move || from_yaml(&doc));
    assert!(matches!(result, Err(PolicyError::Yaml(_))), "{result:?}");
    assert!(took < Duration::from_secs(1), "parsing at the limit took {took:?}");
    // Ordinary content is nowhere near it.
    assert!(VALID.bytes().filter(|b| matches!(b, b'[' | b'{')).count() < 50);
    assert!(from_yaml(VALID).is_ok());
}

#[test]
fn repository_files_get_the_same_protection() {
    #[derive(serde::Deserialize)]
    struct Any {}
    let doc = "[".repeat(100_000);
    assert!(matches!(parse_yaml::<Any>(&doc), Err(PolicyError::TooComplex(_))));
}

#[test]
fn alias_bombs_and_huge_scalars_are_bounded() {
    // Nine levels of ten aliases each: 10^9 expansions if aliases were expanded naively.
    let mut doc = String::from("apiVersion: delbert/v1\nkind: Policy\nmetadata: { name: x, tenant: t }\nspec:\n  vars:\n    a0: &a0 [lol, lol, lol, lol, lol, lol, lol, lol, lol, lol]\n");
    for i in 1..9 {
        doc.push_str(&format!("    a{i}: &a{i} [{}]\n", vec![format!("*a{}", i - 1); 10].join(", ")));
    }
    doc.push_str("  resources: []\n");
    let (_, took) = bounded("alias-bomb", Duration::from_secs(5), move || from_yaml(&doc).is_ok());
    assert!(took < Duration::from_secs(2), "{took:?}");

    let big = "x".repeat(2 * 1024 * 1024);
    let doc = format!("{HEAD}{big}\n  resources: []\n");
    let _ = bounded("big-scalar", Duration::from_secs(10), move || from_yaml(&doc).is_ok());
}

#[test]
fn odd_inputs_never_panic() {
    for odd in ["\u{0}", "\u{feff}", "\t", "\r\n", "!!binary aGk=", "!!python/object:os.system x", "? [a]\n: b", "<<: *nothing", "&a [*a]", "- - - -", "- ".repeat(100_000).as_str(), "? ".repeat(100_000).as_str(), "&a ".repeat(100_000).as_str(), "!t ".repeat(100_000).as_str()] {
        for doc in [format!("{HEAD}{odd}\n  resources: []\n"), odd.to_owned()] {
            let _ = bounded("odd", Duration::from_secs(5), move || from_yaml(&doc).is_ok());
        }
    }
}

/// A seeded mutation fuzzer: random byte edits, truncations and splices of a valid policy must
/// never panic, hang or produce a policy that fails its own validation.
#[test]
fn mutated_policies_never_panic_and_accepted_ones_validate() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let base = VALID.as_bytes().to_vec();
    let started = Instant::now();
    let mut accepted = 0;
    for round in 0..3_000 {
        let mut doc = base.clone();
        for _ in 0..=(next() % 6) {
            if doc.is_empty() {
                break;
            }
            let at = (next() as usize) % doc.len().max(1);
            match next() % 5 {
                0 => doc[at] = next() as u8,
                1 => doc.truncate(at.max(1)),
                2 => {
                    let end = (at + (next() as usize) % 40).min(doc.len());
                    doc.drain(at..end);
                }
                3 => {
                    let piece: Vec<u8> = doc[at..(at + 24).min(doc.len())].to_vec();
                    doc.splice(at..at, piece);
                }
                _ => doc.insert(at, b"[]{}:-?&*!|>#\"'%\n "[(next() as usize) % 17]),
            }
        }
        let Ok(text) = String::from_utf8(doc) else { continue };
        if let Ok(policy) = from_yaml(&text) {
            accepted += 1;
            assert!(delbert_policy::validate(&policy).is_ok(), "round {round}: accepted but invalid");
        }
        assert!(started.elapsed() < Duration::from_secs(60), "fuzzing is taking too long: parser slowdown at round {round}?");
    }
    eprintln!("mutation fuzz: {accepted} of 3000 mutants still valid, {:?}", started.elapsed());
}
