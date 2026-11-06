//! Templates are written by tenants and rendered by the Core (preview) and by agents on managed
//! hosts: a runaway one must fail fast, not hang (docs/SECURITY-REVIEW.md F-12).

use std::time::{Duration, Instant};

use delbert_policy::template_env;

fn render(source: &'static str) -> (Result<String, String>, Duration) {
    let started = Instant::now();
    let handle = std::thread::spawn(move || template_env().render_str(source, minijinja::context! { vars => minijinja::context! { n => 3 } }).map_err(|e| format!("{e:#}")));
    while !handle.is_finished() {
        assert!(started.elapsed() < Duration::from_secs(20), "still rendering after 20 s: {source}");
        std::thread::sleep(Duration::from_millis(5));
    }
    (handle.join().unwrap(), started.elapsed())
}

#[test]
fn runaway_templates_run_out_of_fuel_quickly() {
    for t in [
        "{% for a in range(100000) %}{% for b in range(100000) %}{% endfor %}{% endfor %}",
        "{% for a in range(100000) %}{% for b in range(100000) %}{% for c in range(100000) %}x{% endfor %}{% endfor %}{% endfor %}",
        "{% macro m(n) %}{% for i in range(100000) %}{{ m(n) if n > 0 else '' }}{% endfor %}{% endmacro %}{{ m(400) }}",
    ] {
        let (result, took) = render(t);
        let error = result.expect_err("must not complete");
        assert!(error.to_lowercase().contains("fuel") || error.to_lowercase().contains("recursion") || error.to_lowercase().contains("too"), "{error}");
        assert!(took < Duration::from_secs(10), "{t}: {took:?}");
    }
}

#[test]
fn ordinary_templates_are_unaffected() {
    let (result, _) = render("{% for i in range(5000) %}line {{ i }} of {{ vars.n }}\n{% endfor %}");
    assert!(result.unwrap().lines().count() == 5000);
    let (result, _) = render("{{ vars.missing }}");
    assert!(result.is_err(), "undefined variables stay errors");
}
