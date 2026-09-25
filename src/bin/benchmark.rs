use std::env;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Usage: benchmark <N> <REPEATS>
///
/// Runs the (N, T) scenario REPEATS times, with T = floor(N / 2) + 1, and writes:
/// - benchmark_results_{signers,combiner,tracer}.csv — every raw sample
/// - benchmark_summary.csv — per role and operation: samples, mean, std dev,
///   min and max, all in microseconds
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <N (signers)> <REPEATS>", args[0]);
        eprintln!("Example: cargo run --release --bin benchmark 10 20");
        std::process::exit(2);
    }
    let n = parse_positive(&args[1], "N");
    let repeats = parse_positive(&args[2], "REPEATS");
    let t = n / 2 + 1;

    let mut file_s = create_csv("benchmark_results_signers.csv");
    let mut file_c = create_csv("benchmark_results_combiner.csv");
    let mut file_t = create_csv("benchmark_results_tracer.csv");
    let summary_path = "benchmark_summary.csv";

    writeln!(file_s, "N,T,Run,Signer_ID,Phase,Time_Microseconds").unwrap();
    writeln!(file_c, "N,T,Run,Phase,Time_Microseconds").unwrap();
    writeln!(file_t, "N,T,Run,Phase,Time_Microseconds").unwrap();

    println!("==================================================");
    println!("   STARTING TAPS BENCHMARK SUITE");
    println!("   N={} T={} REPEATS={}", n, t, repeats);
    println!("==================================================");

    let status = Command::new("cargo")
        .args(&["build", "--release", "--bins"])
        .status()
        .expect("Build failed");
    assert!(status.success(), "cargo build --release --bins failed");

    let mut stats = Stats::default();
    let mut failures = 0usize;

    for run in 1..=repeats {
        match run_scenario(n, t, run, repeats) {
            Some(samples) => {
                for s in &samples {
                    match s.signer_id {
                        Some(id) => writeln!(
                            file_s,
                            "{},{},{},{},{},{}",
                            n, t, run, id, s.phase, s.micros
                        ),
                        None => {
                            let file = if s.role == "combiner" { &mut file_c } else { &mut file_t };
                            writeln!(file, "{},{},{},{},{}", n, t, run, s.phase, s.micros)
                        }
                    }
                    .unwrap();
                    stats.add(s.role, &s.phase, s.micros);
                }
            }
            // A failed run's timings are partial, so keep them out of the
            // averages rather than silently skewing them.
            None => failures += 1,
        }

        if run < repeats {
            // Cool-down period to let OS reclaim ports (TIME_WAIT state)
            thread::sleep(Duration::from_secs(5));
        }
    }

    stats.write_summary(summary_path, n, t);

    println!("\n==================================================");
    if failures == 0 {
        println!("   ALL {} RUNS COMPLETED SUCCESSFULLY", repeats);
    } else {
        println!(
            "   {} OF {} RUN(S) FAILED - excluded from the summary",
            failures, repeats
        );
    }
    println!("   Summary written to {}", summary_path);
    println!("==================================================");

    if failures > 0 {
        std::process::exit(1);
    }
}

fn parse_positive(s: &str, name: &str) -> usize {
    match s.parse::<usize>() {
        Ok(v) if v > 0 => v,
        _ => {
            eprintln!("{} must be a positive integer (got '{}')", name, s);
            std::process::exit(2);
        }
    }
}

fn create_csv(path: &str) -> File {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .expect("Cannot open file")
}

struct Sample {
    role: &'static str,
    signer_id: Option<usize>,
    phase: String,
    micros: u128,
}

/// Timings grouped by (role, operation), kept in first-seen order so the
/// summary lists operations in the order the protocol runs them.
#[derive(Default)]
struct Stats {
    groups: Vec<(&'static str, String, Vec<u128>)>,
}

impl Stats {
    fn add(&mut self, role: &'static str, phase: &str, micros: u128) {
        match self.groups.iter_mut().find(|(r, p, _)| *r == role && p == phase) {
            Some((_, _, v)) => v.push(micros),
            None => self.groups.push((role, phase.to_string(), vec![micros])),
        }
    }

    fn write_summary(&self, path: &str, n: usize, t: usize) {
        let mut file = create_csv(path);
        writeln!(
            file,
            "N,T,Role,Operation,Samples,Mean_Microseconds,StdDev_Microseconds,Min_Microseconds,Max_Microseconds"
        )
        .unwrap();

        println!(
            "\n{:<9} {:<24} {:>8} {:>12} {:>12} {:>10} {:>10}",
            "Role", "Operation", "Samples", "Mean(us)", "StdDev(us)", "Min(us)", "Max(us)"
        );

        // Signers first, then combiner, then tracer.
        for role in ["signer", "combiner", "tracer"] {
            for (_, phase, v) in self.groups.iter().filter(|(r, _, _)| *r == role) {
                let count = v.len();
                let mean = v.iter().sum::<u128>() as f64 / count as f64;
                // Sample standard deviation (n - 1); zero when there is one sample.
                let std_dev = if count > 1 {
                    let var = v.iter().map(|&x| (x as f64 - mean).powi(2)).sum::<f64>()
                        / (count - 1) as f64;
                    var.sqrt()
                } else {
                    0.0
                };
                let min = *v.iter().min().unwrap();
                let max = *v.iter().max().unwrap();

                writeln!(
                    file,
                    "{},{},{},{},{},{:.2},{:.2},{},{}",
                    n, t, role, phase, count, mean, std_dev, min, max
                )
                .unwrap();
                println!(
                    "{:<9} {:<24} {:>8} {:>12.2} {:>12.2} {:>10} {:>10}",
                    role, phase, count, mean, std_dev, min, max
                );
            }
        }
    }
}

/// Extracts (phase, micros) from an actor's "BENCH,<phase>,<micros>" lines.
fn parse_bench(stdout: &[u8]) -> Vec<(String, u128)> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|line| line.starts_with("BENCH"))
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let micros = parts[2].trim().parse::<u128>().ok()?;
                Some((parts[1].to_string(), micros))
            } else {
                None
            }
        })
        .collect()
}

/// Runs one (n, t) scenario. Returns the collected timings, or None if any
/// actor failed.
fn run_scenario(n: usize, t: usize, run: usize, repeats: usize) -> Option<Vec<Sample>> {
    println!(
        "\n>>> Running Scenario: N={} T={} (run {}/{}) <<<",
        n, t, run, repeats
    );

    let release_path = "target/release";
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };

    let mut ok = true;
    let mut samples = Vec::new();

    let mut authority = Command::new(format!("{}/authority{}", release_path, ext))
        .arg(n.to_string())
        .arg(t.to_string())
        .stdout(Stdio::null()) // We don't need Authority logs
        .spawn()
        .expect("Failed to start Authority");
    thread::sleep(Duration::from_secs(2));

    let combiner = Command::new(format!("{}/combiner{}", release_path, ext))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Combiner");

    thread::sleep(Duration::from_secs(2));

    let tracer = Command::new(format!("{}/tracer{}", release_path, ext))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Tracer");

    let mut signer_handles: Vec<Child> = Vec::new();
    for i in 0..n {
        let s = Command::new(format!("{}/signer{}", release_path, ext))
            .arg(i.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start signer");
        signer_handles.push(s);
        thread::sleep(Duration::from_millis(10)); // Slight stagger
    }

    let output_c = combiner.wait_with_output().expect("Combiner failed");
    if !output_c.status.success() {
        eprintln!(
            "   [Combiner] EXITED WITH FAILURE ({:?}) for N={} T={}",
            output_c.status.code(),
            n,
            t
        );
        ok = false;
    }
    for (phase, micros) in parse_bench(&output_c.stdout) {
        samples.push(Sample { role: "combiner", signer_id: None, phase, micros });
    }

    for (i, s) in signer_handles.into_iter().enumerate() {
        let output_s = s.wait_with_output().expect("Failed to wait on signer");
        if !output_s.status.success() {
            eprintln!(
                "   [Signer #{}] EXITED WITH FAILURE ({:?})",
                i,
                output_s.status.code()
            );
            ok = false;
        }
        for (phase, micros) in parse_bench(&output_s.stdout) {
            samples.push(Sample { role: "signer", signer_id: Some(i), phase, micros });
        }
    }

    let output_t = tracer.wait_with_output().expect("Tracer failed");
    if !output_t.status.success() {
        eprintln!(
            "   [Tracer] EXITED WITH FAILURE ({:?}) - verification did not pass",
            output_t.status.code()
        );
        ok = false;
    }
    for (phase, micros) in parse_bench(&output_t.stdout) {
        samples.push(Sample { role: "tracer", signer_id: None, phase, micros });
    }

    // The Authority exits on its own once setup is done; kill it only if it is
    // somehow still alive, so a stray process cannot hold port 8080.
    match authority.try_wait() {
        Ok(Some(status)) if !status.success() => {
            eprintln!("   [Authority] EXITED WITH FAILURE ({:?})", status.code());
            ok = false;
        }
        Ok(None) => {
            let _ = authority.kill();
            let _ = authority.wait();
        }
        _ => {}
    }

    if ok { Some(samples) } else { None }
}
