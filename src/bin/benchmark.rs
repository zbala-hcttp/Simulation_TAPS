use std::process::{Command, Stdio, Child};
use std::thread;
use std::time::Duration;
use std::fs::OpenOptions;
use std::io::Write;

fn main() {
    // 1. Define Test Matrix
    // Format: (n, t)
    let scenarios = vec![
        (5, 3),
        (10, 6),
        (20, 11),
        (30, 16),
        (50, 26),
    ];

    // 2. Prepare Results File
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results.csv")
        .expect("Cannot open file");

    writeln!(file, "N,T,Phase,Time_Microseconds").unwrap();

    println!("==================================================");
    println!("   STARTING TAPS BENCHMARK SUITE");
    println!("==================================================");

    // 3. Build Once (Release Mode)
    Command::new("cargo")
        .args(&["build", "--release", "--bins"])
        .status()
        .expect("Build failed");

    // 4. Run Loop
    for (n, t) in scenarios {
        run_scenario(n, t, &mut file);

        // Cool-down period to let OS reclaim ports (TIME_WAIT state)
        thread::sleep(Duration::from_secs(5));
    }
}

fn run_scenario(n: usize, t: usize, file: &mut std::fs::File) {
    println!("\n>>> Running Scenario: N={} T={} <<<", n, t);

    let release_path = "target/release";
    let ext = if cfg!(target_os = "windows") { ".exe" } else { "" };
    let mut children: Vec<Child> = Vec::new();

    // A. Start Authority (Pass N and T)
    let _auth = Command::new(format!("{}/authority{}", release_path, ext))
        .arg(n.to_string())
        .arg(t.to_string())
        .stdout(Stdio::null()) // We don't need Authority logs
        .spawn()
        .expect("Failed to start Authority");
    children.push(_auth);
    thread::sleep(Duration::from_secs(2));

    // B. Start Combiner (Pass N)
    // We capture stdout to parse BENCH lines
    let combiner = Command::new(format!("{}/combiner{}", release_path, ext))
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Combiner");
    // Don't push to children yet, we need to read its output

    thread::sleep(Duration::from_secs(2));

    // C. Start Tracer
    let _tracer = Command::new(format!("{}/tracer{}", release_path, ext))
        .stdout(Stdio::null())
        .spawn()
        .expect("Failed to start Tracer");
    children.push(_tracer);

    // D. Start N Signers
    for i in 0..n {
        let _s = Command::new(format!("{}/signer{}", release_path, ext))
            .arg(i.to_string())
            .stdout(Stdio::null())
            .spawn()
            .expect("Failed to start signer");
        children.push(_s);
        thread::sleep(Duration::from_millis(10)); // Slight stagger
    }

    // E. Read Combiner Output & Wait
    // This blocks until Combiner finishes
    let output = combiner.wait_with_output().expect("Combiner failed");

    // F. Parse Output and Save to CSV
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    for line in stdout_str.lines() {
        if line.starts_with("BENCH") {
            // Log format: BENCH,PhaseName,Microseconds
            // Output format: N,T,PhaseName,Microseconds
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let phase = parts[1];
                let time = parts[2];
                writeln!(file, "{},{},{},{}", n, t, phase, time).unwrap();
                println!("   [Result] {}: {} µs", phase, time);
            }
        }
    }

    // G. Cleanup
    for mut child in children {
        let _ = child.kill();
    }
}