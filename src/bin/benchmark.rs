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
        (100, 51),
        (500, 251),
    ];


    // 2. Prepare Results File
    let mut file_s = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results_signers.csv")
        .expect("Cannot open file");

    // 2. Prepare Results File
    let mut file_c = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results_combiner.csv")
        .expect("Cannot open file");

    // 2. Prepare Results File
    let mut file_t = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("benchmark_results_tracer.csv")
        .expect("Cannot open file");

    writeln!(file_s, "N,T,Signer_ID,Phase,Time_Microseconds").unwrap();
    writeln!(file_c, "N,T,Phase,Time_Microseconds").unwrap();
    writeln!(file_t, "N,T,Phase,Time_Microseconds").unwrap();

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
        run_scenario(n, t, &mut file_s, &mut file_c, &mut file_t);

        // Cool-down period to let OS reclaim ports (TIME_WAIT state)
        thread::sleep(Duration::from_secs(5));
    }
}

fn run_scenario(n: usize, t: usize, file_s: &mut std::fs::File, file_c: &mut std::fs::File, file_t: &mut std::fs::File) {
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
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Tracer");

    let mut signer_handles = Vec::new();
    // D. Start N Signers
    for i in 0..n {
        let _s = Command::new(format!("{}/signer{}", release_path, ext))
            .arg(i.to_string())
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to start signer");
        signer_handles.push(_s);
        thread::sleep(Duration::from_millis(10)); // Slight stagger
    }

    // E. Read Combiner Output & Wait
    // This blocks until Combiner finishes
    let output_c = combiner.wait_with_output().expect("Combiner failed");

    // F. Parse Output and Save to CSV
    let stdout_str_c = String::from_utf8_lossy(&output_c.stdout);
    for line in stdout_str_c.lines() {
        if line.starts_with("BENCH") {
            // Log format: BENCH,PhaseName,Microseconds
            // Output format: N,T,PhaseName,Microseconds
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let phase = parts[1];
                let time = parts[2];
                writeln!(file_c, "{},{},{},{}", n, t, phase, time).unwrap();
                println!("   [Combiner] {}: {} µs", phase, time);
            }
        }
    }

    for (i, _s) in signer_handles.into_iter().enumerate() {
        let output_s = _s.wait_with_output().expect("Failed to wait on signer");
        let stdout_str_s = String::from_utf8_lossy(&output_s.stdout);
        for line in stdout_str_s.lines() {
            if line.starts_with("BENCH") {
                let parts: Vec<&str> = line.split(',').collect();
                if parts.len() >= 3 {
                    writeln!(file_s, "{},{},{},{},{}", n, t, i, parts[1], parts[2]).unwrap();
                    println!("   [Signer] {}: {} µs", parts[1], parts[2]);
                }
            }
        }
    }


    let output_t = _tracer.wait_with_output().expect("Combiner failed");

    // F. Parse Output and Save to CSV
    let stdout_str_t = String::from_utf8_lossy(&output_t.stdout);
    for line in stdout_str_t.lines() {
        if line.starts_with("BENCH") {
            // Log format: BENCH,PhaseName,Microseconds
            // Output format: N,T,PhaseName,Microseconds
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 3 {
                let phase = parts[1];
                let time = parts[2];
                writeln!(file_t, "{},{},{},{}", n, t, phase, time).unwrap();
                println!("   [Tracer] {}: {} µs", phase, time);
            }
        }
    }

    // G. Cleanup
    for mut child in children {
        let _ = child.kill();
    }
}