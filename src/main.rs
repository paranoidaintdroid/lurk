use std::{
    env, fmt, fs, io, process, thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct ProcessStats {
    pid: u32,
    name: String,
    state: char,

    minor_faults: u64,
    major_faults: u64,

    user_ticks: u64,
    system_ticks: u64,

    threads: u64,

    virtual_memory: u64,
    rss_pages: i64,

    voluntary_context_switches: u64,
    involuntary_context_switches: u64,
}

#[derive(Debug)]
struct Snapshot {
    stats: ProcessStats,
    timestamp: Instant,
}

#[derive(Debug)]
enum LurkError {
    Usage,
    InvalidPid(String),
    ProcessNotFound(u32),
    PermissionDenied(u32),

    Io { path: String, source: io::Error },
}

impl fmt::Display for LurkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LurkError::Usage => {
                write!(f, "usage: lurk <pid>\n             lurk watch <pid>")
            }

            LurkError::InvalidPid(value) => {
                write!(f, "invalid PID: {value}")
            }

            LurkError::ProcessNotFound(pid) => {
                write!(f, "process {pid} not found")
            }

            LurkError::PermissionDenied(pid) => {
                write!(f, "permission denied while inspecting process {pid}")
            }

            LurkError::Io { path, source } => {
                write!(f, "failed to read {path}: {source}")
            }
        }
    }
}

impl std::error::Error for LurkError {}

fn parse_pid(value: &str) -> Result<u32, LurkError> {
    value
        .parse()
        .map_err(|_| LurkError::InvalidPid(value.to_string()))
}

fn parse_stat(contents: &str) -> ProcessStats {
    let open_paren = contents.find('(').unwrap();
    let close_paren = contents.rfind(')').unwrap();

    let pid = contents[..open_paren].trim().parse().unwrap();

    let name = contents[open_paren + 1..close_paren].to_string();

    let remaining = contents[close_paren + 1..].trim();

    let fields: Vec<&str> = remaining.split_whitespace().collect();

    ProcessStats {
        pid,
        name,

        state: fields[0].chars().next().unwrap(),

        minor_faults: fields[7].parse().unwrap(),

        major_faults: fields[9].parse().unwrap(),

        user_ticks: fields[11].parse().unwrap(),

        system_ticks: fields[12].parse().unwrap(),

        threads: fields[17].parse().unwrap(),

        virtual_memory: fields[20].parse().unwrap(),

        rss_pages: fields[21].parse().unwrap(),

        voluntary_context_switches: 0,
        involuntary_context_switches: 0,
    }
}

fn read_proc_file(pid: u32, file: &str) -> Result<String, LurkError> {
    let path = format!("/proc/{pid}/{file}");

    match fs::read_to_string(&path) {
        Ok(contents) => Ok(contents),

        Err(error) => match error.kind() {
            io::ErrorKind::NotFound => Err(LurkError::ProcessNotFound(pid)),

            io::ErrorKind::PermissionDenied => Err(LurkError::PermissionDenied(pid)),

            _ => Err(LurkError::Io {
                path,
                source: error,
            }),
        },
    }
}

fn read_context_switches(pid: u32) -> Result<(u64, u64), LurkError> {
    let contents = read_proc_file(pid, "status")?;

    let mut voluntary = 0;
    let mut involuntary = 0;

    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("voluntary_ctxt_switches:") {
            voluntary = value.trim().parse().unwrap();
        } else if let Some(value) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            involuntary = value.trim().parse().unwrap();
        }
    }

    Ok((voluntary, involuntary))
}

fn read_stats(pid: u32) -> Result<ProcessStats, LurkError> {
    let contents = read_proc_file(pid, "stat")?;

    let mut stats = parse_stat(&contents);

    let (voluntary, involuntary) = read_context_switches(pid)?;

    stats.voluntary_context_switches = voluntary;

    stats.involuntary_context_switches = involuntary;

    Ok(stats)
}

fn take_snapshot(pid: u32) -> Result<Snapshot, LurkError> {
    let timestamp = Instant::now();

    let stats = read_stats(pid)?;

    Ok(Snapshot { stats, timestamp })
}

fn clock_ticks_per_second() -> u64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };

    assert!(ticks > 0);

    ticks as u64
}

fn page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };

    assert!(size > 0);

    size as u64
}

fn bytes_to_mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn cpu_percent(
    previous: &ProcessStats,
    current: &ProcessStats,
    elapsed_seconds: f64,
    ticks_per_second: u64,
) -> f64 {
    let previous_ticks = previous.user_ticks + previous.system_ticks;

    let current_ticks = current.user_ticks + current.system_ticks;

    let delta_ticks = current_ticks - previous_ticks;

    let cpu_seconds = delta_ticks as f64 / ticks_per_second as f64;

    cpu_seconds / elapsed_seconds * 100.0
}

fn watch_process(pid: u32) -> Result<(), LurkError> {
    let ticks_per_second = clock_ticks_per_second();

    let page_size = page_size();

    let mut previous = take_snapshot(pid)?;

    loop {
        thread::sleep(Duration::from_secs(1));

        let current = match take_snapshot(pid) {
            Ok(snapshot) => snapshot,

            Err(LurkError::ProcessNotFound(_)) => {
                println!("process {pid} exited");

                return Ok(());
            }

            Err(error) => {
                return Err(error);
            }
        };

        let elapsed = current
            .timestamp
            .duration_since(previous.timestamp)
            .as_secs_f64();

        let cpu = cpu_percent(&previous.stats, &current.stats, elapsed, ticks_per_second);

        let rss_bytes = current.stats.rss_pages as u64 * page_size;

        let rss_mib = bytes_to_mib(rss_bytes);

        let minor_faults_per_sec =
            (current.stats.minor_faults - previous.stats.minor_faults) as f64 / elapsed;

        let major_faults_per_sec =
            (current.stats.major_faults - previous.stats.major_faults) as f64 / elapsed;

        let voluntary_per_sec = (current.stats.voluntary_context_switches
            - previous.stats.voluntary_context_switches) as f64
            / elapsed;

        let involuntary_per_sec = (current.stats.involuntary_context_switches
            - previous.stats.involuntary_context_switches) as f64
            / elapsed;

        println!("{} ({})", current.stats.name, current.stats.pid);

        println!("CPU:           {:>8.2}%", cpu);

        println!("RSS:           {:>8.2} MiB", rss_mib);

        println!("Minor faults:  {:>8.2} /s", minor_faults_per_sec);

        println!("Major faults:  {:>8.2} /s", major_faults_per_sec);

        println!("Vol ctx sw:    {:>8.2} /s", voluntary_per_sec);

        println!("Invol ctx sw:  {:>8.2} /s", involuntary_per_sec);

        println!();

        previous = current;
    }
}

fn print_stats(stats: &ProcessStats) {
    let ticks_per_second = clock_ticks_per_second();

    let page_size = page_size();

    let user_seconds = stats.user_ticks as f64 / ticks_per_second as f64;

    let system_seconds = stats.system_ticks as f64 / ticks_per_second as f64;

    let rss_bytes = stats.rss_pages as u64 * page_size;

    println!("Process: {}", stats.name);
    println!("PID: {}", stats.pid);
    println!("State: {}", stats.state);

    println!();

    println!("User CPU:   {:.3} s", user_seconds);

    println!("System CPU: {:.3} s", system_seconds);

    println!("Threads: {}", stats.threads);

    println!(
        "Virtual memory: {:.2} MiB",
        bytes_to_mib(stats.virtual_memory)
    );

    println!("RSS: {:.2} MiB", bytes_to_mib(rss_bytes));

    println!("Minor faults: {}", stats.minor_faults);

    println!("Major faults: {}", stats.major_faults);

    println!(
        "Voluntary context switches: {}",
        stats.voluntary_context_switches
    );

    println!(
        "Involuntary context switches: {}",
        stats.involuntary_context_switches
    );
}

fn run() -> Result<(), LurkError> {
    let mut args = env::args().skip(1);

    let first = args.next().ok_or(LurkError::Usage)?;

    if first == "watch" {
        let pid_arg = args.next().ok_or(LurkError::Usage)?;

        if args.next().is_some() {
            return Err(LurkError::Usage);
        }

        let pid = parse_pid(&pid_arg)?;

        return watch_process(pid);
    }

    if args.next().is_some() {
        return Err(LurkError::Usage);
    }

    let pid = parse_pid(&first)?;

    let stats = read_stats(pid)?;

    print_stats(&stats);

    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("lurk: {error}");

        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_proc_stat() {
        let input =
            "1234 (bash) S 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

        let stats = parse_stat(input);

        assert_eq!(stats.pid, 1234);

        assert_eq!(stats.name, "bash");

        assert_eq!(stats.state, 'S');

        assert_eq!(stats.minor_faults, 7);

        assert_eq!(stats.major_faults, 9);

        assert_eq!(stats.user_ticks, 11);

        assert_eq!(stats.system_ticks, 12);

        assert_eq!(stats.threads, 17);

        assert_eq!(stats.virtual_memory, 20);

        assert_eq!(stats.rss_pages, 21);
    }

    #[test]
    fn parses_name_with_spaces() {
        let input = "4321 (my weird process) R 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

        let stats = parse_stat(input);

        assert_eq!(stats.pid, 4321);

        assert_eq!(stats.name, "my weird process");

        assert_eq!(stats.state, 'R');
    }

    #[test]
    fn parses_name_with_closing_parenthesis() {
        let input = "9876 (worker)thread) S 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

        let stats = parse_stat(input);

        assert_eq!(stats.pid, 9876);

        assert_eq!(stats.name, "worker)thread");

        assert_eq!(stats.state, 'S');
    }

    #[test]
    fn rejects_invalid_pid() {
        let result = parse_pid("banana");

        assert!(matches!(result, Err(LurkError::InvalidPid(_))));
    }
}
