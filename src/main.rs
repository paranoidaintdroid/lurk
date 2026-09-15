use std::{
    collections::{HashMap, HashSet},
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
    start_time_ticks: u64,
    virtual_memory: u64,
    rss_pages: i64,
    voluntary_context_switches: u64,
    involuntary_context_switches: u64,
}

#[derive(Debug)]
struct ThreadStats {
    tid: u32,
    name: String,
    state: char,
    user_ticks: u64,
    system_ticks: u64,
    start_time_ticks: u64,
    processor: i32,
    allowed_cpus: String,
}

#[derive(Debug)]
struct IoStats {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    syscw: u64,
    read_bytes: u64,
    write_bytes: u64,
    cancelled_write_bytes: i64,
}

#[derive(Debug)]
struct IoSnapshot {
    process: ProcessStats,
    io: IoStats,
    timestamp: Instant,
}

#[derive(Debug)]
struct Snapshot {
    stats: ProcessStats,
    timestamp: Instant,
}

#[derive(Debug)]
struct ThreadSnapshot {
    process: ProcessStats,
    threads: Vec<ThreadStats>,
    timestamp: Instant,
}

#[derive(Debug)]
enum LurkError {
    Usage,
    InvalidPid(String),
    ProcessNotFound(u32),
    PermissionDenied(u32),
    ProcessReused(u32),
    MalformedStat(&'static str),
    InvalidStatField { field: &'static str, value: String },
    MalformedStatus(&'static str),
    Io { path: String, source: io::Error },
    MalformedIo(&'static str),
    InvalidIoField { field: &'static str, value: String },
}

impl fmt::Display for LurkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LurkError::Usage => write!(
                f,
                "usage: lurk <pid>\n       lurk watch <pid>\n       lurk threads <pid>\n       lurk threads <pid> --watch\n       lurk io <pid>\n       lurk io <pid> --watch"
            ),
            LurkError::InvalidPid(value) => write!(f, "invalid PID: {value}"),
            LurkError::ProcessNotFound(pid) => write!(f, "process {pid} not found"),
            LurkError::PermissionDenied(pid) => {
                write!(f, "permission denied while inspecting process {pid}")
            }
            LurkError::ProcessReused(pid) => {
                write!(f, "process {pid} exited and its PID was reused")
            }
            LurkError::MalformedStat(reason) => {
                write!(f, "malformed /proc/<pid>/stat: {reason}")
            }
            LurkError::InvalidStatField { field, value } => {
                write!(f, "invalid value for stat field {field}: {value}")
            }
            LurkError::MalformedStatus(reason) => {
                write!(f, "malformed /proc/<pid>/status: {reason}")
            }
            LurkError::Io { path, source } => {
                write!(f, "failed to read {path}: {source}")
            }
            LurkError::MalformedIo(reason) => {
                write!(f, "malformed /proc/<pid>/io: {reason}")
            }
            LurkError::InvalidIoField { field, value } => {
                write!(f, "invalid value for io field {field}: {value}")
            }
        }
    }
}

impl std::error::Error for LurkError {}

fn parse_pid(value: &str) -> Result<u32, LurkError> {
    let pid = value
        .parse::<u32>()
        .map_err(|_| LurkError::InvalidPid(value.to_string()))?;

    if pid == 0 {
        return Err(LurkError::InvalidPid(value.to_string()));
    }

    Ok(pid)
}

fn parse_u64_field(fields: &[&str], index: usize, name: &'static str) -> Result<u64, LurkError> {
    let value = fields
        .get(index)
        .ok_or(LurkError::MalformedStat("missing fields"))?;

    value
        .parse::<u64>()
        .map_err(|_| LurkError::InvalidStatField {
            field: name,
            value: (*value).to_string(),
        })
}

fn parse_i64_field(fields: &[&str], index: usize, name: &'static str) -> Result<i64, LurkError> {
    let value = fields
        .get(index)
        .ok_or(LurkError::MalformedStat("missing fields"))?;

    value
        .parse::<i64>()
        .map_err(|_| LurkError::InvalidStatField {
            field: name,
            value: (*value).to_string(),
        })
}

fn parse_stat(contents: &str) -> Result<ProcessStats, LurkError> {
    let open_paren = contents
        .find('(')
        .ok_or(LurkError::MalformedStat("missing opening parenthesis"))?;

    let close_paren = contents
        .rfind(')')
        .ok_or(LurkError::MalformedStat("missing closing parenthesis"))?;

    if close_paren <= open_paren {
        return Err(LurkError::MalformedStat("invalid process name boundaries"));
    }

    let pid_text = contents[..open_paren].trim();

    let pid = pid_text
        .parse::<u32>()
        .map_err(|_| LurkError::InvalidStatField {
            field: "pid",
            value: pid_text.to_string(),
        })?;

    let name = contents[open_paren + 1..close_paren].to_string();
    let remaining = contents[close_paren + 1..].trim();
    let fields: Vec<&str> = remaining.split_whitespace().collect();

    let state_text = fields
        .first()
        .ok_or(LurkError::MalformedStat("missing process state"))?;

    let state = state_text
        .chars()
        .next()
        .ok_or(LurkError::MalformedStat("empty process state"))?;

    Ok(ProcessStats {
        pid,
        name,
        state,
        minor_faults: parse_u64_field(&fields, 7, "minflt")?,
        major_faults: parse_u64_field(&fields, 9, "majflt")?,
        user_ticks: parse_u64_field(&fields, 11, "utime")?,
        system_ticks: parse_u64_field(&fields, 12, "stime")?,
        threads: parse_u64_field(&fields, 17, "num_threads")?,
        start_time_ticks: parse_u64_field(&fields, 19, "starttime")?,
        virtual_memory: parse_u64_field(&fields, 20, "vsize")?,
        rss_pages: parse_i64_field(&fields, 21, "rss")?,
        voluntary_context_switches: 0,
        involuntary_context_switches: 0,
    })
}

fn parse_thread_stat(contents: &str) -> Result<ThreadStats, LurkError> {
    let open_paren = contents
        .find('(')
        .ok_or(LurkError::MalformedStat("missing opening parenthesis"))?;

    let close_paren = contents
        .rfind(')')
        .ok_or(LurkError::MalformedStat("missing closing parenthesis"))?;

    if close_paren <= open_paren {
        return Err(LurkError::MalformedStat("invalid thread name boundaries"));
    }

    let tid_text = contents[..open_paren].trim();

    let tid = tid_text
        .parse::<u32>()
        .map_err(|_| LurkError::InvalidStatField {
            field: "tid",
            value: tid_text.to_string(),
        })?;

    let name = contents[open_paren + 1..close_paren].to_string();
    let remaining = contents[close_paren + 1..].trim();
    let fields: Vec<&str> = remaining.split_whitespace().collect();

    let state_text = fields
        .first()
        .ok_or(LurkError::MalformedStat("missing thread state"))?;

    let state = state_text
        .chars()
        .next()
        .ok_or(LurkError::MalformedStat("empty thread state"))?;

    let processor_text = fields
        .get(36)
        .ok_or(LurkError::MalformedStat("missing processor field"))?;

    let processor = processor_text
        .parse::<i32>()
        .map_err(|_| LurkError::InvalidStatField {
            field: "processor",
            value: (*processor_text).to_string(),
        })?;

    Ok(ThreadStats {
        tid,
        name,
        state,
        user_ticks: parse_u64_field(&fields, 11, "utime")?,
        system_ticks: parse_u64_field(&fields, 12, "stime")?,
        start_time_ticks: parse_u64_field(&fields, 19, "starttime")?,
        processor,
        allowed_cpus: String::new(),
    })
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

    let mut voluntary = None;
    let mut involuntary = None;

    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("voluntary_ctxt_switches:") {
            voluntary = Some(value.trim().parse::<u64>().map_err(|_| {
                LurkError::MalformedStatus("invalid voluntary context switch counter")
            })?);
        } else if let Some(value) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            involuntary = Some(value.trim().parse::<u64>().map_err(|_| {
                LurkError::MalformedStatus("invalid involuntary context switch counter")
            })?);
        }
    }

    let voluntary = voluntary.ok_or(LurkError::MalformedStatus(
        "missing voluntary context switch counter",
    ))?;

    let involuntary = involuntary.ok_or(LurkError::MalformedStatus(
        "missing involuntary context switch counter",
    ))?;

    Ok((voluntary, involuntary))
}

fn read_stat_only(pid: u32) -> Result<ProcessStats, LurkError> {
    let contents = read_proc_file(pid, "stat")?;
    parse_stat(&contents)
}

fn read_stats(pid: u32) -> Result<ProcessStats, LurkError> {
    let before = read_stat_only(pid)?;
    let (voluntary, involuntary) = read_context_switches(pid)?;
    let mut after = read_stat_only(pid)?;

    if before.start_time_ticks != after.start_time_ticks {
        return Err(LurkError::ProcessReused(pid));
    }

    after.voluntary_context_switches = voluntary;
    after.involuntary_context_switches = involuntary;

    Ok(after)
}

fn read_thread_affinity(pid: u32, tid: u32) -> Result<String, LurkError> {
    let path = format!("/proc/{pid}/task/{tid}/status");

    let contents = fs::read_to_string(&path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => LurkError::ProcessNotFound(pid),
        io::ErrorKind::PermissionDenied => LurkError::PermissionDenied(pid),
        _ => LurkError::Io {
            path: path.clone(),
            source: error,
        },
    })?;

    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("Cpus_allowed_list:") {
            return Ok(value.trim().to_string());
        }
    }

    Err(LurkError::MalformedStatus("missing Cpus_allowed_list"))
}

fn read_threads(pid: u32) -> Result<Vec<ThreadStats>, LurkError> {
    let path = format!("/proc/{pid}/task");

    let entries = fs::read_dir(&path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => LurkError::ProcessNotFound(pid),
        io::ErrorKind::PermissionDenied => LurkError::PermissionDenied(pid),
        _ => LurkError::Io {
            path: path.clone(),
            source: error,
        },
    })?;

    let mut threads = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|error| LurkError::Io {
            path: path.clone(),
            source: error,
        })?;

        let file_name = entry.file_name();

        let Some(tid_text) = file_name.to_str() else {
            continue;
        };

        let Ok(tid) = tid_text.parse::<u32>() else {
            continue;
        };

        let stat_path = format!("/proc/{pid}/task/{tid}/stat");

        let contents = match fs::read_to_string(&stat_path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return Err(LurkError::PermissionDenied(pid));
            }
            Err(error) => {
                return Err(LurkError::Io {
                    path: stat_path,
                    source: error,
                });
            }
        };

        let mut thread = parse_thread_stat(&contents)?;

        thread.allowed_cpus = match read_thread_affinity(pid, tid) {
            Ok(allowed_cpus) => allowed_cpus,
            Err(LurkError::ProcessNotFound(_)) => continue,
            Err(error) => return Err(error),
        };

        threads.push(thread);
    }

    threads.sort_unstable_by_key(|thread| thread.tid);

    Ok(threads)
}

fn take_snapshot(pid: u32) -> Result<Snapshot, LurkError> {
    let timestamp = Instant::now();
    let stats = read_stats(pid)?;

    Ok(Snapshot { stats, timestamp })
}

fn take_thread_snapshot(pid: u32) -> Result<ThreadSnapshot, LurkError> {
    let timestamp = Instant::now();
    let process = read_stats(pid)?;
    let threads = read_threads(pid)?;
    let after = read_stat_only(pid)?;

    if process.start_time_ticks != after.start_time_ticks {
        return Err(LurkError::ProcessReused(pid));
    }

    Ok(ThreadSnapshot {
        process,
        threads,
        timestamp,
    })
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

fn signed_bytes_to_mib(bytes: i64) -> f64 {
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
    let delta_ticks = current_ticks.saturating_sub(previous_ticks);

    let cpu_seconds = delta_ticks as f64 / ticks_per_second as f64;

    cpu_seconds / elapsed_seconds * 100.0
}

fn thread_cpu_percent(
    previous: &ThreadStats,
    current: &ThreadStats,
    elapsed_seconds: f64,
    ticks_per_second: u64,
) -> f64 {
    let previous_ticks = previous.user_ticks + previous.system_ticks;
    let current_ticks = current.user_ticks + current.system_ticks;
    let delta_ticks = current_ticks.saturating_sub(previous_ticks);

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
            Err(LurkError::ProcessReused(_)) => {
                println!("process {pid} exited; PID was reused");
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        if previous.stats.start_time_ticks != current.stats.start_time_ticks {
            println!("process {pid} exited; PID was reused");
            return Ok(());
        }

        let elapsed = current
            .timestamp
            .duration_since(previous.timestamp)
            .as_secs_f64();

        let cpu = cpu_percent(&previous.stats, &current.stats, elapsed, ticks_per_second);

        let rss_bytes = current.stats.rss_pages as u64 * page_size;
        let rss_mib = bytes_to_mib(rss_bytes);

        let minor_faults_per_sec = current
            .stats
            .minor_faults
            .saturating_sub(previous.stats.minor_faults) as f64
            / elapsed;

        let major_faults_per_sec = current
            .stats
            .major_faults
            .saturating_sub(previous.stats.major_faults) as f64
            / elapsed;

        let voluntary_per_sec = current
            .stats
            .voluntary_context_switches
            .saturating_sub(previous.stats.voluntary_context_switches)
            as f64
            / elapsed;

        let involuntary_per_sec = current
            .stats
            .involuntary_context_switches
            .saturating_sub(previous.stats.involuntary_context_switches)
            as f64
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

fn print_threads(pid: u32) -> Result<(), LurkError> {
    let snapshot = take_thread_snapshot(pid)?;
    let ticks_per_second = clock_ticks_per_second();

    println!(
        "Process: {} ({})",
        snapshot.process.name, snapshot.process.pid
    );
    println!("Threads: {}", snapshot.threads.len());
    println!();

    println!(
        "{:<8} {:<16} {:<7} {:>10} {:>10} {:>8} {:>12}",
        "TID", "NAME", "STATE", "USER", "SYSTEM", "LASTCPU", "ALLOWED"
    );

    for thread in snapshot.threads {
        let user_seconds = thread.user_ticks as f64 / ticks_per_second as f64;
        let system_seconds = thread.system_ticks as f64 / ticks_per_second as f64;

        println!(
            "{:<8} {:<16} {:<7} {:>9.3}s {:>9.3}s {:>8} {:>12}",
            thread.tid,
            thread.name,
            thread.state,
            user_seconds,
            system_seconds,
            thread.processor,
            thread.allowed_cpus,
        );
    }

    Ok(())
}

fn watch_threads(pid: u32) -> Result<(), LurkError> {
    let ticks_per_second = clock_ticks_per_second();
    let mut previous = take_thread_snapshot(pid)?;
    let mut migration_counts: HashMap<(u32, u64), u64> = HashMap::new();

    loop {
        thread::sleep(Duration::from_secs(1));

        let current = match take_thread_snapshot(pid) {
            Ok(snapshot) => snapshot,
            Err(LurkError::ProcessNotFound(_)) => {
                println!("process {pid} exited");
                return Ok(());
            }
            Err(LurkError::ProcessReused(_)) => {
                println!("process {pid} exited; PID was reused");
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        if previous.process.start_time_ticks != current.process.start_time_ticks {
            println!("process {pid} exited; PID was reused");
            return Ok(());
        }

        let elapsed = current
            .timestamp
            .duration_since(previous.timestamp)
            .as_secs_f64();

        let previous_threads: HashMap<(u32, u64), &ThreadStats> = previous
            .threads
            .iter()
            .map(|thread| ((thread.tid, thread.start_time_ticks), thread))
            .collect();

        println!(
            "{} ({}) - {} threads",
            current.process.name,
            current.process.pid,
            current.threads.len()
        );

        println!(
            "{:<8} {:<16} {:<5} {:>9} {:>8} {:>12} {:>7} {:>10}",
            "TID", "NAME", "STATE", "CPU%", "LASTCPU", "ALLOWED", "MIGR", "MOVE"
        );

        for current_thread in &current.threads {
            let identity = (current_thread.tid, current_thread.start_time_ticks);
            let previous_thread = previous_threads.get(&identity).copied();

            let cpu = previous_thread.map(|previous_thread| {
                thread_cpu_percent(previous_thread, current_thread, elapsed, ticks_per_second)
            });

            let moved_from = previous_thread.and_then(|previous_thread| {
                if previous_thread.processor != current_thread.processor {
                    Some(previous_thread.processor)
                } else {
                    None
                }
            });

            let migration_count = migration_counts.entry(identity).or_insert(0);

            if moved_from.is_some() {
                *migration_count += 1;
            }

            let move_text = match moved_from {
                Some(previous_cpu) => {
                    format!("{previous_cpu}->{}", current_thread.processor)
                }
                None => "-".to_string(),
            };

            match cpu {
                Some(cpu) => println!(
                    "{:<8} {:<16} {:<5} {:>8.2}% {:>8} {:>12} {:>7} {:>10}",
                    current_thread.tid,
                    current_thread.name,
                    current_thread.state,
                    cpu,
                    current_thread.processor,
                    current_thread.allowed_cpus,
                    migration_count,
                    move_text,
                ),
                None => println!(
                    "{:<8} {:<16} {:<5} {:>9} {:>8} {:>12} {:>7} {:>10}",
                    current_thread.tid,
                    current_thread.name,
                    current_thread.state,
                    "new",
                    current_thread.processor,
                    current_thread.allowed_cpus,
                    migration_count,
                    move_text,
                ),
            }
        }

        println!();

        let live_threads: HashSet<(u32, u64)> = current
            .threads
            .iter()
            .map(|thread| (thread.tid, thread.start_time_ticks))
            .collect();

        migration_counts.retain(|identity, _| live_threads.contains(identity));

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

fn parse_io_u64(value: &str, field: &'static str) -> Result<u64, LurkError> {
    value.parse::<u64>().map_err(|_| LurkError::InvalidIoField {
        field,
        value: value.to_string(),
    })
}

fn parse_io_i64(value: &str, field: &'static str) -> Result<i64, LurkError> {
    value.parse::<i64>().map_err(|_| LurkError::InvalidIoField {
        field,
        value: value.to_string(),
    })
}

fn parse_io(contents: &str) -> Result<IoStats, LurkError> {
    let mut rchar = None;
    let mut wchar = None;
    let mut syscr = None;
    let mut syscw = None;
    let mut read_bytes = None;
    let mut write_bytes = None;
    let mut cancelled_write_bytes = None;

    for line in contents.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        match key {
            "rchar" => rchar = Some(parse_io_u64(value, "rchar")?),
            "wchar" => wchar = Some(parse_io_u64(value, "wchar")?),
            "syscr" => syscr = Some(parse_io_u64(value, "syscr")?),
            "syscw" => syscw = Some(parse_io_u64(value, "syscw")?),
            "read_bytes" => read_bytes = Some(parse_io_u64(value, "read_bytes")?),
            "write_bytes" => write_bytes = Some(parse_io_u64(value, "write_bytes")?),
            "cancelled_write_bytes" => {
                cancelled_write_bytes = Some(parse_io_i64(value, "cancelled_write_bytes")?)
            }
            _ => {}
        }
    }

    Ok(IoStats {
        rchar: rchar.ok_or(LurkError::MalformedIo("missing rchar"))?,
        wchar: wchar.ok_or(LurkError::MalformedIo("missing wchar"))?,
        syscr: syscr.ok_or(LurkError::MalformedIo("missing syscr"))?,
        syscw: syscw.ok_or(LurkError::MalformedIo("missing syscw"))?,
        read_bytes: read_bytes.ok_or(LurkError::MalformedIo("missing read_bytes"))?,
        write_bytes: write_bytes.ok_or(LurkError::MalformedIo("missing write_bytes"))?,
        cancelled_write_bytes: cancelled_write_bytes
            .ok_or(LurkError::MalformedIo("missing cancelled_write_bytes"))?,
    })
}

fn read_io_stats(pid: u32) -> Result<IoStats, LurkError> {
    let contents = read_proc_file(pid, "io")?;
    parse_io(&contents)
}

fn take_io_snapshot(pid: u32) -> Result<IoSnapshot, LurkError> {
    let timestamp = Instant::now();

    let before = read_stat_only(pid)?;
    let io = read_io_stats(pid)?;
    let after = read_stat_only(pid)?;

    if before.start_time_ticks != after.start_time_ticks {
        return Err(LurkError::ProcessReused(pid));
    }

    Ok(IoSnapshot {
        process: after,
        io,
        timestamp,
    })
}

fn print_io(pid: u32) -> Result<(), LurkError> {
    let snapshot = take_io_snapshot(pid)?;

    println!(
        "Process: {} ({})",
        snapshot.process.name, snapshot.process.pid
    );
    println!();
    println!("Cumulative I/O");
    println!(
        "Logical read:       {:>12.2} MiB",
        bytes_to_mib(snapshot.io.rchar)
    );
    println!(
        "Logical write:      {:>12.2} MiB",
        bytes_to_mib(snapshot.io.wchar)
    );
    println!(
        "Disk read:          {:>12.2} MiB",
        bytes_to_mib(snapshot.io.read_bytes)
    );
    println!(
        "Accounted write:    {:>12.2} MiB",
        bytes_to_mib(snapshot.io.write_bytes)
    );
    println!("Read operations:    {:>12}", snapshot.io.syscr);
    println!("Write operations:   {:>12}", snapshot.io.syscw);
    println!(
        "Cancelled write:    {:>12.2} MiB",
        signed_bytes_to_mib(snapshot.io.cancelled_write_bytes)
    );

    Ok(())
}

fn watch_io(pid: u32) -> Result<(), LurkError> {
    let mut previous = take_io_snapshot(pid)?;

    loop {
        thread::sleep(Duration::from_secs(1));

        let current = match take_io_snapshot(pid) {
            Ok(snapshot) => snapshot,
            Err(LurkError::ProcessNotFound(_)) => {
                println!("process {pid} exited");
                return Ok(());
            }
            Err(LurkError::ProcessReused(_)) => {
                println!("process {pid} exited; PID was reused");
                return Ok(());
            }
            Err(error) => return Err(error),
        };

        if previous.process.start_time_ticks != current.process.start_time_ticks {
            println!("process {pid} exited; PID was reused");
            return Ok(());
        }

        let elapsed = current
            .timestamp
            .duration_since(previous.timestamp)
            .as_secs_f64();

        let delta_rchar = current.io.rchar.saturating_sub(previous.io.rchar);
        let delta_wchar = current.io.wchar.saturating_sub(previous.io.wchar);
        let delta_read_bytes = current.io.read_bytes.saturating_sub(previous.io.read_bytes);
        let delta_write_bytes = current
            .io
            .write_bytes
            .saturating_sub(previous.io.write_bytes);

        let delta_cancelled_write_bytes = current
            .io
            .cancelled_write_bytes
            .saturating_sub(previous.io.cancelled_write_bytes);

        let delta_syscr = current.io.syscr.saturating_sub(previous.io.syscr);
        let delta_syscw = current.io.syscw.saturating_sub(previous.io.syscw);

        let logical_read_mib = bytes_to_mib(delta_rchar) / elapsed;
        let logical_write_mib = bytes_to_mib(delta_wchar) / elapsed;
        let disk_read_mib = bytes_to_mib(delta_read_bytes) / elapsed;
        let accounted_write_mib = bytes_to_mib(delta_write_bytes) / elapsed;
        let cancelled_write_mib = signed_bytes_to_mib(delta_cancelled_write_bytes) / elapsed;

        let read_ops_per_sec = delta_syscr as f64 / elapsed;
        let write_ops_per_sec = delta_syscw as f64 / elapsed;

        let avg_read_kib = if delta_syscr == 0 {
            0.0
        } else {
            delta_rchar as f64 / delta_syscr as f64 / 1024.0
        };

        let avg_write_kib = if delta_syscw == 0 {
            0.0
        } else {
            delta_wchar as f64 / delta_syscw as f64 / 1024.0
        };

        println!("{} ({})", current.process.name, current.process.pid);
        println!("Logical read:       {:>10.2} MiB/s", logical_read_mib);
        println!("Logical write:      {:>10.2} MiB/s", logical_write_mib);
        println!("Disk read:          {:>10.2} MiB/s", disk_read_mib);
        println!("Accounted write:    {:>10.2} MiB/s", accounted_write_mib);
        println!("Cancelled write:    {:>10.2} MiB/s", cancelled_write_mib);
        println!("Read operations:    {:>10.2} /s", read_ops_per_sec);
        println!("Write operations:   {:>10.2} /s", write_ops_per_sec);
        println!("Avg read/op:        {:>10.2} KiB", avg_read_kib);
        println!("Avg write/op:       {:>10.2} KiB", avg_write_kib);
        println!();

        previous = current;
    }
}

fn run() -> Result<(), LurkError> {
    let mut args = env::args().skip(1);
    let first = args.next().ok_or(LurkError::Usage)?;

    if first == "io" {
        let pid_arg = args.next().ok_or(LurkError::Usage)?;
        let option = args.next();

        if args.next().is_some() {
            return Err(LurkError::Usage);
        }

        let pid = parse_pid(&pid_arg)?;

        return match option.as_deref() {
            None => print_io(pid),
            Some("--watch") => watch_io(pid),
            Some(_) => Err(LurkError::Usage),
        };
    }

    if first == "watch" {
        let pid_arg = args.next().ok_or(LurkError::Usage)?;

        if args.next().is_some() {
            return Err(LurkError::Usage);
        }

        let pid = parse_pid(&pid_arg)?;
        return watch_process(pid);
    }

    if first == "threads" {
        let pid_arg = args.next().ok_or(LurkError::Usage)?;
        let option = args.next();

        if args.next().is_some() {
            return Err(LurkError::Usage);
        }

        let pid = parse_pid(&pid_arg)?;

        return match option.as_deref() {
            None => print_threads(pid),
            Some("--watch") => watch_threads(pid),
            Some(_) => Err(LurkError::Usage),
        };
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

    const BASIC_STAT: &str =
        "1234 (bash) S 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

    #[test]
    fn parses_basic_proc_stat() {
        let stats = parse_stat(BASIC_STAT).unwrap();

        assert_eq!(stats.pid, 1234);
        assert_eq!(stats.name, "bash");
        assert_eq!(stats.state, 'S');
        assert_eq!(stats.minor_faults, 7);
        assert_eq!(stats.major_faults, 9);
        assert_eq!(stats.user_ticks, 11);
        assert_eq!(stats.system_ticks, 12);
        assert_eq!(stats.threads, 17);
        assert_eq!(stats.start_time_ticks, 19);
        assert_eq!(stats.virtual_memory, 20);
        assert_eq!(stats.rss_pages, 21);
    }

    #[test]
    fn parses_name_with_spaces() {
        let input = "4321 (my weird process) R 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

        let stats = parse_stat(input).unwrap();

        assert_eq!(stats.pid, 4321);
        assert_eq!(stats.name, "my weird process");
        assert_eq!(stats.state, 'R');
    }

    #[test]
    fn parses_name_with_closing_parenthesis() {
        let input = "9876 (worker)thread) S 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

        let stats = parse_stat(input).unwrap();

        assert_eq!(stats.pid, 9876);
        assert_eq!(stats.name, "worker)thread");
        assert_eq!(stats.state, 'S');
    }

    #[test]
    fn rejects_invalid_pid() {
        let result = parse_pid("banana");
        assert!(matches!(result, Err(LurkError::InvalidPid(_))));
    }

    #[test]
    fn rejects_zero_pid() {
        let result = parse_pid("0");
        assert!(matches!(result, Err(LurkError::InvalidPid(_))));
    }

    #[test]
    fn rejects_truncated_proc_stat() {
        let input = "1234 (bash) S 1 2 3";
        let result = parse_stat(input);

        assert!(matches!(result, Err(LurkError::MalformedStat(_))));
    }

    #[test]
    fn rejects_missing_process_name_delimiter() {
        let input = "1234 bash S 1 2 3";
        let result = parse_stat(input);

        assert!(matches!(result, Err(LurkError::MalformedStat(_))));
    }

    #[test]
    fn parses_thread_stat() {
        let input = "5678 (worker-0) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37";

        let stats = parse_thread_stat(input).unwrap();

        assert_eq!(stats.tid, 5678);
        assert_eq!(stats.name, "worker-0");
        assert_eq!(stats.state, 'R');
        assert_eq!(stats.user_ticks, 11);
        assert_eq!(stats.system_ticks, 12);
        assert_eq!(stats.start_time_ticks, 19);
        assert_eq!(stats.processor, 36);
        assert_eq!(stats.allowed_cpus, "");
    }

    #[test]
    fn parses_proc_io() {
        let input = "\
    rchar: 1048576
    wchar: 2097152
    syscr: 100
    syscw: 50
    read_bytes: 524288
    write_bytes: 1048576
    cancelled_write_bytes: 4096
    ";

        let stats = parse_io(input).unwrap();

        assert_eq!(stats.rchar, 1_048_576);
        assert_eq!(stats.wchar, 2_097_152);
        assert_eq!(stats.syscr, 100);
        assert_eq!(stats.syscw, 50);
        assert_eq!(stats.read_bytes, 524_288);
        assert_eq!(stats.write_bytes, 1_048_576);
        assert_eq!(stats.cancelled_write_bytes, 4096);
    }
}
