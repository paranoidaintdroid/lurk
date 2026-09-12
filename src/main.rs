use std::{env, fs};

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
    }


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

fn main() {
    let args: Vec<String> = env::args().collect();

    let pid_arg = &args[1];
    let path = format!("/proc/{pid_arg}/stat");
    let contents = fs::read_to_string(path).unwrap();

    let stats = parse_stat(&contents);

    let ticks_per_second = clock_ticks_per_second();
    let page_size = page_size();

    let user_seconds = stats.user_ticks as f64 / ticks_per_second as f64;
    let system_seconds = stats.system_ticks as f64 / ticks_per_second as f64;

    let rss_bytes = stats.rss_pages as u64 * page_size;

    //println!("{stats:#?}");

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
    
}

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
    let input =
        "4321 (my weird process) R 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

    let stats = parse_stat(input);

    assert_eq!(stats.pid, 4321);
    assert_eq!(stats.name, "my weird process");
    assert_eq!(stats.state, 'R');
}

#[test]
fn parses_name_with_closing_parenthesis() {
    let input =
        "9876 (worker)thread) S 100 200 300 400 500 600 7 800 9 10 11 12 13 14 15 16 17 18 19 20 21";

    let stats = parse_stat(input);

    assert_eq!(stats.pid, 9876);
    assert_eq!(stats.name, "worker)thread");
    assert_eq!(stats.state, 'S');
}