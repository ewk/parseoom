#![allow(non_snake_case)] // for MiB, GiB

use regex::Regex;
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::iter::FromIterator;
use std::process;

const OOM_KILL_RE: &str = r"(?s)((\w+\s)?invoked oom-killer.*?)(?-s:.*?[oO]ut of memory:?){1}?";
const PS_LIST_END_RE: &str = r"Out of memory:?|oom-kill:|Memory cgroup";
const PS_LIST_RE: &str = r"(.*pid.+\bname\b)(?s)(.*)";

// Find total pages of RAM and return value in KiB
fn parse_meminfo_total(s: &str) -> Option<f64> {
    const PAGES_RAM_RE: &str = r"(\d+) pages RAM";
    const PAGES_RESERVED_RE: &str = r"(\d+) pages reserved";

    let re = Regex::new(PAGES_RAM_RE).unwrap();
    let pages_ram = re
        .captures(s)
        .unwrap()
        .get(1)
        .unwrap()
        .as_str()
        .parse::<f64>()
        .unwrap();

    let re = Regex::new(PAGES_RESERVED_RE).unwrap();
    let pages_reserved = re
        .captures(s)
        .unwrap()
        .get(1)
        .unwrap()
        .as_str()
        .parse::<f64>()
        .unwrap();

    // subtract reserved pages from the RAM total, which may not agree with what other tools report
    let total_ram_kib = ((pages_ram - pages_reserved) * 4096.0) / 1024.0;

    Some(total_ram_kib)
}

// Report free swap in KiB
fn parse_meminfo_swap(s: &str) -> Option<f64> {
    const FREE_SWAP_RE: &str = r"Free swap\s+=\s+(\d+)";

    let re = Regex::new(FREE_SWAP_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let swap = x.get(1).unwrap().as_str().parse::<f64>().unwrap();
        let swap = swap * (2048.0 / 1.024);
        Some(swap)
    } else {
        None
    }
}

// Report unreclaimable slab usage in KiB
fn parse_meminfo_slab(s: &str) -> Option<f64> {
    const UNRECLAIMABLE_SLAB_RE: &str = r"slab_unreclaimable:(\d+)";

    // The first slab_unreclaimable entry in MemInfo contains the total for all zones, in pages
    let re = Regex::new(UNRECLAIMABLE_SLAB_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let slab = x.get(1).unwrap().as_str();
        let slab_kib = (slab.parse::<f64>().unwrap() * 4096.0) / 1024.0;
        Some(slab_kib)
    } else {
        None
    }
}

// Find and return size of 2 MiB and 1 GiB huge page allocations in KiB
// t.0 is the sum of 2 MB huge pages in KiB
// t.1 is the sum of 1 GB huge pages in KiB
fn parse_meminfo_hugepages(s: &str) -> Option<(f64, f64)> {
    const HUGEPAGES_2MB_RE: &str = r"hugepages_total=(\d+).+?hugepages_size=2048kB";
    const HUGEPAGES_1GB_RE: &str = r"hugepages_total=(\d+).+?hugepages_size=1048576kB";
    let mut t = (0.0, 0.0);

    let re = Regex::new(HUGEPAGES_2MB_RE).unwrap();
    let mut num_2_mb_hugepages = 0.0;

    for caps in re.captures_iter(s) {
        num_2_mb_hugepages += &caps[1].parse::<f64>().unwrap();
    }

    // convert total 2 MiB huge page allocation from kb to kib
    t.0 = num_2_mb_hugepages * (2048.0 / 1.024);

    let re = Regex::new(HUGEPAGES_1GB_RE).unwrap();
    let mut num_1_gb_hugepages = 0.0;

    for caps in re.captures_iter(s) {
        num_1_gb_hugepages += &caps[1].parse::<f64>().unwrap();
    }

    // convert total 1 GiB huge page allocation from kb to kib
    t.1 = num_1_gb_hugepages * (1048576.0 / 1.024);

    Some(t)
}

// Report shared memory in KiB
fn parse_meminfo_shared(s: &str) -> Option<f64> {
    const SHMEM_RE: &str = r"shmem:(\d+)";

    let re = Regex::new(SHMEM_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let shmem = x.get(1).unwrap().as_str();
        let shmem_kib = (shmem.parse::<f64>().unwrap() * 4096.0) / 1024.0;
        Some(shmem_kib)
    } else {
        None
    }
}

// Split the process list header into a vector. Return the ps header as a vector along with the
// position of the pid column.
fn parse_ps_header(cleaned: &str) -> (Vec<String>, usize) {
    // Split each line of the ps string at whitespace and add the line to a vector of strings.
    //
    //      [
    //        ["Dec", "20", "03:17:52", "localhost", "kernel:", "75669.642775", "199", "0",
    //          "199", "14838", "226", "102400", "14", "-250", "systemd-journal"],
    //        ...
    //      ]
    //
    let re = Regex::new(PS_LIST_RE).unwrap();
    let ps_header = re
        .captures(cleaned)
        .unwrap()
        .get(1)
        .unwrap()
        .as_str()
        .trim();
    let header_vec = ps_header
        .split_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let pid_col = header_vec.iter().position(|x| x == "pid").unwrap();

    (header_vec, pid_col)
}

// Capture the values in the process list after the header, including the surrounding log metadata,
// and return the list as a &str.
fn parse_ps_list(cleaned: &str) -> Option<&str> {
    // We're keeping the ps entry lines, including log entry noise.
    //
    //      "Dec 20 03:17:52 localhost kernel: 75669.642775     199     0   199    14838 \n
    //          226   102400       14          -250 systemd-journal"
    //
    let re = Regex::new(PS_LIST_RE).unwrap();

    if let Some(x) = re.captures(cleaned) {
        let ps = x.get(2).unwrap().as_str().trim();
        Some(ps)
    } else {
        None
    }
}

// Transform the process list into a matrix of strings
fn parse_ps_matrix(ps: &str) -> Vec<Vec<String>> {
    let ps_matrix = ps
        .lines()
        .map(|s| {
            s.trim()
                .split_whitespace()
                .map(String::from)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    ps_matrix
}

// Parse the ps matrix and return a map of commands -> RSS.
fn top_consumers(
    ps_matrix: &[Vec<String>],
    pid_col: usize,
) -> std::collections::BTreeMap<String, i64> {
    // Iterate over each line in the matrix to create a map
    // of unique commands with their total RSS usage.
    //
    //      {"agetty": 59, "anvil": 189, ...}
    //
    let mut commands: BTreeMap<String, i64> = BTreeMap::new();

    for line in ps_matrix.iter() {
        *commands.entry(line[pid_col + 8].clone()).or_insert(0) +=
            line[pid_col + 4].parse::<i64>().unwrap();
    }

    commands
}

// Print the commands using the most memory.
fn print_top_commands(commands: BTreeMap<String, i64>) {
    // To sort the key (command name) by its value (RSS) we need to convert
    // the map to a vector:
    let mut command_vec = Vec::from_iter(commands.iter());
    command_vec.sort_by(|a, b| b.1.cmp(a.1));

    // Now we have a list of command names sorted by RSS usage we can
    // print the top consumers by name.
    println!("\nTop 10 unique commands using memory:\n");
    for line in command_vec.iter().take(10) {
        let rss = *line.1 as f64;
        println!(
            "    {:15}    {:8.1} MiB",
            line.0,
            (rss * 4096.0) / 1024.0 / 1024.0
        );
    }
}

// Sort and print the process list.
fn print_ps_list(mut ps_matrix: Vec<Vec<String>>, header_vec: Vec<String>, pid_col: usize) {
    // Sort and display the process list.
    // The format may change depending on kernel version, but the number of columns and the
    // position of pid, rss, and name should remain fixed, ie:
    //
    //      [  pid  ]   uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name
    //
    // Print the header from header_vec first.
    println!("\nProcesses using most memory:\n");
    println!(
        "{:^7}  {:>8}  {:>6}  {:>10}  {:>8}  {:>16}  {:>10}  {:>15}  {:<15}  {:>8}",
        header_vec[pid_col],     // pid
        header_vec[pid_col + 1], // uid
        header_vec[pid_col + 2],
        header_vec[pid_col + 3],
        header_vec[pid_col + 4], // rss
        header_vec[pid_col + 5],
        header_vec[pid_col + 6],
        header_vec[pid_col + 7],
        header_vec[pid_col + 8], // name
        "MiB"
    );

    // Sort and display the entire process list from the matrix we started with.
    // The RSS field must be converted from a string to an integer in order to sort.
    ps_matrix.sort_by(|a, b| {
        (b[pid_col + 4].parse::<i64>().unwrap()).cmp(&a[pid_col + 4].parse::<i64>().unwrap())
    });

    // Iterate over the sorted process matrix and display the top results.
    for line in ps_matrix.into_iter().take(10) {
        println!(
            "{:>7}  {:>8}  {:>6}  {:>10}  {:>8}  {:>16}  {:>10}  {:>15}  {:<15}  {:>8.1}",
            line[pid_col],     // pid
            line[pid_col + 1], // uid
            line[pid_col + 2],
            line[pid_col + 3],
            line[pid_col + 4], // rss
            line[pid_col + 5],
            line[pid_col + 6],
            line[pid_col + 7],
            line[pid_col + 8], // name
            (line[pid_col + 4].parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0  // size MiB
        );
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();

    if args.len() < 2 {
        eprintln!("USAGE: parseoom [filename]");
        process::exit(1);
    }

    args.next();

    let filename = args.next().expect("Didn't get a filename");

    // read from beginning of last oom kill to end of log
    let input = fs::read_to_string(filename).expect("Could not read filename");
    let i = input
        .rfind("invoked oom-killer")
        .ok_or("string 'invoked oom-killer' not found")?;
    let contents = &input[i..];

    // match from invocation of oom killer to end of process list, just before end of report
    let oom_kill_re = Regex::new(OOM_KILL_RE).unwrap();
    let mat = oom_kill_re
        .captures(contents)
        .ok_or("Could not match an oom kill message in this file")?;
    let oom = mat
        .get(0)
        .expect("Match for 'invoked oom-killer' not found")
        .as_str()
        .lines(); // convert match to a str iterator

    // Clean up the oom kill report for ease of parsing
    let mut cleaned = String::new();
    let oom_end = Regex::new(PS_LIST_END_RE).unwrap();

    // Strip out end of report summary and PID column brackets
    for line in oom {
        // These patterns appear immediately after the end of the ps list.
        // Do not include them in the new string so we know where to stop.
        if oom_end.is_match(line) {
            continue;
        }

        let s = line.replace('[', ""); // clean up PID entries
        let s = s.replace(']', "");

        cleaned.push_str(&s);
        cleaned.push('\n');
    }

    let total_ram_KiB = parse_meminfo_total(&cleaned).expect("No match for total pages RAM.");
    let free_swap_KiB = parse_meminfo_swap(&cleaned).expect("No match for swap.");
    let (m, g) = parse_meminfo_hugepages(&cleaned).expect("No match for huge pages.");
    let total_2_MiB_hugepages_MiB = m / 1024.0;
    let total_1_GiB_hugepages_GiB = g / 1024.0 / 1024.0;
    let unreclaimable_slab_KiB = parse_meminfo_slab(&cleaned).expect("No match for slab.");
    let shmem_KiB = parse_meminfo_shared(&cleaned).expect("No match for shmem");
    let (header_vec, pid_col) = parse_ps_header(&cleaned);
    let ps_string = parse_ps_list(&cleaned).unwrap();
    let ps_matrix = parse_ps_matrix(ps_string);
    let commands = top_consumers(&ps_matrix, pid_col);
    let mut rss_sum = 0;

    // Calculate total memory consumed by user processes
    for value in commands.values() {
        rss_sum += value;
    }

    println!("\nMemory total:");
    println!("    Total RAM: {:.1} GiB ", total_ram_KiB / 1024.0 / 1024.0);

    println!("\nSwap:");
    println!("    Free swap: {} KiB", free_swap_KiB);

    println!("\nHuge Pages:");
    println!(
        "    Allocated 2 MiB huge pages: {:9.1} GiB  --  ({:.1}%)",
        total_2_MiB_hugepages_MiB / 1024.0,
        (m / total_ram_KiB) * 100.0
    );
    println!(
        "    Allocated 1 GiB huge pages: {:9.1} GiB  --  ({:.1}%)",
        total_1_GiB_hugepages_GiB,
        (g / total_ram_KiB) * 100.0
    );

    println!("\nSlab:");
    println!(
        "    Unreclaimable slab: {:.1} MiB  --  ({:.1}%)",
        unreclaimable_slab_KiB / 1024.0,
        (unreclaimable_slab_KiB / total_ram_KiB) * 100.0
    );

    println!("\nShared Memory:");
    println!(
        "    Shared memory: {:.1} MiB  --  ({:.1}%)",
        shmem_KiB / 1024.0,
        (shmem_KiB / total_ram_KiB) * 100.0
    );

    print_top_commands(commands);
    print_ps_list(ps_matrix, header_vec, pid_col);
    println!(
        "\nTotal RSS utilized by user processes: {:.1} MiB   --  ({:.1}%)",
        (rss_sum as f64 * 4096.0) / 1024.0 / 1024.0,
        ((rss_sum as f64 * 4096.0) / 1024.0) / total_ram_KiB * 100.0
    );

    println!();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_total_ram() {
        const TOTAL_RAM_RE: &str = r"(\d+) pages RAM";
        let re = Regex::new(TOTAL_RAM_RE).unwrap();
        let s = "Dec 20 03:17:52 localhost kernel: 75669.637758 5241544212132178 pages RAM\n Dec 20 03:17:52 localhost kernel: 75669.637798 132311 pages reserved";
        assert!(re.is_match(s));
        assert_eq!(parse_meminfo_total(s), Some(2.096_617_684_799_946_8e16));
    }

    #[test]
    fn report_swap() {
        const FREE_SWAP_RE: &str = r"Free swap\s+=.*";
        let re = Regex::new(FREE_SWAP_RE).unwrap();
        let s = "Dec 20 03:17:52 localhost kernel: 75669.636534 Free swap  = 0kB";
        assert!(re.is_match(s));
        assert_eq!(parse_meminfo_swap(s).unwrap(), 0.0);
    }

    #[test]
    fn report_slab() {
        const UNRECLAIMABLE_SLAB_RE: &str = r"slab_unreclaimable:(\d+)";
        let re = Regex::new(UNRECLAIMABLE_SLAB_RE).unwrap();
        let s = "Dec 20 03:17:52 localhost kernel: 75669.607722  slab_reclaimable:4158 slab_unreclaimable:12849311288";
        assert!(re.is_match(s));
        assert_eq!(parse_meminfo_slab(s).unwrap(), 51397245152.0);
    }

    #[test]
    fn report_hugepages() {
        let s = "Dec 20 03:17:52 localhost kernel: 75669.631773 Node 0 hugepages_total=2 hugepages_free=0 hugepages_surp=0 hugepages_size=1048576kB\n Dec 20 03:17:52 localhost kernel: 75669.633105 Node 0 hugepages_total=12 hugepages_free=0 hugepages_surp=0 hugepages_size=2048kB";
        let (m, g) = parse_meminfo_hugepages(s).unwrap();
        assert_eq!(m, 24000.0);
        assert_eq!(g, 2048000.0);

        const HUGEPAGES_RE: &str = r"hugepages_total=(\d+)";
        let re = Regex::new(HUGEPAGES_RE).unwrap();
        let s = "Dec 20 03:17:52 localhost kernel: 75669.631773 Node 0 hugepages_total=512 hugepages_free=0 hugepages_surp=0 hugepages_size=1048576kB";
        assert!(re.is_match(s));
        let s = "Dec 20 03:17:52 localhost kernel: 75669.633105 Node 0 hugepages_total=512 hugepages_free=0 hugepages_surp=0 hugepages_size=2048kB";
        assert!(re.is_match(s));
    }

    #[test]
    fn report_shared() {
        const SHMEM_RE: &str = r"shmem:(\d+)";
        let re = Regex::new(SHMEM_RE).unwrap();
        let s = "Dec 20 03:17:52 localhost kernel: 75669.607722  mapped:70 shmem:147 pagetables:2089 bounce:0";
        assert!(re.is_match(s));
        assert_eq!(parse_meminfo_shared(s).unwrap(), 588.0);
    }

    #[test]
    fn report_ps_usage() {
        const PS_LIST_RE: &str = r"(.*pid.+\bname\b)(?s)(.*)";
        let re = Regex::new(PS_LIST_RE).unwrap();
        let s = "Dec 20 03:17:52 localhost kernel: 75669.641206   pid     uid  tgid total_vm      rss pgtables_bytes swapents oom_score_adj name
Dec 20 03:17:52 localhost kernel: 75669.642775     199     0   199    14838      226   102400       14          -250 systemd-journal
Dec 20 03:17:52 localhost kernel: 75669.644513     255     0   255     5316      159    69632       37         -1000 systemd-udevd";
        assert!(re.is_match(s));
    }
}
