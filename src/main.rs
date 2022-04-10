use regex::Regex;
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::iter::FromIterator;
use std::process;

const OOM_KILL_RE: &str = r"(?s)((\w+\s)?invoked oom-killer.*?)(?-s:.*?[oO]ut of memory:){1}?";
const PS_LIST_END_RE: &str = r"Out of memory:|oom-kill:|Memory cgroup";

// Parse the meminfo section of the oom kill report and print the results
fn parse_meminfo_total(s: &str) {
    const TOTAL_RAM_RE: &str = r"(\d+) pages RAM";

    // Find total memory
    let re = Regex::new(TOTAL_RAM_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let total_ram = x.get(1).unwrap().as_str();
        let total_ram_mib = (total_ram.parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0;
        // physical memory installed will be more than MemTotal reported by /proc/meminfo
        println!("Total RAM: {:.1} MiB ", total_ram_mib)
    } else {
        println!("No match for total_ram");
    }
}

fn parse_meminfo_swap(s: &str) {
    const FREE_SWAP_RE: &str = r"Free swap\s+=.*";
    // Find free swap at time of oom kill
    let re = Regex::new(FREE_SWAP_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let swap = x.get(0).unwrap().as_str();
        println!("{}", swap)
    } else {
        println!("No match for swap");
    }
}

fn parse_meminfo_slab(s: &str) {
    const UNRECLAIMABLE_SLAB_RE: &str = r"slab_unreclaimable:(\d+)";

    // The first slab_unreclaimable entry in MemInfo contains the total for all zones, in pages
    let re = Regex::new(UNRECLAIMABLE_SLAB_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let slab = x.get(1).unwrap().as_str();
        let slab_mib = (slab.parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0;
        println!("Unreclaimable slab: {:.1} MiB", slab_mib);
    } else {
        println!("No match for slab");
    }
}

fn parse_meminfo_hugepages(s: &str) {
    const HUGEPAGES_RE: &str = r"hugepages_total=(\d+)";
    // Find huge page allocations at time of oom kill
    let re = Regex::new(HUGEPAGES_RE).unwrap();
    let mut hugepages = 0;

    for caps in re.captures_iter(s) {
        hugepages += &caps[1].parse::<i64>().unwrap();
    }

    println!("Number of allocated huge pages: {}", hugepages);
}

fn parse_meminfo_shared(s: &str) {
    const SHMEM_RE: &str = r"shmem:(\d+)";
    // Find shared memory
    let re = Regex::new(SHMEM_RE).unwrap();

    if let Some(x) = re.captures(s) {
        let shmem = x.get(1).unwrap().as_str();
        let shmem_mib = (shmem.parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0;
        println!("Shared memory: {:.1} MiB", shmem_mib)
    } else {
        println!("No match for shmem");
    }
}

fn report_ram_usage(cleaned: &str) {
    const PS_LIST_RE: &str = r"(.*pid.+\bname\b)(?s)(.*)";

    // Capture the process header and find the position of the 'pid' column
    let re = Regex::new(PS_LIST_RE).unwrap();
    let ps_header = re
        .captures(&cleaned)
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

    // Capture the values in the process list after the header
    let re = Regex::new(PS_LIST_RE).unwrap();

    // Sort processes by memory used and report the commands using the most memory
    if let Some(x) = re.captures(&cleaned) {
        let ps = x.get(2).unwrap().as_str().trim();

        // Convert the process list into a matrix of strings
        let mut v = ps
            .lines()
            .map(|s| {
                s.trim()
                    .split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // First identify unique commands using the most memory
        // Create a map with a running total of RSS in use by unique commands
        let mut commands: BTreeMap<&str, i64> = BTreeMap::new();
        for line in v.iter() {
            *commands.entry(&line[pid_col + 8]).or_insert(0) +=
                line[pid_col + 4].parse::<i64>().unwrap();
        }

        // convert the map back to a vector for sorting
        let mut command_vec = Vec::from_iter(commands.iter());
        command_vec.sort_by(|a, b| a.1.cmp(b.1).reverse());

        println!("\nTop 20 unique commands using memory:\n");
        for line in command_vec.iter().take(20) {
            let rss = *line.1 as f64;
            println!("{}: {:.1} MiB", line.0, (rss * 4096.0) / 1024.0 / 1024.0);
        }

        // Sort and display the ps list
        println!("\nProcesses using most memory:\n");
        println!(
            "{:^7} {:>5} {:>5} {:>8} {:>8} {:<14} {:<8} {:<13} {:<4}",
            header_vec[pid_col],
            header_vec[pid_col + 1],
            header_vec[pid_col + 2],
            header_vec[pid_col + 3],
            header_vec[pid_col + 4],
            header_vec[pid_col + 5],
            header_vec[pid_col + 6],
            header_vec[pid_col + 7],
            header_vec[pid_col + 8]
        );

        // We need to convert RSS from a string to an integer in order to sort correctly.
        v.sort_by(|a, b| {
            (a[pid_col + 4].parse::<i64>().unwrap()).cmp(&b[pid_col + 4].parse::<i64>().unwrap())
        });

        // Put the sorted string back together so we can display the results.
        // FIXME this has to run last so the iterator can consume the vector
        for line in v.into_iter().rev().take(20) {
            println!(
                "{:>7} {:>5} {:>5} {:>8} {:>8} {:^14} {:>8} {:>13} {:<15}",
                line[pid_col],
                line[pid_col + 1],
                line[pid_col + 2],
                line[pid_col + 3],
                line[pid_col + 4],
                line[pid_col + 5],
                line[pid_col + 6],
                line[pid_col + 7],
                line[pid_col + 8]
            );
        }
    } else {
        println!("No match for ps");
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

        let s = line.replace("[", ""); // clean up PID entries
        let s = s.replace("]", "");

        cleaned.push_str(&s);
        cleaned.push('\n');
    }

    parse_meminfo_total(&cleaned);
    parse_meminfo_swap(&cleaned);
    parse_meminfo_slab(&cleaned);
    parse_meminfo_hugepages(&cleaned);
    parse_meminfo_shared(&cleaned);
    report_ram_usage(&cleaned);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Make sure we can match various log formats containing an oom kill
    fn log_entry_pattern() {
        let re = Regex::new(LOG_ENTRY_RE).unwrap();

        let t1 = "Oct 24 00:00:11 noplacelikehome kernel: [11686.040488]  [<c10e1c15>] dump_header.isra.7+0x85/0xc0";
        let t2 = "June 25 23:09:46 localhost kernel: numactl invoked oom-killer: gfp_mask=0x2084d0, order=1, oom_score_adj=0";
        let t3 =
            "[ 5720.256923] [PID]     uid  tgid total_vm      rss cpu oom_adj oom_score_adj name";
        let t4 = "Nov 11 19:47:17 localhost kernel: containerd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=-999";
        let t5 = "May 12 13:13:47 local-host kernel: sshd invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0";
        let t6 = "Nov 11 15:20:04 home kernel: [ 2323]   999  2323   156297     1709      66      235             0 polkitd";
        let t7 = "Jun  4 15:36:26 localhost kernel: JIT invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0";
        let t8 = "Apr  5 15:06:40 SHOUTYCAPS kernel: httpd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0";

        assert_eq!(
            re.replace_all(t1, ""),
            "[<c10e1c15>] dump_header.isra.7+0x85/0xc0"
        );
        assert_eq!(
            re.replace_all(t2, ""),
            "numactl invoked oom-killer: gfp_mask=0x2084d0, order=1, oom_score_adj=0"
        );
        assert_eq!(
            re.replace_all(t3, ""),
            "[PID]     uid  tgid total_vm      rss cpu oom_adj oom_score_adj name"
        );
        assert_eq!(
            re.replace_all(t4, ""),
            "containerd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=-999"
        );
        assert_eq!(re.replace_all(t5, ""),
            "sshd invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0");
        assert_eq!(
            re.replace_all(t6, ""),
            "[ 2323]   999  2323   156297     1709      66      235             0 polkitd"
        );
        assert_eq!(
            re.replace_all(t7, ""),
            "JIT invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0"
        );
        assert_eq!(
            re.replace_all(t8, ""),
            "httpd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0"
        );
    }
}
