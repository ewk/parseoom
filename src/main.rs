use std::collections::BTreeMap;
use std::env;
use std::iter::FromIterator;
use std::process;
use std::error::Error;
use regex::Regex;
use std::fs;

// Parse the meminfo section of the oom kill report and print the results
fn parse_meminfo(s: &str) {
    // Find total memory
    let re = Regex::new(r"(\d+) pages RAM").unwrap();

    if let Some(x) = re.captures(s) {
        let total_ram = x.get(1).unwrap().as_str();
        let total_ram_mib = (total_ram.parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0 ;
        // physical memory installed will be more than MemTotal reported by /proc/meminfo
        println!("Total RAM: {:.1} MiB ", total_ram_mib)
    } else {
        println!("No match for total_ram");
    }

    // Find free swap at time of oom kill
    let re = Regex::new(r"Free swap\s+=.*").unwrap();

    if let Some(x) = re.captures(s) {
        let swap = x.get(0).unwrap().as_str();
        println!("{}", swap)
    } else {
        println!("No match for swap");
    }

    // The first slab_unreclaimable entry in MemInfo contains the total for all zones, in pages
    let re = Regex::new(r"slab_unreclaimable:(\d+)").unwrap();

    if let Some(x) = re.captures(s) {
        let slab = x.get(1).unwrap().as_str();
        let slab_mib = (slab.parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0;
        println!("Unreclaimable slab: {:.1} MiB", slab_mib);
    } else {
        println!("No match for slab");
    }

    // Find huge page allocations at time of oom kill
    let re = Regex::new(r"hugepages_total=\d").unwrap();

    if let Some(x) = re.captures(s) {
        let hugepages = x.get(0).unwrap().as_str();
        println!("{}", hugepages)
    } else {
        println!("No match for hugepages");
    }

    // Find shared memory
    let re = Regex::new(r"shmem:(\d+)").unwrap();

    if let Some(x) = re.captures(s) {
        let shmem = x.get(1).unwrap().as_str();
        let shmem_mib = (shmem.parse::<f64>().unwrap() * 4096.0) / 1024.0 / 1024.0;
        println!("Shared memory: {:.1} MiB", shmem_mib)
    } else {
        println!("No match for shmem");
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
    let s = fs::read_to_string(filename).expect("Could not read filename");
    let i = s.rfind("invoked oom-killer").ok_or("string 'invoked oom-killer' not found")?;
    let contents = &s[i..];

    // match from invocation of oom killer to end of process list, just before end of report
    let oom_kill_re = Regex::new(r"(?s)((\w+\s)?invoked oom-killer.*)[oO]ut of memory:")
        .unwrap();
    let mat = oom_kill_re.captures(&contents).ok_or("Could not match an oom kill message in this file")?;
    let oom = mat.get(1).expect("Match for 'invoked oom-killer' not found")
        .as_str()
        .lines();   // convert match to a str iterator

    // Clean up the oom kill report for ease of parsing
    let mut cleaned = String::new();
    let log_entry_re = Regex::new(r"((\w+\s+\d+\s\d+:\d+:\d+\s)?[-\w+]+\s(kernel:)\s?)?(\[\s*\d+\.\d+\]\s+)?").unwrap();
    // Strip out beginning of line log noise, end of report summary, and PID column brackets
    for line in oom {
        // These patterns appear immediately after the end of the ps list.
        // Do not include them in the new string so we know where to stop.
        if Regex::new(r"Out of memory:|oom-kill:|Memory cgroup").unwrap().is_match(line) {
            continue;
        }

        let s = log_entry_re.replace_all(line, "");   // strip out log timestamp noise
        let s = s.replace("[", "");                   // clean up PID entries
        let s = s.replace("]", "");

        cleaned.push_str(&s);
        cleaned.push('\n');
    }

    parse_meminfo(&cleaned);

    // Capture the values in the process list after the header
    let re = Regex::new(r"(?s)pid.+name(.*)").unwrap();

    // Sort processes by memory used and report the commands using the most memory
    if let Some(x) = re.captures(&cleaned) {
        let ps = x.get(1).unwrap().as_str().trim();

        // Convert the process list into a matrix of strings
        let mut v = ps.lines()
            .map(|s| s.trim().split_whitespace().map(String::from).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // First identify unique commands using the most memory
        // Create a map with a running total of RSS in use by unique commands
        let mut commands: BTreeMap<&str, i64> = BTreeMap::new();
        for line in v.iter() {
            *commands.entry(&line[8]).or_insert(0) += line[4].parse::<i64>().unwrap();
        }

        // convert the map back to a vector for sorting
        let mut command_vec = Vec::from_iter(commands.iter());
        command_vec.sort_by(|a, b| a.1.cmp(b.1).reverse());

        println!("\nTop 20 unique commands using memory:\n");
        for line in command_vec.iter().take(20) {
            println!("{}: {} KiB", line.0, (line.1 * 4096) / 1024);
        }

        // Sort and display the ps list
        println!("\nProcesses using most memory:\n");
        println!("pid     uid     tgid  total_vm  rss   cpu oom_adj  oom_score_adj  name");

        // We need to convert RSS from a string to an integer in order to sort correctly.
        // The RSS column is 5, but the index is 4.
        v.sort_by(|a, b| (a[4].parse::<i64>().unwrap()).cmp(&b[4].parse::<i64>().unwrap()));

        // Put the sorted string back together so we can display the results.
        // FIXME this has to run last so the iterator can consume the vector
        for line in v.into_iter().rev().take(20) {
            for x in line.iter() {
                print!("{}\t", x);
            }
            println!();
        }

    } else {
        println!("No match for ps");
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Make sure we can match various log formats containing an oom kill
    fn log_entry_pattern() {
        let re = Regex::new(r"((\w+\s+\d+\s\d+:\d+:\d+\s)?[-\w+]+\s(kernel:)\s?)?(\[\s*\d+\.\d+\]\s+)?").unwrap();

        let t1 = "Oct 24 00:00:11 noplacelikehome kernel: [11686.040488]  [<c10e1c15>] dump_header.isra.7+0x85/0xc0";
        let t2 = "June 25 23:09:46 localhost kernel: numactl invoked oom-killer: gfp_mask=0x2084d0, order=1, oom_score_adj=0";
        let t3 = "[ 5720.256923] [PID]     uid  tgid total_vm      rss cpu oom_adj oom_score_adj name";
        let t4 = "Nov 11 19:47:17 localhost kernel: containerd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=-999";
        let t5 = "May 12 13:13:47 local-host kernel: sshd invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0";
        let t6 = "Nov 11 15:20:04 home kernel: [ 2323]   999  2323   156297     1709      66      235             0 polkitd";
        let t7 = "Jun  4 15:36:26 localhost kernel: JIT invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0";
        let t8 = "Apr  5 15:06:40 SHOUTYCAPS kernel: httpd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0";

        assert_eq!(re.replace_all(t1, ""),
            "[<c10e1c15>] dump_header.isra.7+0x85/0xc0");
        assert_eq!(re.replace_all(t2, ""),
            "numactl invoked oom-killer: gfp_mask=0x2084d0, order=1, oom_score_adj=0");
        assert_eq!(re.replace_all(t3, ""),
            "[PID]     uid  tgid total_vm      rss cpu oom_adj oom_score_adj name");
        assert_eq!(re.replace_all(t4, ""),
            "containerd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=-999");
        assert_eq!(re.replace_all(t5, ""),
            "sshd invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), order=0, oom_score_adj=0");
        assert_eq!(re.replace_all(t6, ""),
            "[ 2323]   999  2323   156297     1709      66      235             0 polkitd");
        assert_eq!(re.replace_all(t7, ""),
            "JIT invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0");
        assert_eq!(re.replace_all(t8, ""),
            "httpd invoked oom-killer: gfp_mask=0x201da, order=0, oom_score_adj=0");
    }

}
