use std::collections::BTreeMap;
use std::env;
use std::iter::FromIterator;
use std::process;
use std::error::Error;
use regex::Regex;
use std::fs;

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

    // match from invocation of oom killer to end of report
    let re = Regex::new(r"(?s)((\w+\s)?invoked oom-killer.*)[oO]ut of memory:")
        .unwrap();
    let mat = re.captures(&contents).ok_or("Could not find an oom kill message in this file")?;
    let oom = mat.get(1).expect("Match for 'invoked oom-killer' not found")
        .as_str()
        .lines();   // convert match to a str iterator

    // Clean up the oom kill report for ease of parsing
    let mut cleaned = String::new();
    let re = Regex::new(r"((\w+\s\d+\s\d+:\d+:\d+\s)?\w+\s(kernel:)\s?)?(\[\s*\d+\.\d+\]\s+)?").unwrap();
    // Strip out beginning of line log noise, end of report summary, and PID column brackets
    for line in oom {
        if Regex::new(r"Out of memory:|oom-kill:|Memory cgroup").unwrap().is_match(line) {
            continue;
        }

        let s = re.replace_all(line, "");   // strip out log timestamp noise
        let s = s.replace("[", "");        // clean up PID entries
        let s = s.replace("]", "");

        cleaned.push_str(&s);
        cleaned.push('\n');
    }

    // Find free swap at time of oom kill
    let re = Regex::new(r"Free swap\s+=.*").unwrap();

    if let Some(x) = re.captures(&cleaned) {
        let swap = x.get(0).unwrap().as_str();
        println!("{}", swap)
    } else {
        println!("No match for swap");
    }

    // The first slab_unreclaimable entry in MemInfo contains the total for all zones, in pages
    let re = Regex::new(r"slab_unreclaimable:(\d+)").unwrap();

    if let Some(x) = re.captures(&cleaned) {
        let slab = x.get(1).unwrap().as_str();
        let slab_mib = (slab.parse::<i64>().unwrap() * 4096) / 1024 / 1024;
        println!("Unreclaimable slab: {} MiB", slab_mib);
    } else {
        println!("No match for slab");
    }

    // Find huge page allocations at time of oom kill
    let re = Regex::new(r"hugepages_total=\d").unwrap();

    if let Some(x) = re.captures(&cleaned) {
        let hugepages = x.get(0).unwrap().as_str();
        println!("{}", hugepages)
    } else {
        println!("No match for hugepages");
    }

    // Capture the values in the process list after the header
    let re = Regex::new(r"(?s)pid.+name(.*)").unwrap();

    // Sort processes by memory used and report the commands using the most memory
    if let Some(x) = re.captures(&cleaned) {
        let ps = x.get(1).unwrap().as_str().trim();

        // Convert the process list into a matrix of strings
        let mut v = ps.lines()
            .map(|s| s.trim().split_whitespace().map(String::from).collect::<Vec<_>>())
            .collect::<Vec<_>>();

        // The RSS column is 5, but the index is 4. We need to convert RSS from a string
        // to an integer in order to sort correctly.
        v.sort_by(|a, b| (a[4].parse::<i64>().unwrap()).cmp(&b[4].parse::<i64>().unwrap()));

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

        println!("\nProcesses using most memory:\n");
        println!("pid     uid     tgid  total_vm  rss   cpu oom_adj  oom_score_adj  name");

        // Put the sorted string back together so we can display the results.
        // FIXME this has to run last so the iterator can consume the vector
        for line in v {
            let s: String = line.into_iter().collect::<Vec<String>>().join("\t");
            println!("{}", s);
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
        let re = Regex::new(r"((\w+\s\d+\s\d+:\d+:\d+\s)?\w+\s(kernel:)\s?)?(\[\s*\d+\.\d+\]\s+)?").unwrap();

        let l1 = "Oct 24 00:00:11 localhost kernel: [11686.040488]  [<c10e1c15>] dump_header.isra.7+0x85/0xc0";
        let l2 = "June 25 23:09:46 localhost kernel: numactl invoked oom-killer: gfp_mask=0x2084d0, order=1, oom_score_adj=0";
        let l3 = "[ 5720.256923] [PID]     uid  tgid total_vm      rss cpu oom_adj oom_score_adj name";

        assert_eq!(re.replace_all(l1, ""),
            "[<c10e1c15>] dump_header.isra.7+0x85/0xc0");
        assert_eq!(re.replace_all(l2, ""),
            "numactl invoked oom-killer: gfp_mask=0x2084d0, order=1, oom_score_adj=0");
        assert_eq!(re.replace_all(l3, ""),
            "[PID]     uid  tgid total_vm      rss cpu oom_adj oom_score_adj name");
    }

}
