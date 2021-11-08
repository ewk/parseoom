use std::env;
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
    let re = Regex::new(r"(?s)(\w+\s)?invoked oom-killer.*Out of memory: Kill process.*child")
        .unwrap();
    let mat = re.captures(&contents).ok_or("Could not find an oom kill message in this file")?;
    let oom = mat.get(0).expect("Match for 'invoked oom-killer' not found")
        .as_str()
        .lines();   // convert match to a str iterator

    // Clean up the oom kill report for ease of parsing
    let mut cleaned = String::new();
    let re = Regex::new(r"((\w+\s\d+\s\d+:\d+:\d+\s)?\w+\s(kernel:)\s?)?(\[\s*\d+\.\d+\]\s+)?").unwrap();
    // Strip out beginning of line log noise and PID column brackets
    for line in oom {
        let s = re.replace_all(line, "");   // strip out log timestamp noise
        let s = s.replace("[ ", "");        // clean up PID entries
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
    let re = Regex::new(r"(?s)pid.+name(.*)Out of memory: Kill process").unwrap();

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

        println!("\nProcesses using most memory:\n");
        println!("pid     uid     tgid  total_vm  rss   cpu oom_adj  oom_score_adj  name");

        // Put the sorted string back together so we can display the results.
        for line in v {
            let s: String = line.into_iter().collect::<Vec<String>>().join("\t");
            println!("{}", s);
        }

        // Let awk report the top unique commands using memory, because that's what awk is for
        fs::write("ps.out", ps)?;
        let unique = r#"
The list of running processes when the oom killer fired has been saved to the file 'ps.out'.
Run the following command to print the unique processes that were using the most memory.

    awk '{a[$9] += $5} END { for (item in a) {printf "%20s %10s KiB \n", item, a[item]} }' ps.out | sort -rnk2 | head -n 20
"#;

        println!("{}", unique);

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
