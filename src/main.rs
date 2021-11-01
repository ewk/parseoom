use std::env;
use std::process;
use std::process::{Command, Stdio};
use std::error::Error;
use regex::Regex;
use std::fs;

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args();

    if args.len() < 2 {
        eprintln!("USAGE: oomparse [filename]");
        process::exit(1);
    }

    args.next();

    let filename = args.next().expect("Didn't get a filename");

    // read in only from beginning of last oom kill to end of report
    // TODO doesn't read the *last* oom messages
    let contents = fs::read_to_string(filename).expect("Could not read filename");

    let re = Regex::new(r"(?s)\w+\sinvoked oom-killer.*Out of memory: Kill process.*child")
        .unwrap();
    let mat = re.captures(&contents).ok_or("Could not find an oom kill message in this file")?;
    let oom = mat.get(0).expect("Match for 'invoked oom-killer' not found")
        .as_str()
        .lines();   // convert match to a str iterator

    let re = Regex::new(r"(.*)?kernel:\s*(\[\d+\.\d+\])?\s").unwrap();
    let mut cleaned = String::new();

    // Strip out beginning of line log noise and PID column brackets
    for line in oom {
        let s = re.replace_all(line, "");   // strip out log timestamp noise
        let s = s.replace("[ ", "");        // clean up PID entries
        let s = s.replace("]", "");

        cleaned.push_str(&s);
        cleaned.push('\n');
    }

    println!("{}", cleaned);
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

    // Sort process list by RSS
    if let Some(x) = re.captures(&cleaned) {
        let ps = x.get(1).unwrap().as_str().trim();

        println!("Processes using most memory:\n");
        println!("pid    uid  tgid total_vm      rss cpu oom_adj oom_score_adj name");

        let mut output_child = Command::new("echo")
            .arg(ps)
            .stdout(Stdio::piped())
            .spawn()?;

        if let Some(output) = output_child.stdout.take() {
            let mut sort_output_child = Command::new("sort")
                .arg("-nk5")
                .stdin(output)
                .spawn()?;

            sort_output_child.wait()?;
        }
    } else {
        println!("No match for ps");
    }

    Ok(())
}
