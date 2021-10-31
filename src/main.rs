use std::env;
use std::process;
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

    // Build new string stripping out beginning of line containing log noise and PID column
    for line in oom {
        let s = re.replace_all(&line, "");  // strip out log timestamp noise
        let s = s.replace("[ ", "");        // clean up PID entry
        let s = s.replace("]", "");         // clean up PID entry

        cleaned.push_str(&s);
        cleaned.push_str("\n");
    }

    println!("{}", cleaned);
    Ok(())
}
