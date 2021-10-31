use std::env;
use std::process;
use std::fs;
use regex::Regex;

fn main() {
    let mut args = env::args();

    if args.len() < 2 {
        process::exit(1);
    }

    args.next();

    let filename = match args.next() {
        Some(arg) => arg,
        None => ("Didn't get a file name".to_string()),
    };

    // read in only from beginning of last oom kill to end of report
    // TODO doesn't read the *last* oom messages
    let contents = fs::read_to_string(filename).unwrap();

    let re = Regex::new(r"(?s)\w+\sinvoked oom-killer.*Out of memory: Kill process.*child").unwrap();
    let mat = re.captures(&contents).unwrap();
    let oom = mat.get(0).unwrap().as_str().lines();

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
}
