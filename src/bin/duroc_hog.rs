//! File system secret scanner in Rust
//!
//! # Usage
//! ```
//!     duroc_hog [FLAGS] [OPTIONS] <FSPATH>
//!
//!FLAGS:
//!        --caseinsensitive    Sets the case insensitive flag for all regexes
//!        --entropy            Enables entropy scanning
//!        --prettyprint        Outputs the JSON in human readable format
//!        --recursive          Scans all subdirectories underneath the supplied path
//!        --archives           Scans archives within the directory
//!    -v, --verbose            Sets the level of debugging information
//!    -h, --help               Prints help information
//!    -V, --version            Prints version information
//!
//!OPTIONS:
//!        --default_entropy_threshold <DEFAULT_ENTROPY_THRESHOLD>    Default entropy threshold (0.6 by default)
//!    -a, --allowlist <ALLOWLIST>          Sets a custom allowlist JSON file
//!    -o, --outputfile <OUTPUT>            Sets the path to write the scanner results to (stdout by default)
//!    -r, --regex <REGEX>                  Sets a custom regex JSON file, defaults to built-in

//!
//!ARGS:
//!    <FSPATH>    Sets the path of the file system to scan.
//! ```

extern crate clap;

extern crate tempdir;

extern crate chrono;

extern crate encoding;

use clap::{Arg, ArgAction, ArgMatches, Command};
use log::{self, debug, error, info};
use serde::{Deserialize, Serialize};
use simple_error::SimpleError;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::{io, str};
use walkdir::WalkDir;

use encoding::all::ASCII;
use encoding::{DecoderTrap, Encoding};
use path_clean::PathClean;
use rusty_hog_scanner::{SecretScanner, SecretScannerBuilder};

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone, Default)]
/// `serde_json` object that represents a single found secret - finding
pub struct FileFinding {
    //    branch: String, // this requires a walk of the commits for each finding, so lets leave it out for the moment
    #[serde(rename = "stringsFound")]
    pub strings_found: Vec<String>,
    pub path: String,
    pub reason: String,
    /// Every detection rule that produced this finding, sorted and deduplicated.
    /// `reason` holds the highest-confidence entry (a named regex rule wins over
    /// the generic entropy detector).
    pub reasons: Vec<String>,
    pub linenum: usize,
    pub lineindextuples: Vec<(usize, usize)>,
}

const ZIPEXTENSIONS: &[&str] = &["zip"];
const TAREXTENSIONS: &[&str] = &["tar", "gem"];
const GZEXTENSIONS: &[&str] = &["gz", "tgz"];

/// Main entry function that uses the [clap crate](https://docs.rs/clap/2.33.0/clap/)
fn main() {
    let matches = Command::new("duroc_hog")
        .version("1.0.11")
        .author("Scott Cutler <scutler@newrelic.com>")
        .about("File system secret scanner in Rust")
        .arg(
            Arg::new("REGEX")
                .short('r')
                .long("regex")
                .action(ArgAction::Set)
                .value_name("REGEX")
                .help("Sets a custom regex JSON file"),
        )
        .arg(
            Arg::new("FSPATH")
                .required(true)
                .action(ArgAction::Set)
                .value_name("PATH")
                .help("Sets the path of the directory or file to scan."),
        )
        .arg(
            Arg::new("NORECURSIVE")
                .long("norecursive")
                .action(ArgAction::SetTrue)
                .help(
                    "Disable recursive scanning of all subdirectories underneath the supplied path",
                ),
        )
        .arg(
            Arg::new("VERBOSE")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .help("Sets the level of debugging information"),
        )
        .arg(
            Arg::new("ENTROPY")
                .long("entropy")
                .action(ArgAction::SetTrue)
                .help("Enables entropy scanning"),
        )
        .arg(
            Arg::new("DEFAULT_ENTROPY_THRESHOLD")
                .long("default_entropy_threshold")
                .action(ArgAction::Set)
                .default_value("0.6")
                .value_parser(clap::value_parser!(f32))
                .help("Default entropy threshold (0.6 by default)"),
        )
        .arg(
            Arg::new("UNZIP")
                .short('z')
                .long("unzip")
                .action(ArgAction::SetTrue)
                .help("Recursively scans archives (ZIP and TAR) in memory (dangerous)"),
        )
        .arg(
            Arg::new("CASE")
                .long("caseinsensitive")
                .action(ArgAction::SetTrue)
                .help("Sets the case insensitive flag for all regexes"),
        )
        .arg(
            Arg::new("OUTPUT")
                .short('o')
                .long("outputfile")
                .action(ArgAction::Set)
                .help("Sets the path to write the scanner results to (stdout by default)"),
        )
        .arg(
            Arg::new("PRETTYPRINT")
                .long("prettyprint")
                .action(ArgAction::SetTrue)
                .help("Outputs the JSON in human readable format"),
        )
        .arg(
            Arg::new("ALLOWLIST")
                .short('a')
                .long("allowlist")
                .action(ArgAction::Set)
                .help("Sets a custom allowlist JSON file"),
        )
        .get_matches();
    match run(&matches) {
        Ok(()) => {}
        Err(e) => error!("Error running command: {}", e),
    }
}

/// Main logic contained here. Get the CLI variables, and use them to initialize a GitScanner
fn run(arg_matches: &ArgMatches) -> Result<(), SimpleError> {
    // Set logging
    SecretScanner::set_logging(arg_matches.get_count("VERBOSE").into());

    // Initialize some more variables
    let secret_scanner = SecretScannerBuilder::new().conf_argm(arg_matches).build();
    // let scan_entropy = arg_matches.is_present("ENTROPY");
    let recursive = !arg_matches.get_flag("NORECURSIVE");
    let fspath = Path::new(arg_matches.get_one::<String>("FSPATH").unwrap());
    let default_path = String::from("");
    let output_file = Path::new(arg_matches.get_one("OUTPUT").unwrap_or(&default_path));
    let unzip: bool = arg_matches.get_flag("UNZIP");

    debug!("fspath: {:?}", fspath);

    // First verify the path
    if !Path::exists(fspath) {
        return Err(SimpleError::new("Path does not exist"));
    } else {
        info!("path verification succeeded");
    }

    let mut output: Vec<FileFinding> = Vec::new();

    if Path::is_dir(fspath) {
        output.extend(scan_dir(
            fspath,
            output_file,
            &secret_scanner,
            recursive,
            unzip,
        ));
    } else {
        let f = File::open(fspath).unwrap();
        output.extend(scan_file(fspath, &secret_scanner, f, "", unzip));
    }

    output.retain(|ff| !secret_scanner.is_allowlisted_path(&ff.reason, ff.path.as_bytes()));
    sort_findings(&mut output);

    info!("Found {} secrets", output.len());
    match secret_scanner.output_findings_ordered(&output) {
        Ok(_) => Ok(()),
        Err(err) => Err(SimpleError::with(
            "failed to output findings",
            SimpleError::new(err.to_string()),
        )),
    }
}

fn scan_dir(
    fspath: &Path,
    output_file: &Path,
    ss: &SecretScanner,
    recursive: bool,
    unzip: bool,
) -> Vec<FileFinding> {
    let mut output: Vec<FileFinding> = Vec::new();

    let scanning_closure = |file_path: &Path| {
        let f = File::open(file_path).unwrap();
        let mut inner_findings = scan_file(file_path, &ss, f, "", unzip);
        output.append(&mut inner_findings);
    };

    if recursive {
        recursive_dir_scan(fspath, Path::new(output_file), scanning_closure)
    } else {
        flat_dir_scan(fspath, Path::new(output_file), scanning_closure)
    };

    output
}

fn recursive_dir_scan<C>(fspath: &Path, output_file: &Path, mut closure: C)
where
    C: FnMut(&Path),
{
    for entry in WalkDir::new(fspath).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() && PathBuf::from(entry.path()).clean() != output_file {
            closure(&entry.path());
        }
    }
}

fn flat_dir_scan<C>(fspath: &Path, output_file: &Path, mut closure: C)
where
    C: FnMut(&Path),
{
    let dir_contents: Vec<PathBuf> = fspath
        .read_dir()
        .expect("read_dir call failed")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().unwrap().is_file())
        .map(|e| e.path())
        .inspect(|e| {
            debug!(
                "clean path: {:?}, output_file: {:?}",
                &e.clean(),
                output_file
            )
        })
        .filter(|e| e.clean() != output_file)
        .collect();
    debug!("dir_contents: {:?}", dir_contents);

    for file_path in dir_contents {
        closure(&file_path);
    }
}

fn scan_file<R: Read + io::Seek>(
    file_path: &Path,
    ss: &SecretScanner,
    mut reader: R,
    path_prefix: &str,
    unzip: bool,
) -> Vec<FileFinding> {
    let mut findings: Vec<FileFinding> = Vec::new();
    let path_string = String::from(Path::new(path_prefix).join(file_path).to_str().unwrap());
    info!("scan_file({:?})", path_string);
    let ext: String = match file_path.extension() {
        Some(osstr) => String::from(osstr.to_str().unwrap_or("")).to_ascii_lowercase(),
        None => String::from(""),
    };

    // https://stackoverflow.com/questions/23975391/how-to-convert-a-string-into-a-static-str
    if ZIPEXTENSIONS.contains(&&*ext) && unzip {
        let mut zip = zip::ZipArchive::new(reader).unwrap();
        for i in 0..zip.len() {
            let mut innerfile = zip.by_index(i).unwrap();
            // by using read_to_end we are decompressing the data (expensive)
            // and moving it (inefficient) *but* that means we can recursively decompress
            let mut innerdata: Vec<u8> = Vec::new();
            let read_result = innerfile.read_to_end(&mut innerdata);
            if read_result.is_err() {
                info!("read error within ZIP file");
                continue;
            }
            let new_reader = Cursor::new(innerdata);
            let mut inner_findings = scan_file(
                innerfile.enclosed_name().unwrap(),
                ss,
                new_reader,
                &path_string,
                unzip,
            );
            for d in &inner_findings {
                info!("FileFinding: {:?}", d);
            }
            findings.append(&mut inner_findings);
        }
        findings
    } else if TAREXTENSIONS.contains(&&*ext) && unzip {
        let mut tarobj = tar::Archive::new(reader);
        let tar_entries = tarobj.entries().unwrap();
        for entry_result in tar_entries {
            let mut inner_entry = entry_result.unwrap();
            let mut innerdata: Vec<u8> = Vec::new();
            let read_result = inner_entry.read_to_end(&mut innerdata);
            if read_result.is_err() {
                info!("read error within TAR file");
                continue;
            }
            let new_reader = Cursor::new(innerdata);
            let mut inner_findings = scan_file(
                inner_entry.path().unwrap().as_ref(),
                ss,
                new_reader,
                &path_string,
                unzip,
            );
            for d in &inner_findings {
                info!("FileFinding: {:?}", d);
            }
            findings.append(&mut inner_findings);
        }
        findings
    } else if GZEXTENSIONS.contains(&&*ext) && unzip {
        let mut decompressor = flate2::read::GzDecoder::new(reader);
        let mut innerdata: Vec<u8> = Vec::new();
        let read_result = decompressor.read_to_end(&mut innerdata);
        if read_result.is_err() {
            info!("read error within ZIP file");
            return findings;
        }
        let new_reader = Cursor::new(innerdata);
        let mut tempstring = String::from(file_path.file_stem().unwrap().to_str().unwrap());
        if ext.to_ascii_lowercase() == "tgz" {
            tempstring.push_str(".tar");
        }
        let inner_path: &Path = Path::new(&tempstring);
        info!("gunzip inner path: {:?}", inner_path);
        let mut inner_findings = scan_file(inner_path, ss, new_reader, &path_string, unzip);
        for d in &inner_findings {
            info!("FileFinding: {:?}", d);
        }
        findings.append(&mut inner_findings);
        findings
    } else {
        let mut data = Vec::new();
        let read_result = reader.read_to_end(&mut data);
        if read_result.is_err() {
            info!("read error for file {}", path_string);
        }
        scan_bytes(data, ss, path_string)
    }
}

/// A single detection rule hit before overlapping hits are merged together.
#[derive(Clone, Debug)]
struct RawFinding {
    reason: String,
    start: usize,
    end: usize,
    string_found: String,
}

/// Two half-open byte ranges overlap when each starts before the other ends.
/// Touching ranges (one ends where the next starts) are not considered overlapping.
fn ranges_overlap(start_a: usize, end_a: usize, start_b: usize, end_b: usize) -> bool {
    start_a < end_b && start_b < end_a
}

/// Sort (and collapse exact duplicates) so the serialized JSON is byte-identical across runs.
fn sort_findings(findings: &mut Vec<FileFinding>) {
    findings.sort_by(|a, b| {
        (
            &a.path,
            a.linenum,
            &a.lineindextuples,
            &a.reasons,
            &a.strings_found,
        )
            .cmp(&(
                &b.path,
                b.linenum,
                &b.lineindextuples,
                &b.reasons,
                &b.strings_found,
            ))
    });
    findings.dedup();
}

fn scan_bytes(input: Vec<u8>, ss: &SecretScanner, path: String) -> Vec<FileFinding> {
    info!("scan_bytes: {:?}", path);
    let mut findings: Vec<FileFinding> = Vec::new();
    // Main loop - split the data based on newlines, then run get_matches() on each line,
    // then make a list of findings in output
    let lines = input.split(|&x| (x as char) == '\n');
    for (index, new_line) in lines.enumerate() {
        let results = ss.matches_entropy(new_line);
        // Flatten into one entry per (rule, match) so overlaps across detection
        // types (e.g. a regex rule and the generic entropy detector) can be merged
        // into a single finding instead of being reported twice.
        let mut raw_hits: Vec<RawFinding> = Vec::new();
        for (r, matches) in results {
            for m in matches {
                let result = ASCII
                    .decode(&new_line[m.start()..m.end()], DecoderTrap::Ignore)
                    .unwrap_or_else(|_| "<STRING DECODE ERROR>".parse().unwrap());
                raw_hits.push(RawFinding {
                    reason: r.clone(),
                    start: m.start(),
                    end: m.end(),
                    string_found: result,
                });
            }
        }
        if raw_hits.is_empty() {
            continue;
        }
        // Deterministic ordering before merging: position first, then rule name.
        raw_hits.sort_by(|a, b| {
            (a.start, a.end, &a.reason, &a.string_found).cmp(&(
                b.start,
                b.end,
                &b.reason,
                &b.string_found,
            ))
        });

        // Greedily group overlapping hits. Hits are sorted by start position, so a
        // new hit can only overlap the most recently opened group.
        let mut merged_groups: Vec<Vec<RawFinding>> = Vec::new();
        for hit in raw_hits {
            let overlaps_last = match merged_groups.last() {
                Some(group) => group.iter().any(|existing| {
                    ranges_overlap(existing.start, existing.end, hit.start, hit.end)
                }),
                None => false,
            };
            if overlaps_last {
                merged_groups.last_mut().unwrap().push(hit);
            } else {
                merged_groups.push(vec![hit]);
            }
        }

        for group in merged_groups {
            let mut strings_found: Vec<String> = Vec::new();
            let mut lineindextuples: Vec<(usize, usize)> = Vec::new();
            for hit in &group {
                let tuple = (hit.start, hit.end);
                if !lineindextuples.contains(&tuple) {
                    lineindextuples.push(tuple);
                    strings_found.push(hit.string_found.clone());
                }
            }
            let mut reasons: Vec<String> = group.iter().map(|hit| hit.reason.clone()).collect();
            reasons.sort();
            reasons.dedup();
            // A named regex rule is higher confidence than the generic entropy detector.
            let reason = reasons
                .iter()
                .find(|name| name.as_str() != "Entropy")
                .cloned()
                .unwrap_or_else(|| reasons[0].clone());
            findings.push(FileFinding {
                strings_found,
                reason,
                reasons,
                path: path.clone(),
                linenum: index + 1,
                lineindextuples,
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use escargot::CargoBuild;
    use std::io::Result;
    use std::io::Write;
    use std::process::Output;
    use tempfile::{tempdir, NamedTempFile, TempDir};

    fn run_command_in_dir(dir: &TempDir, command: &str, args: &[&str]) -> Result<Output> {
        let dir_path = dir.path().to_str().unwrap();
        let binary = CargoBuild::new().bin(command).run().unwrap();

        binary.command().current_dir(dir_path).args(args).output()
    }

    fn write_temp_file(dir: &TempDir, filename: &str, contents: &str) {
        let file_path = dir.path().join(filename);
        let mut tmp_file = File::create(&file_path).unwrap();
        write!(tmp_file, "{}", contents).unwrap();
    }

    fn read_temp_file(dir: &TempDir, filename: &str) -> String {
        let mut contents = String::new();
        let file_path = dir.path().join(filename);
        let mut file_handle = File::open(&file_path).unwrap();
        file_handle.read_to_string(&mut contents).unwrap();
        contents
    }

    #[test]
    fn does_not_scan_output_file() {
        let temp_dir = tempdir().expect("couldn't make tempdir");

        write_temp_file(
            &temp_dir,
            "insecure-file.txt",
            "My email is username@mail.com",
        );

        let cmd_args = ["-o", "output_file.txt", "."];

        run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();
        run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();

        let text = read_temp_file(&temp_dir, "output_file.txt");

        println!("{}", text);
        temp_dir.close().expect("couldn't close tempdir");

        assert!(
            text.contains("\"path\":\"./insecure-file.txt\"")
                || text.contains("\"path\":\".\\\\insecure-file.txt\"")
        );
        assert!(!text.contains("output_file.txt"));
    }

    #[test]
    fn allowlist_json_file_prevents_output() {
        let temp_dir = tempdir().expect("couldn't make tempdir");
        let mut allowlist_temp_file = NamedTempFile::new().unwrap();
        let json = r#"
        {
            "Email address": [
                "username@mail.com"
            ]
        }
        "#;
        write!(allowlist_temp_file, "{}", json).unwrap();
        write_temp_file(
            &temp_dir,
            "insecure-file.txt",
            "My email is username@mail.com",
        );

        let cmd_args = [
            "--allowlist",
            allowlist_temp_file.path().to_str().unwrap(),
            ".",
        ];

        let output = run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();
        temp_dir.close().expect("couldn't close tempdir");
        let prg_out = str::from_utf8(&output.stdout).unwrap();
        assert_eq!("[]\n", prg_out);
    }

    // A high-entropy base64 word (decoded normalized entropy above the 0.6 default
    // threshold) that the Generic Secret regex also matches. It contains no token
    // from the built-in allowlist.
    const OVERLAP_TOKEN: &str = "2xRiKZv1j9l7W4gzGPW4I41bSOlnUlDOL9vtxuBL89UJPVhI8KluBoqR";

    #[test]
    fn overlapping_regex_and_entropy_hits_are_merged() {
        let mut ss_builder = SecretScannerBuilder::new();
        ss_builder.add_entropy_findings = true;
        let ss = ss_builder.build();
        let input = format!("secret: {}\n", OVERLAP_TOKEN).into_bytes();

        let findings = scan_bytes(input, &ss, String::from("leak.txt"));

        assert_eq!(
            findings.len(),
            1,
            "overlapping hits must merge into one finding"
        );
        let finding = &findings[0];
        assert_eq!(finding.reason, "Generic Secret");
        assert_eq!(finding.reasons, vec!["Entropy", "Generic Secret"]);
        assert_eq!(finding.linenum, 1);
        assert_eq!(finding.lineindextuples.len(), 2);
        assert_eq!(finding.strings_found.len(), 2);
        // The entropy-only span is nested inside the regex match span.
        assert!(finding
            .lineindextuples
            .iter()
            .any(|(start, end)| *start == 8 && *end == 64));
    }

    #[test]
    fn non_overlapping_hits_remain_separate_findings() {
        let ss = SecretScannerBuilder::new().build();
        let input = String::from("My email is username@mail.com\n").into_bytes();

        let findings = scan_bytes(input, &ss, String::from("mail.txt"));

        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.reason, "Email address");
        assert_eq!(finding.reasons, vec!["Email address"]);
        assert_eq!(finding.linenum, 1);
    }

    #[test]
    fn repeated_runs_produce_byte_identical_output() {
        let temp_dir = tempdir().expect("couldn't make tempdir");
        write_temp_file(
            &temp_dir,
            "insecure-file.txt",
            format!("secret: {}\n", OVERLAP_TOKEN).as_str(),
        );

        let cmd_args = ["--entropy", "."];
        let first = run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();
        for _ in 0..4 {
            let repeated = run_command_in_dir(&temp_dir, "duroc_hog", &cmd_args).unwrap();
            assert_eq!(first.stdout, repeated.stdout);
        }

        let parsed: serde_json::Value = serde_json::from_slice(first.stdout.as_slice()).unwrap();
        let findings = parsed.as_array().unwrap();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding["reason"], "Generic Secret");
        assert_eq!(
            finding["reasons"],
            serde_json::json!(["Entropy", "Generic Secret"])
        );
        temp_dir.close().expect("couldn't close tempdir");
    }

    #[test]
    fn directory_findings_are_sorted_by_path_and_line() {
        let temp_dir = tempdir().expect("couldn't make tempdir");
        std::fs::create_dir(temp_dir.path().join("sub")).unwrap();
        write_temp_file(
            &temp_dir,
            "z-last.txt",
            format!("secret: {}\n", OVERLAP_TOKEN).as_str(),
        );
        write_temp_file(
            &temp_dir,
            "sub/a-first.txt",
            "My email is username@mail.com\n",
        );

        let output = run_command_in_dir(&temp_dir, "duroc_hog", &["--entropy", "."]).unwrap();
        let parsed: Vec<FileFinding> = serde_json::from_slice(&output.stdout).unwrap();

        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].path.ends_with("a-first.txt"));
        assert!(parsed[1].path.ends_with("z-last.txt"));
        assert_eq!(parsed[0].reasons, vec!["Email address"]);
        assert_eq!(parsed[1].reasons, vec!["Entropy", "Generic Secret"]);
        temp_dir.close().expect("couldn't close tempdir");
    }
}
