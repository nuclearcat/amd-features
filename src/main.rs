//! CLI entry point.

use std::io::IsTerminal;
use std::process::ExitCode;

use amd_features::probes::{Context, ContextOptions};
use amd_features::report::{self, TextOptions};

#[cfg(feature = "gui")]
mod gui;

const HELP: &str = "\
amd-features — detect AMD processor and platform features

USAGE:
    amd-features [OPTIONS]

OPTIONS:
        --gui         Open the native feature dashboard
    -j, --json        Emit the report as JSON
    -v, --verbose     Show each probe's finding under every feature (text mode)
    -a, --all         Include features detected as absent (hidden by default)
        --load-msr-module
                      If root and /dev/cpu/0/msr is missing, run modprobe msr once
        --no-color    Disable ANSI colors
    -h, --help        Print this help
    -V, --version     Print version

EXIT CODES:
    0  ran successfully
    1  internal probe/report error
    2  bad arguments

TRADEMARKS:
    AMD and related marks are trademarks of Advanced Micro Devices, Inc.
    This independent project is not affiliated with or endorsed by AMD.
";

struct Args {
    gui: bool,
    json: bool,
    verbose: bool,
    show_absent: bool,
    color: Option<bool>,
    load_msr_module: bool,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => return code,
    };

    let ctx = Context::with_options(ContextOptions {
        load_msr_module: args.load_msr_module,
    });
    if args.gui {
        #[cfg(feature = "gui")]
        return match gui::run(ctx) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("cannot open GUI: {error}");
                ExitCode::from(1)
            }
        };
        #[cfg(not(feature = "gui"))]
        {
            eprintln!("GUI support is not included in this build; rebuild with --features gui");
            return ExitCode::from(2);
        }
    }
    let report = match report::collect(&ctx) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("internal error: {error}");
            return ExitCode::from(1);
        }
    };

    if args.json {
        println!("{}", report.to_json());
    } else {
        let color = args
            .color
            .unwrap_or_else(|| std::io::stdout().is_terminal());
        let opts = TextOptions {
            color,
            verbose: args.verbose,
            hide_absent: !args.show_absent,
        };
        print!("{}", report.render_text(opts));
    }

    ExitCode::SUCCESS
}

fn parse_args() -> Result<Args, ExitCode> {
    parse_args_from(std::env::args().skip(1))
}

fn parse_args_from(args_iter: impl IntoIterator<Item = String>) -> Result<Args, ExitCode> {
    let mut args = Args {
        gui: false,
        json: false,
        verbose: false,
        show_absent: false,
        color: None,
        load_msr_module: false,
    };
    for arg in args_iter {
        match arg.as_str() {
            "--gui" => args.gui = true,
            "-j" | "--json" => args.json = true,
            "-v" | "--verbose" => args.verbose = true,
            "-a" | "--all" => args.show_absent = true,
            "--no-color" => args.color = Some(false),
            "--color" => args.color = Some(true),
            "--load-msr-module" => args.load_msr_module = true,
            "-h" | "--help" => {
                print!("{HELP}");
                return Err(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("amd-features {}", env!("CARGO_PKG_VERSION"));
                return Err(ExitCode::SUCCESS);
            }
            other => {
                eprintln!("error: unknown argument '{other}'\n\n{HELP}");
                return Err(ExitCode::from(2));
            }
        }
    }
    if args.gui && args.json {
        eprintln!("error: --gui and --json cannot be used together");
        return Err(ExitCode::from(2));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_module_loading_opt_in() {
        let args =
            parse_args_from(["--json".to_string(), "--load-msr-module".to_string()]).unwrap();
        assert!(args.json);
        assert!(args.load_msr_module);
    }

    #[test]
    fn module_loading_is_off_by_default() {
        let args = parse_args_from(Vec::<String>::new()).unwrap();
        assert!(!args.load_msr_module);
    }

    #[test]
    fn rejects_unknown_option() {
        assert!(parse_args_from(["--bogus".to_string()]).is_err());
    }

    #[test]
    fn gui_is_explicit_and_conflicts_with_json() {
        assert!(!parse_args_from(Vec::<String>::new()).unwrap().gui);
        assert!(parse_args_from(["--gui".into()]).unwrap().gui);
        assert!(parse_args_from(["--gui".into(), "--json".into()]).is_err());
        assert!(parse_args_from(["--json".into(), "--gui".into()]).is_err());
    }
}
