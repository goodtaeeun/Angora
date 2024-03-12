#[macro_use]
extern crate clap;
use clap::{App, Arg};

extern crate angora;
extern crate angora_common;
use angora::fuzz_main;

fn main() {
    let matches = App::new("angora-fuzzer")
        .version(crate_version!())
        .about("Angora is a mutation-based fuzzer. The main goal of Angora is to increase branch coverage by solving path constraints without symbolic execution.")
        .arg(Arg::with_name("output_dir")
             .short("o")
             .long("output")
             .value_name("DIR")
             .help("Sets the directory of outputs")
             .takes_value(true)
             .required(true))
        .arg(Arg::with_name("track_target")
             .short("t")
             .long("track")
             .value_name("PROM")
             .help("Sets the target (USE_TRACK or USE_PIN) for tracking, including taints, cmps.  Only set in LLVM mode.")
             .takes_value(true))
       .get_matches();

    fuzz_main(
        matches.value_of("output_dir").unwrap(),
        matches.value_of("track_target").unwrap_or("-"),
    );

//     let conds = track::load_track_data(matches.value_of("track_target").unwrap_or("-"));
//      let path_s = matches.value_of("output_dir").unwrap();
//      drop_results(Path::new(&path_s), conds);
}
