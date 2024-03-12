use angora_common::defs;
use chrono::prelude::Local;
use std::{
    collections::HashMap,
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, RwLock,
    },
    thread, time,
};

use crate::{track};
use ctrlc;
use libc;
use pretty_env_logger;

pub fn fuzz_main(
    out_dir: &str,
    track_target: &str,
) {
    let target_path = Path::new(track_target);
    let conds = track::load_track_data_new(target_path);
    track::drop_results(Path::new(&out_dir), conds);
}

