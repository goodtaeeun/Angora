use crate::{
    cond_stmt::{CondState, CondStmt},
    mut_input,
};
use angora_common::{defs, tag::TagSeg};
use runtime::get_log_data;
use std::{collections::HashMap, io, fs, path::Path, io::prelude::*};

pub fn read_and_parse_new(
    out_f: &Path,
) -> io::Result<Vec<CondStmt>> {
    let log_data = get_log_data(out_f)?;
    // eprintln!("This is going to standard error!, {}", "awesome");
    let mut cond_list: Vec<CondStmt> = Vec::new();
    // assign taint labels and magic_bytes to cond list
    for (i, cond_base) in log_data.cond_list.iter().enumerate() {
        let mut cond = CondStmt::from(*cond_base);
        if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {
            if cond_base.size == 0 {
                debug!("cond: {:?}", cond_base);
            }
            get_offsets_and_variables_new(&log_data.tags, &mut cond, &log_data.magic_bytes.get(&i));
        }

        cond_list.push(cond);
    }
    Ok(cond_list)
}

fn get_offsets_and_variables_new(
    m: &HashMap<u32, Vec<TagSeg>>,
    cond: &mut CondStmt,
    magic_bytes: &Option<&(Vec<u8>, Vec<u8>)>,
) {
    let empty_offsets: Vec<TagSeg> = vec![];
    let offsets1 = m.get(&cond.base.lb1).unwrap_or(&empty_offsets);
    let offsets2 = m.get(&cond.base.lb2).unwrap_or(&empty_offsets);
    if offsets2.len() == 0 || (offsets1.len() > 0 && offsets1.len() <= offsets2.len()) {
        cond.offsets = offsets1.clone();
        if cond.base.lb2 > 0 && cond.base.lb1 != cond.base.lb2 {
            cond.offsets_opt = offsets2.clone();
        }
        cond.variables = if let Some(args) = magic_bytes {
            [&args.1[..], &args.0[..]].concat()
        } else {
            // if it is integer comparison, we use the bytes of constant as magic bytes.
            mut_input::write_as_ule(cond.base.arg2, cond.base.size as usize)
        };
    } else {
        cond.offsets = offsets2.clone();
        if cond.base.lb1 > 0 && cond.base.lb1 != cond.base.lb2 {
            cond.offsets_opt = offsets1.clone();
        }
        cond.variables = if let Some(args) = magic_bytes {
            [&args.0[..], &args.1[..]].concat()
        } else {
            mut_input::write_as_ule(cond.base.arg1, cond.base.size as usize)
        };
    }
}

pub fn load_track_data_new(
    out_f: &Path
) -> Vec<CondStmt> {
    eprintln!("@@@@@ Path in load_track_data, {}", out_f.display());
    let mut cond_list = match read_and_parse_new(out_f) {
        Result::Ok(val) => val,
        Result::Err(err) => {
            error!("parse track file error!! {:?}", err);
            vec![]
        },
    };

    for cond in cond_list.iter_mut() {
        eprintln!("@@@@@ load_track_data_new: For every con in cond_list");
        cond.base.belong = 0;
        cond.speed = 0;
        if cond.offsets.len() == 1 && cond.offsets[0].end - cond.offsets[0].begin == 1 {
            cond.state = CondState::OneByte;
        }
    }

    cond_list
}

pub fn drop_results(out_path: &Path, conds: Vec<CondStmt>) {
    info!("dump constraints and chart..");
    let dir = out_path;

    let mut log_q = fs::File::create(dir.join(defs::COND_QUEUE_FILE)).unwrap();
    writeln!(
        log_q,
        "cmpid, context, order, belong, p, op, condition, is_desirable, offsets, state"
    )
    .unwrap();

    for cond in conds.iter() {
        eprintln!("@@@@@ drop_results: For every con in cond_list");
        if !cond.base.is_afl() {
            let mut offsets = vec![];
            for off in &cond.offsets {
                offsets.push(format!("{}-{}", off.begin, off.end));
            }
            eprintln!("@@@@@ drop_results: pass the cond?");
            writeln!(
                log_q,
                "{}, {}, {}, {}, {}, {}, {:x}, {:x}, {}, {}, {:?}",
                cond.base.cmpid,
                cond.base.context,
                cond.base.order,
                cond.base.belong,
                // p,
                cond.base.op,
                cond.base.condition,
                cond.base.arg1,
                cond.base.arg2,
                cond.is_desirable,
                offsets.join("&"),
                cond.state
            )
            .unwrap();
        }
    }
}