use bincode::{deserialize_from, serialize_into};
use std::{collections::HashMap, env, fs, io, path::Path, io::prelude::*};
use angora_common::tag::TagSeg;
use angora_common::{config};
use crate::{len_label, tag_set_wrap};
use angora_common::{cond_stmt_base::CondStmtBase, cond_stmt::CondStmt, defs, log_data::LogData, mut_input};

#[derive(Debug)]
pub struct Logger {
    data: LogData,
    fd: Option<fs::File>,
    order_map: HashMap<(u32, u32), u32>,
}

impl Logger {
    pub fn new() -> Self {
        // export ANGORA_TRACK_OUTPUT=track.log
        let fd = match env::var(defs::TRACK_OUTPUT_VAR) {
            Ok(path) => match fs::File::create(&path) {
                Ok(f) => Some(f),
                Err(_) => None,
            },
            Err(_) => None,
        };

        eprintln!("@@@@@ Logger.new is called!!");

        Self {
            data: LogData::new(),
            fd,
            order_map: HashMap::new(),
        }
    }

    fn save_tag(&mut self, lb: u32) {
        if lb > 0 {
            let tag = tag_set_wrap::tag_set_find(lb as usize);
            self.data.tags.entry(lb).or_insert(tag);
        }
    }

    pub fn save_magic_bytes(&mut self, bytes: (Vec<u8>, Vec<u8>)) {
        let i = self.data.cond_list.len();
        if i > 0 {
            self.data.magic_bytes.insert(i - 1, bytes);
        }
    }

    // like the fn in fparser.rs
    pub fn get_order(&mut self, cond: &mut CondStmtBase) -> u32 {
        let order_key = (cond.cmpid, cond.context);
        let order = self.order_map.entry(order_key).or_insert(0);
        if cond.order == 0 {
            // first case in switch
            let order_inc = *order + 1;
            *order = order_inc;
        }
        cond.order += *order;
        *order
    }

    pub fn save(&mut self, mut cond: CondStmtBase) {
        if cond.lb1 == 0 && cond.lb2 == 0 {
            return;
        }

        eprintln!("@@@@@ Logger.save is called!!");
        let mut order = 0;

        // also modify cond to remove len_label information
        let len_cond = len_label::get_len_cond(&mut cond);

        if cond.op < defs::COND_AFL_OP || cond.op == defs::COND_FN_OP {
            order = self.get_order(&mut cond);
        }
        if order <= config::MAX_COND_ORDER {
            self.save_tag(cond.lb1);
            self.save_tag(cond.lb2);
            self.data.cond_list.push(cond);

            if let Some(mut c) = len_cond {
                c.order = 0x10000 + order; // avoid the same as cond;
                self.data.cond_list.push(c);
            }
        }
    }

    pub fn parse_log_data(
        &self
    ) -> io::Result<Vec<CondStmt>> {
        let mut cond_list: Vec<CondStmt> = Vec::new();
        // assign taint labels and magic_bytes to cond list
        for (i, cond_base) in self.data.cond_list.iter().enumerate() {
            let mut cond = CondStmt::from(*cond_base);
            if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {
                // if cond_base.size == 0 {
                //     debug!("cond: {:?}", cond_base);
                // }
                self.get_offsets_and_variables(&self.data.tags, &mut cond, &self.data.magic_bytes.get(&i));
            }
    
            cond_list.push(cond);
        }
        Ok(cond_list)
    }
    fn get_offsets_and_variables(
        &self,
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

    fn fini(&self) {
        if let Some(fd) = &self.fd {
            // let mut writer = io::BufWriter::new(fd);
            // serialize_into(&mut writer, &self.data).expect("Could not serialize data.");
            let conds = match self.parse_log_data(){
                Result::Ok(val) => val,
                Result::Err(err) => {
                    // error!("parse track file error!! {:?}", err);
                    vec![]
                },
            };

            drop_results(conds);
        }
    }

    
}

impl Drop for Logger {
    fn drop(&mut self) {
        eprintln!("@@@@@ Logger.drop is called!!");
        self.fini();
    }
}

pub fn get_log_data(path: &Path) -> io::Result<LogData> {
    let f = fs::File::open(path)?;
    if f.metadata().unwrap().len() == 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "Could not find any interesting constraint!, Please make sure taint tracking works or running program correctly."));
    }
    let mut reader = io::BufReader::new(f);
    match deserialize_from::<&mut io::BufReader<fs::File>, LogData>(&mut reader) {
        Ok(v) => Ok(v),
        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "bincode parse error!")),
    }
}

// pub fn parse_log_data(
//     log_data: LogData,
// ) -> io::Result<Vec<CondStmt>> {
//     let mut cond_list: Vec<CondStmt> = Vec::new();
//     // assign taint labels and magic_bytes to cond list
//     for (i, cond_base) in log_data.cond_list.iter().enumerate() {
//         let mut cond = CondStmt::from(*cond_base);
//         if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {
//             // if cond_base.size == 0 {
//             //     debug!("cond: {:?}", cond_base);
//             // }
//             get_offsets_and_variables(&log_data.tags, &mut cond, &log_data.magic_bytes.get(&i));
//         }

//         cond_list.push(cond);
//     }
//     Ok(cond_list)
// }

// fn get_offsets_and_variables(
//     m: &HashMap<u32, Vec<TagSeg>>,
//     cond: &mut CondStmt,
//     magic_bytes: &Option<&(Vec<u8>, Vec<u8>)>,
// ) {
//     let empty_offsets: Vec<TagSeg> = vec![];
//     let offsets1 = m.get(&cond.base.lb1).unwrap_or(&empty_offsets);
//     let offsets2 = m.get(&cond.base.lb2).unwrap_or(&empty_offsets);
//     if offsets2.len() == 0 || (offsets1.len() > 0 && offsets1.len() <= offsets2.len()) {
//         cond.offsets = offsets1.clone();
//         if cond.base.lb2 > 0 && cond.base.lb1 != cond.base.lb2 {
//             cond.offsets_opt = offsets2.clone();
//         }
//         cond.variables = if let Some(args) = magic_bytes {
//             [&args.1[..], &args.0[..]].concat()
//         } else {
//             // if it is integer comparison, we use the bytes of constant as magic bytes.
//             mut_input::write_as_ule(cond.base.arg2, cond.base.size as usize)
//         };
//     } else {
//         cond.offsets = offsets2.clone();
//         if cond.base.lb1 > 0 && cond.base.lb1 != cond.base.lb2 {
//             cond.offsets_opt = offsets1.clone();
//         }
//         cond.variables = if let Some(args) = magic_bytes {
//             [&args.0[..], &args.1[..]].concat()
//         } else {
//             mut_input::write_as_ule(cond.base.arg1, cond.base.size as usize)
//         };
//     }
// }

// pub fn load_track_data_new(
//     out_f: &Path
// ) -> Vec<CondStmt> {
//     eprintln!("@@@@@ Path in load_track_data, {}", out_f.display());
//     let mut cond_list = match read_and_parse_new(out_f) {
//         Result::Ok(val) => val,
//         Result::Err(err) => {
//             error!("parse track file error!! {:?}", err);
//             vec![]
//         },
//     };

//     for cond in cond_list.iter_mut() {
//         eprintln!("@@@@@ load_track_data_new: For every con in cond_list");
//         cond.base.belong = 0;
//         cond.speed = 0;
//         if cond.offsets.len() == 1 && cond.offsets[0].end - cond.offsets[0].begin == 1 {
//             cond.state = CondState::OneByte;
//         }
//     }

//     cond_list
// }

pub fn drop_results(conds: Vec<CondStmt>) {
    // info!("dump constraints and chart..");
    // let dir = out_path;
    let dir = Path::new(".");

    let mut log_q = fs::File::create(dir.join(defs::COND_QUEUE_FILE)).unwrap();
    writeln!(
        log_q,
        "cmpid, context, order, belong, op, condition, arg1, arg2, is_desirable, offsets, state"
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
