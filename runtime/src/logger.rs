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
        // let len_cond = len_label::get_len_cond(&mut cond);

        if cond.op < defs::COND_AFL_OP || cond.op == defs::COND_FN_OP {
            order = self.get_order(&mut cond);
        }
        if order <= config::MAX_COND_ORDER {
            self.save_tag(cond.lb1);
            self.save_tag(cond.lb2);
            self.data.cond_list.push(cond);
            // if let Some(mut c) = len_cond {
            //     c.order = 0x10000 + order; // avoid the same as cond;
            //     self.data.cond_list.push(c);
            // }
        }
    }

    fn parse_log_data(
        &self
    ) {
        let dir = Path::new(".");
        let mut log_q = fs::File::create(dir.join(defs::COND_QUEUE_FILE)).unwrap();
        writeln!(
            log_q,
            "location, offsets"
        )
        .unwrap();

        for cond_base in self.data.cond_list.iter() {
            if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {

                let empty_offsets: Vec<TagSeg> = vec![];
                let offsets1 = self.data.tags.get(&cond_base.lb1).unwrap_or(&empty_offsets);
                let offsets2 = self.data.tags.get(&cond_base.lb2).unwrap_or(&empty_offsets);
                
                let mut combined_offsets = offsets1.clone();
                combined_offsets.extend(offsets2.iter().cloned()); // Extend with elements from offsets2


                eprintln!("@@@@@ drop_results: For every con in cond_list");
                if !cond_base.is_afl() {
                    let mut offsets = vec![];
                    for off in combined_offsets {
                        offsets.push(format!("{}-{}", off.begin, off.end));
                    }
                    eprintln!("@@@@@ drop_results: pass the cond?");
                    writeln!(
                        log_q,
                        "{},{}",
                        cond_base.loc_string,
                        offsets.join("&")
                    )
                    .unwrap();
                }
            }
        }
    }

    fn fini(&self) {
        if let Some(fd) = &self.fd {
            self.parse_log_data();
        }
    }    
}

impl Drop for Logger {
    fn drop(&mut self) {
        eprintln!("@@@@@ Logger.drop is called!!");
        self.fini();
    }
}
