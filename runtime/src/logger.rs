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

        // eprintln!("@@@@@ Logger.new is called!!");

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

        // eprintln!("@@@@@ Logger.save is called!!");
        // eprintln!("@@@@@ cond.locstring is {}",cond.loc_string);
        let mut order = 0;
        
        // also modify cond to remove len_label information
        // let len_cond = len_label::get_len_cond(&mut cond);

        // if cond.op < defs::COND_AFL_OP || cond.op == defs::COND_FN_OP {
        //     order = self.get_order(&mut cond);
        // }
        // if order <= config::MAX_COND_ORDER {
            // eprintln!("@@@@@ cond is actually saved!!");
            self.save_tag(cond.lb1);
            self.save_tag(cond.lb2);
            self.data.cond_list.push(cond);
            // if let Some(mut c) = len_cond {
            //     c.order = 0x10000 + order; // avoid the same as cond;
            //     self.data.cond_list.push(c);
            // }
        // }
    }

    fn parse_log_data(
        &self
    ) {
        let dir = Path::new(".");
        let mut log_q = fs::File::create(dir.join(defs::TAINT_OUT_FILE)).unwrap();
        // writeln!(
        //     log_q,
        //     "location, offsets"
        // )
        // .unwrap();

        let mut result: HashMap<String, Vec<(u32, u32)>> = HashMap::new();

        for cond_base in self.data.cond_list.iter() {
            // eprintln!("@@@@@ cond_base.loc_string: {}",cond_base.loc_string);
            // if cond_base.op == defs::COND_LEN_OP{
            //     eprintln!("@@@@@ cond_base.op == defs::COND_LEN_OP");}
            // if (cond_base.lb1 <= 0 && cond_base.lb2 <= 0){
            //     eprintln!("@@@@@ cond_base.lb1 <= 0 && cond_base.lb2 <= 0");
            // }

            if cond_base.op != defs::COND_LEN_OP && (cond_base.lb1 > 0 || cond_base.lb2 > 0) {

                let empty_offsets: Vec<TagSeg> = vec![];
                let offsets1 = self.data.tags.get(&cond_base.lb1).unwrap_or(&empty_offsets);
                let offsets2 = self.data.tags.get(&cond_base.lb2).unwrap_or(&empty_offsets);
                
                let mut combined_offsets = offsets1.clone();
                combined_offsets.extend(offsets2.iter().cloned()); // Extend with elements from offsets2



                if !cond_base.is_afl() {
                    let mut offsets = vec![];
                    let mut ranges: Vec<(u32, u32)> = vec![];
                    for off in combined_offsets {
                        // To represent the exact byte that is being used, we need to subtract 1 from the end
                        offsets.push(format!("{}-{}", off.begin, off.end-1));
                        ranges.push((off.begin, off.end-1));
                    }

                    // let loc_string = cond_base.loc_string
                    
                    if !result.contains_key(&cond_base.loc_string) {
                        result.insert(cond_base.loc_string.clone(), vec![]);
                    }

                    let line_ranges = result.get_mut(&cond_base.loc_string).unwrap();
                    
                    for range in ranges {
                        line_ranges.push(range);
                    }

                }
            }
        }

        for (line_name, ranges) in result.iter_mut() {
            ranges.sort_by_key(|&x| x.0);
            // eprintln!("@@@@@ line is {}",line_name);
            // eprintln!("@@@@@ renges are {:?}",ranges);

            let mut merged_ranges = Vec::new();
            let mut iter = ranges.iter().copied();
    
            if let Some(mut current) = iter.next() {
                while let Some(next) = iter.next() {
                    let (mut current_start, mut current_end) = current;
                    let (next_start, next_end) = next;
                    
                    if next_start <= current_end + 1 {
                        current = (current_start, current_end.max(next_end));
                    } else {
                        merged_ranges.push(current);
                        current = (next_start, next_end);
                    }
    

                }
    
                merged_ranges.push(current);
            }

            let mut offset_strings = vec![];
            for range in merged_ranges {
                let (mut start, mut end) = range;
                offset_strings.push(format!("{}-{}", start, end));
            }

            // eprintln!("@@@@@ proceed to writeln");
            writeln!(
                log_q,
                "{},{}",
                line_name.to_string(),
                offset_strings.join("&")
            )
            .unwrap();
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
        // eprintln!("@@@@@ Logger.drop is called!!");
        self.parse_log_data();
    }
}
