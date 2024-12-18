use crate::{cond_stmt_base::CondStmtBase, tag::TagSeg};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive( PartialEq, Debug)]
pub struct LogData {
    pub cond_list: Vec<CondStmtBase>,
    pub tags: HashMap<u32, Vec<TagSeg>>,
    pub magic_bytes: HashMap<usize, (Vec<u8>, Vec<u8>)>,
}

impl LogData {
    pub fn new() -> Self {
        Self {
            cond_list: vec![],
            tags: HashMap::new(),
            magic_bytes: HashMap::new(),
        }
    }
}
