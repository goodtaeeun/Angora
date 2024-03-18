use crate::{tag::TagSeg};
use byteorder::{LittleEndian, WriteBytesExt};

pub fn merge_offsets(v1: &Vec<TagSeg>, v2: &Vec<TagSeg>) -> Vec<TagSeg> {
    if v1.len() == 0 {
        return v2.clone();
    }
    if v2.len() == 0 {
        return v1.clone();
    }

    let mut v = vec![];

    let mut v1_it = v1.iter();
    let mut v2_it = v2.iter();
    let mut o1 = v1_it.next();
    let mut o2 = v2_it.next();

    // The begin field is unique: if there are two different `TagSeg`, their begin field must be different.
    while o1.is_some() && o2.is_some() {
        let b1 = o1.unwrap().begin;
        let b2 = o2.unwrap().begin;
        if b1 == b2 {
            if o1.unwrap().end >= o2.unwrap().end {
                v.push(o1.unwrap().clone());
            } else {
                v.push(o2.unwrap().clone());
            }
            o1 = v1_it.next();
            o2 = v2_it.next();
        } else if b1 < b2 {
            v.push(o1.unwrap().clone());
            //merge_push(&mut v, &o1.unwrap());
            o1 = v1_it.next();
        } else {
            // b2 < b1
            v.push(o2.unwrap().clone());
            //merge_push(&mut v, &o2.unwrap());
            o2 = v2_it.next();
        }
    }

    while o1.is_some() {
        // merge_push(&mut v, &o1.unwrap());
        v.push(o1.unwrap().clone());
        o1 = v1_it.next();
    }

    while o2.is_some() {
        // merge_push(&mut v, &o2.unwrap());
        v.push(o2.unwrap().clone());
        o2 = v2_it.next();
    }

    v
}

pub fn write_as_ule(val: u64, size: usize) -> Vec<u8> {
    let mut wtr = vec![];
    match size {
        1 => {
            wtr.write_u8(val as u8).unwrap();
        },
        2 => {
            wtr.write_u16::<LittleEndian>(val as u16).unwrap();
        },
        4 => {
            wtr.write_u32::<LittleEndian>(val as u32).unwrap();
        },
        8 => {
            wtr.write_u64::<LittleEndian>(val as u64).unwrap();
        },
        _ => {
            // debug!("wrong size: {:?}", size);
            // panic!("strange arg size: {}", size);
        },
    }

    wtr
}