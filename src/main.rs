extern crate untrusted;
extern crate rand;

use std::collections::BTreeMap;
use std::vec::Vec;
use std::io::Write;
use rand::Rng;

/// Reads a little endian u32 from the reader.  If the input doesn't have 4 bytes,
/// then we return untrusted::EndOfInput.
fn read_u32(reader: &mut untrusted::Reader) -> Result<u32, untrusted::EndOfInput> {
    let b1 = try!(reader.read_byte()) as u32;
    let b2 = try!(reader.read_byte()) as u32;
    let b3 = try!(reader.read_byte()) as u32;
    let b4 = try!(reader.read_byte()) as u32;
    Ok(b1 | b2 << 8 | b3 << 16 | b4 << 24)
}

fn read_message(reader: &mut untrusted::Reader) -> Result<BTreeMap<u32, Vec<u8>>, untrusted::EndOfInput> {
    let num_tags = try!(read_u32(reader));
    if num_tags == 0 {
        return Ok(BTreeMap::new());
    }
    // There are num_tags-1 offsets
    let mut offsets: Vec<u32> = Vec::with_capacity((num_tags-1) as usize);
    for _ in 0..num_tags-1 {
        // DOC CLARITY: Do offsets need to be increasing and unique, or can tags
        // share and/or overlap values? (Doesn't seem to be explicitly forbidden)
        // I am assuming they are in the same order as the tags, and non-overlapping.
        // I believe this is what's intended, though not explicitly stated.
        let offset = try!(read_u32(reader));
        // Offset must be a multiple of 4.
        if offset & 0b11 != 0 {
            return Err(untrusted::EndOfInput)
        }
        offsets.push(offset);
    }

    let mut tags: Vec<u32> = Vec::with_capacity(num_tags as usize);
    let last_tag = try!(read_u32(reader));
    tags.push(last_tag);
    for _ in 1..num_tags {
        let tag = try!(read_u32(reader));
        if tag <= last_tag {
            // Tags must be strictly increasing
            return Err(untrusted::EndOfInput);
        }
        tags.push(tag);
    }

    // Now read the values and build the map
    let mut map = BTreeMap::new();
    // Handle the last tag specially because it goes to end of input
    let last_tag = tags.pop().unwrap();
    let mut offset=0;
    for (i, tag) in tags.iter().enumerate() {
        // Use offsets to get input slice
        let next_offset = offsets[i];
        let input = try!(reader.skip_and_get_input((next_offset-offset) as usize));
        let v: Vec<u8> = input.as_slice_less_safe().into();
        map.insert(*tag, v);
        offset = next_offset;
    }
    map.insert(last_tag, reader.skip_to_end().as_slice_less_safe().into());
    Ok(map)
}

/// parse_message loads the tag -> value map in roughtime.
/// This interface isn't very efficient, as it copies everything.
fn parse_message(input: untrusted::Input) -> Result<BTreeMap<u32, Vec<u8>>, ()> {
    match input.read_all(untrusted::EndOfInput, read_message) {
        Ok(n) => Ok(n),
        Err(_) => Err(())
    }
}

// append_u32 appends the four bytes from a to v, little endian.
fn append_u32(mut a: u32, v: &mut Vec<u8>) {
    for _ in 0..4 {
        v.push((a & 0xFF) as u8);
        a = a >> 8;
    }
}

#[test]
fn test_append_u8() {
    let mut v = vec![0xAA];
    append_u32(0x12BC23CD, &mut v);
    assert_eq!(vec![0xAA, 0xCD, 0x23, 0xBC, 0x12], v);
}

fn encode_message(message: &BTreeMap<u32, Vec<u8>>) -> Vec<u8> {
    let mut d = vec![];
    let num_tags = message.iter().len() as u32;
    let mut write = num_tags;
    let mut offset = 0;
    // Since there's n-1 offsets to write out, we have the loop write num_tags as the first
    // value.  That removes any icky business with figuring out if we're in the first or last value.
    for (_, v) in message {
        append_u32(write, &mut d);
        offset += v.len() as u32;
        write = offset;
    }
    for &k in message.keys() {
        append_u32(k, &mut d);
    }
    for (_, v) in message {
        d.extend(v);
    }
    return d;
}

// TODO: Use enum instead?
mod tag {
    // A macro or const fn could reduce potential for error here.
    // Request tags:
    pub const NONC: u32 = 0x434e4f4e;
    pub const PAD : u32 = 0xff444150;
    // Reply tags:
    pub const SREP: u32 = 0x50455253;
    pub const ROOT: u32 = 0x544f4f52;
    pub const MIDP: u32 = 0x5044494d;
    pub const RADI: u32 = 0x49444152;
    pub const SIG : u32 = 0x00474953;
    pub const INDX: u32 = 0x58444e49;
    pub const PATH: u32 = 0x48544150;
    pub const CERT: u32 = 0x54524543;
    pub const DELE: u32 = 0x454c4544;
    pub const MINT: u32 = 0x544e494d;
    pub const MAXT: u32 = 0x5458414d;
    pub const PUBK: u32 = 0x4b425550;
}

#[test]
fn test_tag() {
    use tag::*;
    let tags = vec![(NONC, b"NONC"), (PAD, b"PAD\xff"), (SREP, b"SREP"), (ROOT, b"ROOT"),
        (MIDP, b"MIDP"), (RADI, b"RADI"), (SIG, b"SIG\x00"), (INDX, b"INDX"), (PATH, b"PATH"),
        (CERT, b"CERT"), (DELE, b"DELE"), (MINT, b"MINT"), (MAXT, b"MAXT"), (PUBK, b"PUBK")];
    for (tag, bytes) in tags {
        let v = untrusted::Input::from(bytes).read_all(untrusted::EndOfInput, read_u32).unwrap();
        if tag != v {
            println!("{} encoded to 0x{:x} != 0x{:x}", std::str::from_utf8(&bytes[..]).unwrap(), v, tag);
        }
        assert_eq!(tag, v);
    }
}



fn main() {
    // Really rough time.
    //println!("Ding Dong! It is 9 PM.");

    // Create a request with a random 64 byte nonce and PAD
    // 1 tag count, 2 tags + 1 offset = 4 words = 16 bytes
    // 1024 - 16 - 64 = 944 pad bytes
    let mut nonce_val = [0x44; 64];
    rand::thread_rng().fill_bytes(&mut nonce_val);
    let pad = [0; 944];
    let mut req = BTreeMap::new();
    req.insert(tag::NONC, Vec::from(&nonce_val[..]));
    req.insert(tag::PAD, Vec::from(&pad[..]));
    let req_msg = encode_message(&req);
    std::io::stdout().write(&req_msg);
}

#[test]
fn test_message_roundtrip() {

    let notags = untrusted::Input::from(b"\x00\x00\x00\x00");
    println!("Empty message: {:?}", parse_message(notags));

    let tags = untrusted::Input::from(b"\x02\x00\x00\x00\x04\x00\x00\x00\x05\x03\x02\x00\x04\x03\x02\x01\x00\x00\x00\x00\x80\x80\x80\x80");
    println!("Some stuff: {:?}", parse_message(tags));

    let ttags = untrusted::Input::from(
        b"\x03\x00\x00\x00\
          \
          \x04\x00\x00\x00\
          \x08\x00\x00\x00\
          \
          \x01\x00\x00\x00\
          \x02\x00\x00\x00\
          \xFF\xFF\xFF\xFF\
          \
          \x00\x00\x00\x00\
          \x80\x80\x80\x80\
          \xFF\xFF\xFF\xFF");
    let parsed = parse_message(ttags).unwrap();
    println!("Some stuff: {:?}", parsed);
    assert_eq!(parsed[&1], b"\x00\x00\x00\x00");
    assert_eq!(parsed[&2], b"\x80\x80\x80\x80");
    assert_eq!(parsed[&4294967295], b"\xFF\xFF\xFF\xFF");

    let reencoded = encode_message(&parsed);
    assert_eq!(ttags.as_slice_less_safe(), &reencoded[..]);
    let reparsed = parse_message(untrusted::Input::from(&reencoded[..])).unwrap();
    assert_eq!(parsed, reparsed);
    println!("Reparsed stuff: {:?}", reparsed)
}
