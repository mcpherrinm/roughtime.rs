extern crate untrusted;

use std::collections::HashMap;
use std::vec::Vec;

/// Reads a little endian u32 from the reader.  If the input doesn't have 4 bytes,
/// then we return untrusted::EndOfInput.
fn read_u32(reader: &mut untrusted::Reader) -> Result<u32, untrusted::EndOfInput> {
    let b1 = try!(reader.read_byte()) as u32;
    let b2 = try!(reader.read_byte()) as u32;
    let b3 = try!(reader.read_byte()) as u32;
    let b4 = try!(reader.read_byte()) as u32;
    Ok(b1 | b2 << 8 | b3 << 16 | b4 << 24)
}

fn read_message(reader: &mut untrusted::Reader) -> Result<HashMap<u32, Vec<u8>>, untrusted::EndOfInput> {
    let num_tags = try!(read_u32(reader));
    if num_tags == 0 {
        return Ok(HashMap::new());
    }
    // There are num_tags-1 offsets
    // DOC ERROR: Docs say min(0, num_tags-1), and not max.
    let mut offsets: Vec<u32> = Vec::with_capacity(num_tags as usize);
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
    let mut map = HashMap::new();
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
fn parse_message(input: untrusted::Input) -> Result<HashMap<u32, Vec<u8>>, ()> {
    match input.read_all(untrusted::EndOfInput, read_message) {
        Ok(n) => Ok(n),
        Err(_) => Err(())
    }
}

fn main() {
    // Really rough time.
    println!("Ding Dong! It is 9 PM.");


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
    println!("Some stuff: {:?}", parse_message(ttags));

}
