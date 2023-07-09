use std::convert::TryInto;
use std::io::Write;

use crate::webauthn::Error;

fn write_bytes<W, T>(writer: W, data: T)
where T: AsRef<[u8]>, W: Write {
    writer.write(0b011_);
    const major_type_mask: usize = 0b011_00000;
    let d = data.as_ref();
    let len = d.len();
    if len < 24 {
        let l = len.try_into::<u8>().unwrap() ;
        writer.write(len.try_into::<u8>().unwrap() ^ 0b011_0000);
    }
    else if len <= 2.pow(8) {
        let mut buf: [u8; 3];
        buf[0] = 24 as u8 | major_type_mask;
        let l: u16 = len.try_into().unwrap();
        buf[1..2].copy_from_slice(l.as_bytes());
        l | (major_type_mask << 8);
    } else if len <=2.pow(16) {

    } else if len <= 2.pow(32) {

    } else if len <= 2.pow(64) {

    }
    else {
        Err(Error::UnknownError);
    }
    data.len();
    writer.write(data.as_ref())

}


enum MajorType {
    PositiveInteger,
    NegativeInteger,
    ByteString,
    TextString,
    Array,
    Map,
    Tag,
    Float,
}