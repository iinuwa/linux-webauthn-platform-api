use std::convert::TryInto;
use std::io::{Error, Write};

struct CborWriter<W> {
    writer: W,
}

impl <W> CborWriter<W>
where W: Write {
    fn new(writer: W) -> Self {
        CborWriter { writer }
    }

    fn write_bytes<T>(&mut self, data: T) -> Result<(), Error>
    where T: AsRef<[u8]> {
        const MAJOR_TYPE_MASK: u8 = 0b011_00000;
        let d = data.as_ref();
        let len: u64 = d.len().try_into().unwrap();
        let mut major_type_buf = vec![0; 17];
        if len < 24 {
            let l: u8 = len.try_into().unwrap();
            self.writer.write(&[l | MAJOR_TYPE_MASK])?;
        }
        else if len < 2u64.pow(8) {
            let l: u8 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..2].copy_from_slice(&l.to_be_bytes());
            self.writer.write(&major_type_buf)?;
        } else if len < 2u64.pow(16) {
            let l: u16 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..4].copy_from_slice(&l.to_be_bytes());
            self.writer.write(&major_type_buf)?;
        } else if len < 2u64.pow(32) {
            let l: u32 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..8].copy_from_slice(&l.to_be_bytes());
            self.writer.write(&major_type_buf)?;
        } else if len < 2u64.pow(64) {
            let l: u64 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..16].copy_from_slice(&l.to_be_bytes());
            self.writer.write(&major_type_buf)?;
        }
        else {
            return Err(Error::new(std::io::ErrorKind::Unsupported, "Value too large".to_string()));
        }
        self.writer.write(data.as_ref())?;
        Ok(())

    }
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

#[cfg(test)]
mod tests {
    use super::CborWriter;

    #[test]
    fn write_bytes() {
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        // let b: &mut [u8] = buf.as_mut();
        let mut cbor_writer = CborWriter::new(&mut buf[0..15]);
        let data: &[u8] = &[0x01, 0x23, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff];
        cbor_writer.write_bytes(data).unwrap();
        assert_eq!(buf, &[0b011_01001, 0x01, 0x23, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff]);
    }
}