use std::convert::TryInto;
use std::io::{Error, Write};

pub(crate) struct CborWriter<'a, W> {
    writer: &'a mut W,
}

impl <W> CborWriter<'_, W>
where W: Write {
    pub fn new(writer: &'_ mut W) -> CborWriter<'_, W> {
        CborWriter { writer }
    }

    pub fn write_bytes<T>(&mut self, data: T) -> Result<(), Error>
    where T: AsRef<[u8]> {
        self.write_cbor_value(MajorType::ByteString, data.as_ref())?;
        return Ok(());
        const MAJOR_TYPE_MASK: u8 = 0b010_00000;
        let d = data.as_ref();
        let len: u64 = d.len().try_into().unwrap();
        let mut major_type_buf = vec![0; 17];
        if len < 24 {
            let l: u8 = len.try_into().unwrap();
            self.writer.write_all(&[l | MAJOR_TYPE_MASK])?;
        }
        else if len < 2u64.pow(8) {
            let l: u8 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..2].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        } else if len < 2u64.pow(16) {
            let l: u16 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..4].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        } else if len < 2u64.pow(32) {
            let l: u32 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..8].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        } else if len < 2u64.pow(64) {
            let l: u64 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | MAJOR_TYPE_MASK;
            major_type_buf[1..16].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        }
        else {
            return Err(Error::new(std::io::ErrorKind::Unsupported, "Value too large".to_string()));
        }
        self.writer.write(data.as_ref())?;
        Ok(())

    }

    pub fn write_number(&mut self, num: i128) -> Result<(), Error> {
        const POSITIVE_INTEGER_MASK: u8 = 0b000_00000;
        const NEGATIVE_INTEGER_MASK: u8 = 0b001_00000;
        let (mask, num) = if num >= 0 { (POSITIVE_INTEGER_MASK, num as u64) } else { (NEGATIVE_INTEGER_MASK, (-num - 1) as u64)};
        if num < 24 {
            let d: u8 = num.try_into().unwrap();
            self.writer.write_all(&[mask | d])?;
            Ok(())
        }
        else if num < 2u64.pow(8) {
            let d: u8 = num.try_into().unwrap();
            self.writer.write_all(&[mask | 24])?;
            self.writer.write_all(&d.to_be_bytes())?;
            Ok(())
        } else if num < 2u64.pow(16) {
            let d: u16 = num.try_into().unwrap();
            self.writer.write_all(&[mask | 25])?;
            self.writer.write_all(&d.to_be_bytes())?;
            Ok(())
        } else if num < 2u64.pow(32) {
            let d: u32 = num.try_into().unwrap();
            self.writer.write_all(&[mask | 26])?;
            self.writer.write_all(&d.to_be_bytes())?;
            Ok(())
        } else if num < 2u64.pow(64) {
            let d: u64 = num.try_into().unwrap();
            self.writer.write_all(&[mask | 27])?;
            self.writer.write_all(&d.to_be_bytes())?;
            Ok(())
        }
        else {
            Err(Error::new(std::io::ErrorKind::InvalidInput, "value too large".to_string()))
        }
    }

    pub fn write_map_start(len: usize) {
        write_cbor_value(MajorType::Map, )
    }

    fn write_cbor_value(&mut self, major_type: MajorType, len: u64, data: &[u8]) -> Result<(), Error> {
        let major_type_mask = match major_type {
            MajorType::PositiveInteger => 0b000_00000,
            MajorType::NegativeInteger => 0b001_00000,
            MajorType::ByteString => 0b010_00000,
            MajorType::TextString => 0b011_00000,
            MajorType::Array => 0b100_00000,
            MajorType::Map => 0b101_00000,
            MajorType::Tag => 0b110_00000,
            MajorType::Float => 0b111_00000,
        };

        let d = data.as_ref();
        // let len: u64 = d.len().try_into().unwrap();
        let mut major_type_buf = vec![0; 17];
        if len
        if len > 0
        if len < 24 {
            let l: u8 = len.try_into().unwrap();
            self.writer.write_all(&[l | major_type_mask])?;
        }
        else if len < 2u64.pow(8) {
            let l: u8 = len.try_into().unwrap();
            major_type_buf[0] = 24u8 | major_type_mask;
            major_type_buf[1..2].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        } else if len < 2u64.pow(16) {
            let l: u16 = len.try_into().unwrap();
            major_type_buf[0] = 0b10101010; // 25u8 | major_type_mask;
            major_type_buf[1..4].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        } else if len < 2u64.pow(32) {
            let l: u32 = len.try_into().unwrap();
            major_type_buf[0] = 26u8 | major_type_mask;
            major_type_buf[1..8].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
        } else if len < 2u64.pow(64) {
            let l: u64 = len.try_into().unwrap();
            major_type_buf[0] = 27u8 | major_type_mask;
            major_type_buf[1..16].copy_from_slice(&l.to_be_bytes());
            self.writer.write_all(&major_type_buf)?;
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
        let mut cbor_writer = CborWriter::new(&mut buf);
        let data: &[u8] = &[0x01, 0x23, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff];
        cbor_writer.write_bytes(data).unwrap();
        assert_eq!(buf, &[0b010_01001, 0x01, 0x23, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff]);
    }

    #[test]
    fn write_bytes_over24() {
        let mut buf: Vec<u8> = Vec::new();
        // let b: &mut [u8] = buf.as_mut();
        let mut cbor_writer = CborWriter::new(&mut buf);
        // let data: &[u8] = &[0x00, 0x, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff];
        let data = vec![0; 32];
        cbor_writer.write_bytes(data.clone()).unwrap();
        assert_eq!(&buf[0..2], &[0b010_11000, 32u8]);
        assert_eq!(&buf[2..34], &data);
    }

    #[test]
    fn write_uint() {
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        // let b: &mut [u8] = buf.as_mut();
        let mut cbor_writer = CborWriter::new(&mut buf);
        cbor_writer.write_number(22 as i128).unwrap();
        assert_eq!(buf, &[0b000_10110]);
    }

    #[test]
    fn write_number_u8() {
        let mut buf: Vec<u8> = Vec::with_capacity(16);
        // let b: &mut [u8] = buf.as_mut();
        let mut cbor_writer = CborWriter::new(&mut buf);
        cbor_writer.write_number(500 as i128).unwrap();
        assert_eq!(buf, &[0b000_11001, 0x01, 0xf4]);
    }
}