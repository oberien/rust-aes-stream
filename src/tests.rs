use super::*;
use std::io::{Write, Read, Cursor};
use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};

struct VecRefCursor<'a>(&'a mut Vec<u8>);

impl<'a> Write for VecRefCursor<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

fn encrypt(data: &[u8]) -> Vec<u8> {
    let key = [0u8; 16];
    let iv = vec![0u8; 16];
    let block_enc = AesSafe128Encryptor::new(&key);
    let mut enc = Vec::new();
    {
        let mut aes = AesWriter::new(VecRefCursor(&mut enc), block_enc, iv.clone());
        aes.write_all(&data).unwrap();
    }
    enc
}

fn decrypt<R: Read>(data: R) -> Vec<u8> {
    let key = [0u8; 16];
    let iv = vec![0u8; 16];
    let block_dec = AesSafe128Decryptor::new(&key);
    let mut dec = Vec::new();
    let mut aes = AesReader::new(data, block_dec, iv);
    aes.read_to_end(&mut dec).unwrap();
    dec
}

struct UnalignedReader<'a> {
    buf: &'a [u8],
    block_size: usize,
    written: usize,
}
impl<'a> UnalignedReader<'a> {
    fn new(buf: &'a [u8], block_size: usize) -> UnalignedReader<'a> {
        UnalignedReader { buf, block_size, written: 0 }
    }
}
impl<'a> Read for UnalignedReader<'a> {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {
        let until = std::cmp::min(self.written + self.block_size, self.buf.len());
        let written = buf.write(&self.buf[self.written..until]).unwrap();
        self.written += written;
        Ok(written)
    }
}

#[test]
fn enc_unaligned() {
    let orig = [0u8; 16];
    let key = [0u8; 16];
    let iv = vec![0u8; 16];
    let block_enc = AesSafe128Encryptor::new(&key);
    let mut enc = Vec::new();
    {
        let mut aes = AesWriter::new(VecRefCursor(&mut enc), block_enc, iv.clone());
        for chunk in orig.chunks(3) {
            aes.write_all(&chunk).unwrap();
        }
    }
    assert_eq!(enc.len(), 32);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn enc_dec_single() {
    let orig = [0u8; 15];
    let enc = encrypt(&orig);
    assert_eq!(enc.len(), 16);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn enc_dec_single_full() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);
    assert_eq!(enc.len(), 32);
    let dec = decrypt(Cursor::new(&enc));
    assert_eq!(dec, &orig);
}

#[test]
fn dec_unaligned() {
    let orig = [0u8; 16];
    let mut enc = encrypt(&orig);
    let dec = decrypt(UnalignedReader::new(&mut enc, 3));
    assert_eq!(dec, &orig);
}

#[test]
fn dec_read_unaligned() {
    let orig = [0u8; 16];
    let enc = encrypt(&orig);

    let key = [0u8; 16];
    let iv = vec![0u8; 16];
    let block_dec = AesSafe128Decryptor::new(&key);
    let mut dec: Vec<u8> = Vec::new();
    let mut aes = AesReader::new(Cursor::new(&enc), block_dec, iv);
    loop {
        let mut buf = [0u8; 3];
        let read = aes.read(&mut buf).unwrap();
        dec.extend(&buf[..read]);
        if read == 0 { break; }
    }
    assert_eq!(dec, &orig);
}
