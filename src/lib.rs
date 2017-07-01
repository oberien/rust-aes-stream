extern crate crypto;

#[cfg(test)] mod tests;

use std::io::{Read, Write, Seek, SeekFrom, Result, Error, ErrorKind};

use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor, Encryptor, Decryptor};
use crypto::blockmodes::{PkcsPadding, CbcEncryptor, CbcDecryptor, EncPadding, DecPadding};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer};

const BUFFER_SIZE: usize = 8192;

pub struct AesWriter<E: BlockEncryptor, W: Write> {
    writer: W,
    enc: CbcEncryptor<E, EncPadding<PkcsPadding>>,
    closed: bool,
}

impl<E: BlockEncryptor, W: Write> AesWriter<E, W> {
    pub fn new(writer: W, enc: E, iv: Vec<u8>) -> AesWriter<E, W> {
        AesWriter {
            writer: writer,
            enc: CbcEncryptor::new(enc, PkcsPadding, iv),
            closed: false,
        }
    }

    fn encrypt_write(&mut self, buf: &[u8], eof: bool) -> Result<usize> {
        let mut read_buf = RefReadBuffer::new(buf);
        let mut out = [0u8; BUFFER_SIZE];
        let mut write_buf = RefWriteBuffer::new(&mut out);
        loop {
            let res = self.enc.encrypt(&mut read_buf, &mut write_buf, eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("encryption error: {:?}", e)))?;
            let mut enc = write_buf.take_read_buffer();
            let enc = enc.take_remaining();
            self.writer.write_all(enc)?;
            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow if eof =>
                    panic!("read_buf underflow during encryption with eof"),
                BufferResult::BufferOverflow => {},
            }
        }
        // CbcEncryptor has its own internal buffer and always consumes everything
        assert_eq!(read_buf.remaining(), 0);
        Ok(buf.len())
    }
}

impl<E: BlockEncryptor, W: Write> Write for AesWriter<E, W> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(Error::new(ErrorKind::Other, "AesWriter is closed"));
        }
        let written = self.encrypt_write(buf, false)?;
        Ok(written)
    }

    fn flush(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.encrypt_write(&[], true)?;
        self.closed = true;
        self.writer.flush()
    }
}

impl<E: BlockEncryptor, W: Write> Drop for AesWriter<E, W> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.flush().unwrap();
        } else {
            let _ = self.flush();
        }
    }
}

pub struct AesReader<D: BlockDecryptor, R: Read> {
    /// Reader to read encrypted data from
    reader: R,
    /// Decryptor to decrypt data with
    dec: CbcDecryptor<D, DecPadding<PkcsPadding>>,
    /// IV used if seeked to the first block
    iv: Vec<u8>,
    /// Block size of BlockDecryptor, needed when seeking to correctly seek to the nearest block
    block_size: usize,
    /// Buffer used to store blob needed to find out if we reached eof
    buffer: Vec<u8>,
    /// Indicates wheather eof of the underlying buffer was reached
    eof: bool,
}

impl<D: BlockDecryptor, R: Read> AesReader<D, R> {
    pub fn new(reader: R, dec: D, iv: Vec<u8>) -> AesReader<D, R> {
        AesReader {
            reader: reader,
            block_size: dec.block_size(),
            iv: iv.clone(),
            dec: CbcDecryptor::new(dec, PkcsPadding, iv),
            buffer: Vec::new(),
            eof: false,
        }
    }

    fn fill_buf(&mut self) -> Result<Vec<u8>> {
        let mut eof_buffer = vec![0u8; BUFFER_SIZE];
        let read = self.reader.read(&mut eof_buffer)?;
        self.eof = read == 0;
        eof_buffer.truncate(read);
        Ok(eof_buffer)
    }

    fn read_decrypt(&mut self, buf: &mut [u8]) -> Result<usize> {
        let buf_len = buf.len();
        let mut write_buf = RefWriteBuffer::new(buf);
        let mut read_buf = RefReadBuffer::new(&[]);

        // test if CbcDecryptor still has enough decrypted data
        let res = self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
            .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
        match res {
            BufferResult::BufferOverflow => return Ok(buf_len),
            BufferResult::BufferUnderflow if self.eof => return Ok(write_buf.position()),
            _ => {}
        }

        // if this is the first iteration, fill internal buffer
        if self.buffer.is_empty() && !self.eof {
            self.buffer = self.fill_buf()?;
        }

        let mut dec_len = 0;
        while dec_len == 0 && !self.eof {
            let eof_buffer = self.fill_buf()?;
            {
                let mut read_buf = RefReadBuffer::new(&self.buffer);
                self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
                let mut dec = write_buf.take_read_buffer();
                let dec = dec.take_remaining();
                dec_len = dec.len();
            }
            // keep remaining bytes
            let len = self.buffer.len();
            self.buffer.drain(..(len - read_buf.remaining()));
            // append newly read bytes
            self.buffer.extend(eof_buffer);
        }
        Ok(dec_len)
    }
}

impl<D: BlockDecryptor, R: Read> Read for AesReader<D, R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self.read_decrypt(buf)?;
        Ok(read)
    }
}

impl<D: BlockDecryptor, R: Read + Seek> Seek for AesReader<D, R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                let block_num = offset / self.block_size as u64;
                let block_offset = offset % self.block_size as u64;
                // reset CbcDecryptor
                if block_num == 0 {
                    self.dec.reset(&self.iv);
                } else {
                    self.reader.seek(SeekFrom::Start(block_num * self.block_size as u64))?;
                    self.buffer = Vec::new();
                    self.eof = false;
                    let mut iv = vec![0u8; self.block_size];
                    self.reader.read_exact(&mut iv)?;
                    self.dec.reset(&iv);
                }
                let mut skip = vec![0u8; block_offset as usize];
                self.read_exact(&mut skip)?;
                Ok(offset)
            },
            _ => unimplemented!()
        }
    }
}
