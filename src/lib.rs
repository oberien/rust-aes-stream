//! Read/Write Wrapper for AES Encryption and Decryption during I/O Operations
//!
//! This crate provides an [`AesWriter`](struct.AesWriter.html), which can be used to wrap any
//! existing [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) implementation with AES
//! encryption, and [`AesReader`](struct.AesReader.html), which can wrap any existing
//! [`Read`](https://doc.rust-lang.org/std/io/trait.Read.html) implemntation with AES decryption.
//! If the inner reader provides a [`Seek`](https://doc.rust-lang.org/std/io/trait.Seek.html)
//! implementation, AesReader will do so as well.
//! See their struct-level documentation for more information.
//!
//! In fact this crate is not limited to AES.
//! It can wrap any kind of [`BlockEncryptor`][be] i.e. [`BlockDecryptor`][bd] with CBC.
//!
//! [be]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
//! [bd]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
//!
//! # Examples
//!
//! You can use [`AesWriter`](struct.AesWriter.html) to wrap a file with encryption.
//!
//! ```no_run
//! # extern crate crypto;
//! # extern crate aesstream;
//! # use std::io::{Write, Result};
//! # use std::fs::File;
//! # use crypto::aessafe::AesSafe128Encryptor;
//! # use aesstream::AesWriter;
//! # fn foo() -> Result<()> {
//! let key = [0u8; 16];
//! let iv = vec![0u8; 16];
//! let file = File::open("...")?;
//! let encryptor = AesSafe128Encryptor::new(&key);
//! let mut writer = AesWriter::new(file, encryptor, iv.clone());
//! writer.write_all("Hello World!".as_bytes())?;
//! # Ok(())
//! # }
//! # fn main() { let _ = foo(); }
//! ```
//!
//! And [`AesReader`](struct.AesReader.html) to decrypt it again.
//!
//! ```no_run
//! # extern crate crypto;
//! # extern crate aesstream;
//! # use std::io::{Read, Result};
//! # use std::fs::File;
//! # use crypto::aessafe::AesSafe128Decryptor;
//! # use aesstream::AesReader;
//! # fn foo() -> Result<()> {
//! let key = [0u8; 16];
//! let iv = vec![0u8; 16];
//! let file = File::open("...")?;
//! let decryptor = AesSafe128Decryptor::new(&key);
//! let mut reader = AesReader::new(file, decryptor, iv.clone());
//! let mut decrypted = String::new();
//! reader.read_to_string(&mut decrypted)?;
//! assert_eq!(decrypted, "Hello World!");
//! # Ok(())
//! # }
//! # fn main() { let _ = foo(); }
//! ```
//!
//! They can be used to en- and decrypt in-memory as well.
//!
//! ```
//! # extern crate crypto;
//! # extern crate aesstream;
//! # use std::io::{Read, Write, Result, Cursor};
//! # use crypto::aessafe::{AesSafe128Encryptor, AesSafe128Decryptor};
//! # use aesstream::{AesWriter, AesReader};
//! # fn foo() -> Result<()> {
//! let key = [0u8; 16];
//! let iv = vec![0u8; 16];
//! let encryptor = AesSafe128Encryptor::new(&key);
//! let mut writer = AesWriter::new(Vec::new(), encryptor, iv.clone());
//! writer.write_all("Hello World!".as_bytes())?;
//! let encrypted = writer.into_inner()?;
//!
//! let decryptor = AesSafe128Decryptor::new(&key);
//! let mut reader = AesReader::new(Cursor::new(encrypted), decryptor, iv);
//! let mut decrypted = String::new();
//! reader.read_to_string(&mut decrypted)?;
//! assert_eq!(decrypted, "Hello World!");
//! # Ok(())
//! # }
//! # fn main() { let _ = foo(); }
//! ```

extern crate crypto;

#[cfg(test)] mod tests;

use std::io::{Read, Write, Seek, SeekFrom, Result, Error, ErrorKind};

use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor, Encryptor, Decryptor};
use crypto::blockmodes::{PkcsPadding, CbcEncryptor, CbcDecryptor, EncPadding, DecPadding};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer};

const BUFFER_SIZE: usize = 8192;

/// Wraps a [`Write`](https://doc.rust-lang.org/std/io/trait.Write.html) implementation with CBC
/// based on given [`BlockEncryptor`][be]
///
/// [be]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
///
/// # Examples
///
/// Write encrypted to a file.
///
/// ```no_run
/// # extern crate crypto;
/// # extern crate aesstream;
/// # use std::io::{Write, Result};
/// # use std::fs::File;
/// # use crypto::aessafe::AesSafe128Encryptor;
/// # use aesstream::AesWriter;
/// # fn foo() -> Result<()> {
/// let key = [0u8; 16];
/// let iv = vec![0u8; 16];
/// let file = File::open("...")?;
/// let encryptor = AesSafe128Encryptor::new(&key);
/// let mut writer = AesWriter::new(file, encryptor, iv.clone());
/// writer.write_all("Hello World!".as_bytes())?;
/// # Ok(())
/// # }
/// # fn main() { let _ = foo(); }
/// ```
///
/// Encrypt in-memory.
///
/// ```
/// # extern crate crypto;
/// # extern crate aesstream;
/// # use std::io::{Write, Result, Cursor};
/// # use crypto::aessafe::AesSafe128Encryptor;
/// # use aesstream::AesWriter;
/// # fn foo() -> Result<()> {
/// let key = [0u8; 16];
/// let iv = vec![0u8; 16];
/// let encryptor = AesSafe128Encryptor::new(&key);
/// let mut writer = AesWriter::new(Vec::new(), encryptor, iv.clone());
/// writer.write_all("Hello World!".as_bytes())?;
/// let encrypted = writer.into_inner()?;
/// # Ok(())
/// # }
/// # fn main() { let _ = foo(); }
/// ```
pub struct AesWriter<E: BlockEncryptor, W: Write> {
    /// Writer to write encrypted data to
    writer: Option<W>,
    /// Encryptor to encrypt data with
    enc: CbcEncryptor<E, EncPadding<PkcsPadding>>,
    /// Indicates weather the encryptor has done its final operation (inserting padding)
    closed: bool,
}

impl<E: BlockEncryptor, W: Write> AesWriter<E, W> {
    /// Creates a new AesWriter.
    ///
    /// # Parameters
    ///
    /// * **writer**: Writer to write encrypted data into
    /// * **enc**: [`BlockEncryptor`][be] to use for encyrption
    /// * **iv**: IV used for CBC operation. It must have a length of 16 bytes
    ///
    /// # Panics
    ///
    /// Panics if the passed IV does not have 16 bytes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate crypto;
    /// # extern crate aesstream;
    /// # use crypto::aessafe::AesSafe128Encryptor;
    /// # use std::io::Result;
    /// # use std::fs::File;
    /// # use aesstream::AesWriter;
    /// # fn foo() -> Result<()> {
    /// let key = [0u8; 16];
    /// let iv = vec![0u8; 16];
    /// let encryptor = AesSafe128Encryptor::new(&key);
    /// let file = File::open("...")?;
    /// let mut writer = AesWriter::new(file, encryptor, iv);
    /// # Ok(())
    /// # }
    /// # fn main() { let _ = foo(); }
    /// ```
    ///
    /// [be]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockEncryptor.html
    pub fn new(writer: W, enc: E, iv: Vec<u8>) -> AesWriter<E, W> {
        assert_eq!(iv.len(), 16, "IV must be 16 bytes in length");
        AesWriter {
            writer: Some(writer),
            enc: CbcEncryptor::new(enc, PkcsPadding, iv),
            closed: false,
        }
    }

    /// Consumes self and returns the underlying writer.
    ///
    /// This method finishes encryption and flushes the internal encryption buffer.
    ///
    /// # Errors
    ///
    /// If flushing fails, the error is returned.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate crypto;
    /// # extern crate aesstream;
    /// # use crypto::aessafe::AesSafe128Encryptor;
    /// # use std::io::Result;
    /// # use std::fs::File;
    /// # use aesstream::AesWriter;
    /// # fn foo() -> Result<()> {
    /// let key = [0u8; 16];
    /// let iv = vec![0u8; 16];
    /// let encryptor = AesSafe128Encryptor::new(&key);
    /// let file = File::open("...")?;
    /// let mut writer = AesWriter::new(file, encryptor, iv);
    /// // do something with writer
    /// let file = writer.into_inner()?;
    /// # Ok(())
    /// # }
    /// # fn main() { let _ = foo(); }
    /// ```
    pub fn into_inner(mut self) -> Result<W> {
        self.flush()?;
        Ok(self.writer.take().unwrap())
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
            self.writer.as_mut().unwrap().write_all(enc)?;
            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow if eof =>
                    panic!("read_buf underflow during encryption with eof"),
                BufferResult::BufferOverflow => {},
            }
        }
        // CbcEncryptor has its own internal buffer and always consumes all input
        assert_eq!(read_buf.remaining(), 0);
        Ok(buf.len())
    }
}

impl<E: BlockEncryptor, W: Write> Write for AesWriter<E, W> {
    /// Encrypts the passed buffer and writes the result to the underlying writer.
    ///
    /// Due to the blocksize of CBC not all data will be written instantaneously.
    /// For example if 17 bytes are passed, the first 16 will be encrypted as one block and written
    /// the underlying writer, but the last byte won't be encrypted and written yet.
    ///
    /// If [`flush`](#method.flush) has been called, this method will always return an error.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(Error::new(ErrorKind::Other, "AesWriter is closed"));
        }
        let written = self.encrypt_write(buf, false)?;
        Ok(written)
    }

    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    /// [Read more](https://doc.rust-lang.org/nightly/std/io/trait.Write.html#tymethod.flush)
    ///
    /// **Warning**: When this method is called, the encryption will finish and insert final padding.
    /// After calling `flush`, this writer cannot be written to anymore and will always return an
    /// error.
    fn flush(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.encrypt_write(&[], true)?;
        self.closed = true;
        self.writer.as_mut().unwrap().flush()
    }
}

impl<E: BlockEncryptor, W: Write> Drop for AesWriter<E, W> {
    /// Drops this AesWriter trying to finish encryption and write everything to the underlying writer.
    fn drop(&mut self) {
        if self.writer.is_some() {
            if !std::thread::panicking() {
                self.flush().unwrap();
            } else {
                let _ = self.flush();
            }
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
        assert_eq!(iv.len(), 16, "IV must be 16 bytes in length");
        AesReader {
            reader: reader,
            block_size: dec.block_size(),
            iv: iv.clone(),
            dec: CbcDecryptor::new(dec, PkcsPadding, iv),
            buffer: Vec::new(),
            eof: false,
        }
    }

    pub fn into_inner(self) -> R {
        self.reader
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
        let res;
        let remaining;
        {
            let mut read_buf = RefReadBuffer::new(&self.buffer);

            // test if CbcDecryptor still has enough decrypted data
            res = self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
            remaining = read_buf.remaining();
        }
        // keep remaining bytes
        let len = self.buffer.len();
        self.buffer.drain(..(len - remaining));
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
            let remaining;
            {
                let mut read_buf = RefReadBuffer::new(&self.buffer);
                self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
                let mut dec = write_buf.take_read_buffer();
                let dec = dec.take_remaining();
                dec_len = dec.len();
                remaining = read_buf.remaining();
            }
            // keep remaining bytes
            let len = self.buffer.len();
            self.buffer.drain(..(len - remaining));
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
                    self.reader.seek(SeekFrom::Start(0))?;
                    self.dec.reset(&self.iv);
                } else {
                    self.reader.seek(SeekFrom::Start((block_num - 1) * self.block_size as u64))?;
                    let mut iv = vec![0u8; self.block_size];
                    self.reader.read_exact(&mut iv)?;
                    self.dec.reset(&iv);
                }
                self.buffer = Vec::new();
                self.eof = false;
                let mut skip = vec![0u8; block_offset as usize];
                self.read_exact(&mut skip)?;
                Ok(offset)
            },
            SeekFrom::Current(_) | SeekFrom::End(_) => {
                let pos = self.reader.seek(pos)?;
                self.seek(SeekFrom::Start(pos))
            },
        }
    }
}
