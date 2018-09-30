#![deny(missing_docs)]

//! Rust implementation of the TUS protocol
//!
//! https://tus.io/protocols/resumable-upload.html

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate reqwest;

use std::io::Read;
use failure::Error;
pub use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

/// Version of the TUS protocol we're configured to use.
pub const TUS_VERSION: &'static str = "1.0.0";

/// Default is 4 meg chunks
const CHUNK_SIZE: usize = 1024 * 1024 * 4;

lazy_static! {
    static ref TUS_RESUMABLE: HeaderName = HeaderName::from_static("tus-resumable");
    static ref UPLOAD_OFFSET: HeaderName = HeaderName::from_static("upload-offset");
    static ref UPLOAD_LENGTH: HeaderName = HeaderName::from_static("upload-length");

    static ref OFFSET_OCTET_STREAM: HeaderValue = HeaderValue::from_static("application/offset+octet-stream");
}

/// A client for a TUS endpoint. This leaks a lot of the implementation details of reqwest.
pub struct Client {
    url: String,
    headers: HeaderMap,
    // TODO(richo) Make this generic over some trait so we can test it
    client: reqwest::Client,
}

impl Client {
    /// Creates a new
    pub fn new(url: String, headers: HeaderMap) -> Client {
        Client {
            url,
            headers,
            client: reqwest::Client::new(),
        }
    }

    /// Uploads all content from `reader` to the endpoint, consuming this Client.
    pub fn upload<T>(mut self, mut reader: T) -> Result<usize, Error>
    where T: Read {
        let mut offset = 0;
        loop {
            let mut buf = Vec::with_capacity(CHUNK_SIZE);
            let len = reader.read(&mut buf)?;
            if len == 0 {
                return Ok(offset)
            }
            let mut headers = self.headers.clone();
            headers.insert(UPLOAD_OFFSET.clone(), HeaderValue::from_str(&format!("{}", offset))?);
            offset += self.upload_chunk(buf, headers)?;
        }
        Ok(offset)
    }

    fn upload_chunk(&mut self, chunk: Vec<u8>, headers: HeaderMap) -> Result<usize, Error> {
        let len = chunk.len();
        let res = self.client
            .patch(&self.url)
            .body(chunk)
            .headers(headers)
            .send()?;
        if res.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(format_err!("Did not save chunk: {}", res.status()))
        }
        // TODO(richo) parse out the UPLOAD_OFFSET value, and do the appropriate bookkeeping
        // internally to resend any of the chunk that was not saved.
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
