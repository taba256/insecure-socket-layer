use std::num::NonZeroUsize;

pub type Result<T> = std::result::Result<T, DecodeError>;
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("データがこわれています")]
    InvalidData,
    #[error("データ不足")]
    NeedMoreData,
}

pub struct Reader<'a> {
    buf: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, cursor: 0 }
    }
    pub fn cursor(&self) -> usize {
        self.cursor
    }
    pub fn available(&self) -> usize {
        self.buf.len() - self.cursor
    }
    pub fn is_eof(&self) -> bool {
        self.buf.len() <= self.cursor
    }
    pub fn take(&mut self, len: usize) -> Result<&[u8]> {
        if self.available() < len {
            return Err(DecodeError::NeedMoreData);
        }
        let start = self.cursor;
        self.cursor += len;
        Ok(&self.buf[start..self.cursor])
    }
    pub fn take_byte(&mut self) -> Result<u8> {
        self.take(1).map(|b| b[0])
    }
    pub fn slice(&mut self, len: usize) -> Result<Reader> {
        self.take(len).map(Reader::new)
    }
    pub fn remain(&mut self) -> Result<&[u8]> {
        let start = self.cursor;
        self.cursor = self.buf.len();
        Ok(&self.buf[start..])
    }
}

pub trait Codec: Sized {
    const SIZE_OF_SELF: Option<NonZeroUsize> = None;
    fn encode(&self, output: &mut Vec<u8>);
    fn decode(input: &mut Reader) -> Result<Self>;
}

impl Codec for u8 {
    const SIZE_OF_SELF: Option<NonZeroUsize> = NonZeroUsize::new(std::mem::size_of::<Self>());
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(*self);
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        input.take_byte()
    }
}

impl Codec for u16 {
    const SIZE_OF_SELF: Option<NonZeroUsize> = NonZeroUsize::new(std::mem::size_of::<Self>());
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend(self.to_be_bytes());
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        Ok(u16::from_be_bytes(
            input
                .take(2)?
                .try_into()
                .map_err(|_| DecodeError::InvalidData)?,
        ))
    }
}

impl Codec for u32 {
    const SIZE_OF_SELF: Option<NonZeroUsize> = NonZeroUsize::new(std::mem::size_of::<Self>());
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend(self.to_be_bytes());
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        Ok(u32::from_be_bytes(
            input
                .take(4)?
                .try_into()
                .map_err(|_| DecodeError::InvalidData)?,
        ))
    }
}

#[allow(non_camel_case_types)]
pub struct u24(pub u32);
impl u24 {
    pub fn from_be_bytes(bytes: [u8; 3]) -> Self {
        Self(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }
}
impl Codec for u24 {
    const SIZE_OF_SELF: Option<NonZeroUsize> = NonZeroUsize::new(3);
    fn encode(&self, output: &mut Vec<u8>) {
        let bytes = self.0.to_be_bytes();
        output.extend(&bytes[1..])
    }
    fn decode(input: &mut Reader) -> Result<Self> {
        Ok(u24::from_be_bytes(
            input
                .take(3)?
                .try_into()
                .map_err(|_| DecodeError::InvalidData)?,
        ))
    }
}
impl From<u24> for usize {
    fn from(u: u24) -> usize {
        u.0 as usize
    }
}

pub fn encode_slice<I: Codec, const LENGTH_SIZE: usize>(output: &mut Vec<u8>, items: &[I]) {
    let start_cursor = output.len();
    // もしもアイテムのサイズが不明でないなら、先に領域を確保しておくと幸せになれる
    if let Some(size) = I::SIZE_OF_SELF {
        let items_len_bytes = size.get() * items.len();
        output.reserve(items_len_bytes + LENGTH_SIZE);
        output.extend(&(items_len_bytes as u64).to_be_bytes()[8 - LENGTH_SIZE..]);
    } else {
        // アイテムサイズが不明の場合、lengthを格納する部分を確保しておく
        output.resize(start_cursor + LENGTH_SIZE, 0);
    }
    for item in items {
        item.encode(output);
    }
    // アイテムサイズが不明なら、バイト数の格納はデータ格納後に行う
    if I::SIZE_OF_SELF.is_none() {
        let end_cursor = output.len();
        let items_len_bytes = end_cursor - (start_cursor + LENGTH_SIZE);
        output.extend(&(items_len_bytes as u64).to_be_bytes()[8 - LENGTH_SIZE..]);
    }
}

pub fn decode_vec<I: Codec, const LENGTH_SIZE: usize>(input: &mut Reader) -> Result<Vec<I>> {
    let items_len_bytes = {
        let mut len_bytes = [0; 8];
        len_bytes
            .iter_mut()
            .rev()
            .zip(input.take(LENGTH_SIZE)?.iter().rev())
            .for_each(|(a, b)| *a = *b);
        u64::from_be_bytes(len_bytes) as usize
    };
    let input = &mut input.slice(items_len_bytes)?;
    let mut res = Vec::new();
    if let Some(size) = I::SIZE_OF_SELF {
        if items_len_bytes % size.get() != 0 {
            return Err(DecodeError::InvalidData);
        }
        let items_len = items_len_bytes / size.get();
        res.reserve(items_len);
    }
    while !input.is_eof() {
        res.push(I::decode(input)?);
    }
    Ok(res)
}
