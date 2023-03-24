use crate::{
    msg::{codec::DecodeError, *},
    *,
};
use std::collections::VecDeque;

pub struct RecordDefragContext {
    messages: VecDeque<Message>,
    buffer: Vec<u8>,
}
impl RecordDefragContext {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            buffer: Vec::new(),
        }
    }
    pub fn extend_buffer(&mut self, content_type: u8, fragment: &[u8]) -> Result<usize> {
        // fragment単位で呼ばれるため、バッファが空でないのはメッセージが複数のレコードにまたがっている場合
        self.buffer.extend(fragment);
        while !self.buffer.is_empty() {
            let input = &mut crate::msg::codec::Reader::new(&self.buffer);
            match Message::decode(content_type, input) {
                Ok(msg) => {
                    // Messageとして解釈できたら、その分のデータをdrainして次のデータを先頭にする
                    // そして次のループでまたデコードだ
                    self.buffer.drain(..input.cursor());
                    self.messages.push_back(msg);
                }
                Err(DecodeError::NeedMoreData) => {
                    // データがデコードに足りない場合、次のfragmentを追加すれば行けるかもしれない
                    // よってリターンしてよい
                    break;
                }
                Err(DecodeError::InvalidData) => return Err(DecodeError::InvalidData.into()),
            }
        }
        Ok(self.messages.len())
    }
    pub fn next_message(&mut self) -> Option<Message> {
        self.messages.pop_front()
    }
}
