pub struct ParserContext {
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl ParserContext {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            src_port: None,
            dst_port: None
        })
    }
}