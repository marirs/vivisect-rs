pub trait MemoryCanvas {
    fn add_text(&self, text: String, tag: Option<String>);
}