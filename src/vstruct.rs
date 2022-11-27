pub trait VStruct {
    fn get_vs_fields(&self) -> Vec<i32>;

    fn vs_parse(&self, _sbytes: Vec<u8>, offset: i32, _fast: bool) -> i32 {
        offset
    }
}
