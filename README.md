# Vivisect

A crate to perform static analysis. This is a port of the vivisect library written in python.
[See the original project.](https://github.com/vivisect/vivisect)

### Requirements
- Rust 1.60+ (2021 edition)

### Usage
```toml
[dependancies]
vivisect = { git = "https://github.com/marirs/vivisect-rs", branch = "master" }
```

### Example
```rust
use vivisect::workspace::VivWorkspace;

pub fn main() {
    let sample_path = "path_to_the_workspace";
    let mut workspace = VivWorkspace::new("", false);
    workspace.load_from_file(sample_path, None, None);
    workspace.analyze();
}
```

### Contribution

Feel free to make a pull request to update or fix any bug.

---
License: Apache 2.0