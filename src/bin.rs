// Copyright (c) 2022-2026 Sprite Tong (<spritetong@gmail.com>)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! Toolchain binary locations (`cargo`, `rustc`, `rustdoc`).

use std::env;
use std::path::PathBuf;

/// Path to the `cargo` binary.
pub fn cargo() -> PathBuf {
    env::var_os("CARGO")
        .map(Into::into)
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

/// Path to `rustc` as selected by Cargo.
pub fn rustc() -> PathBuf {
    env::var_os("RUSTC")
        .expect("RUSTC env var is not set")
        .into()
}

/// Path to `rustdoc` as selected by Cargo.
pub fn rustdoc() -> PathBuf {
    env::var_os("RUSTDOC")
        .expect("RUSTDOC env var is not set")
        .into()
}
