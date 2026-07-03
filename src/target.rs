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

//! Target platform information (endianness, pointer width, triple).

use crate::{Endianness, Triple};

/// Platform endianness. Returns `None` on older Rust versions.
pub fn endian() -> Option<Endianness> {
    let raw = std::env::var("CARGO_CFG_TARGET_ENDIAN").ok()?;
    Some(raw.parse().expect("CARGO_CFG_TARGET_ENDIAN is not valid"))
}

/// Width (in bits) of a pointer on this platform.
/// Returns `None` on older Rust versions.
pub fn pointer_width() -> Option<u8> {
    let raw = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH").ok()?;
    Some(raw.parse().expect("CARGO_CFG_TARGET_POINTER_WIDTH is not valid"))
}

/// Platform triple (e.g. `x86_64-unknown-linux-gnu`).
pub fn triple() -> Triple {
    let raw = std::env::var("TARGET").expect("TARGET env var is not set");
    Triple::new(raw)
}

/// Target operating system (e.g. `linux`, `windows`, `darwin`).
pub fn os() -> String {
    std::env::var("CARGO_CFG_TARGET_OS").expect("CARGO_CFG_TARGET_OS env var is not set")
}

/// Target processor architecture (e.g. `x86_64`, `aarch64`, `arm`).
pub fn arch() -> String {
    std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH env var is not set")
}

/// Target ABI environment (e.g. `gnu`, `msvc`, `musl`).
/// Returns `None` on platforms where this is not defined (e.g. some bare-metal targets).
pub fn target_env() -> Option<String> {
    std::env::var("CARGO_CFG_TARGET_ENV").ok()
}

/// Target family (e.g. `unix`, `windows`).
/// Returns `None` on platforms where this is not defined.
pub fn target_family() -> Option<String> {
    std::env::var("CARGO_CFG_TARGET_FAMILY").ok()
}
