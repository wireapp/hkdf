// Copyright (C) 2015 Wire Swiss GmbH <support@wire.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Implementation of RFC 5869
//!
//! [__HMAC-based Extract-and-Expand Key Derivation Function (HKDF)__][1]
//!
//! HKDF follows the "extract-then-expand" paradigm, where the KDF
//! logically consists of two modules.  The first stage takes the input
//! keying material and "extracts" from it a fixed-length pseudorandom
//! key K.  The second stage "expands" the key K into several additional
//! pseudorandom keys (the output of the KDF).
//!
//! [1]: https://tools.ietf.org/html/rfc5869

use sodiumoxide::crypto::auth::hmacsha256::{self, authenticate, State, Tag};
use sodiumoxide::utils;
use std::vec::Vec;

pub const HASH_LEN: usize = 32;

#[derive(Debug)]
pub struct Input<'r>(pub &'r [u8]);

#[derive(Debug)]
pub struct Salt<'r>(pub &'r [u8]);

#[derive(Debug)]
pub struct Info<'r>(pub &'r [u8]);

#[derive(Debug)]
pub struct Key(pub Vec<u8>);

impl Drop for Key {
    fn drop(&mut self) {
        utils::memzero(&mut self.0)
    }
}

/// Length of output keying material in octets (`<= 255 * HASH_LEN`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Len(u16);

impl Len {
    pub fn new(i: u16) -> Option<Len> {
        if i as usize > 255 * HASH_LEN {
            None
        } else {
            Some(Len(i))
        }
    }
}

/// HMAC-based KDF implementing RFC 5869.
/// Only SHA-256 is supported as hash function.
pub fn hkdf(salt: Salt, input: Input, info: Info, Len(len): Len) -> Key {
    Key(expand(extract(salt, input), info, len as usize))
}

// Step1: HKDF-Extract(salt, IKM) -> PRK
pub fn extract(Salt(s): Salt, Input(i): Input) -> Tag {
    let mut state = State::init(s);
    state.update(i);
    state.finalize()
}

// Step2: HKDF-Expand(PRK, info, L) -> OKM
pub fn expand(Tag(prk): Tag, Info(info): Info, len: usize) -> Vec<u8> {
    let n = (len as f32 / HASH_LEN as f32).ceil() as usize;
    let mut t = Vec::new();
    let mut okm = Vec::new();

    for i in 1..n + 1 {
        let mut buf = Vec::with_capacity(t.len() + info.len() + 1);
        buf.extend(&t);
        buf.extend(info);
        buf.push(i as u8);

        let t_i = authenticate(&buf, &hmacsha256::Key(prk));
        okm.extend(&t_i.0);

        t.clear();
        t.extend(&t_i.0);
    }

    okm.into_iter().take(len).collect()
}
