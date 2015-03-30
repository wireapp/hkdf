// This Source Code Form is subject to the terms of
// the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, You
// can obtain one at http://mozilla.org/MPL/2.0/.

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

#![feature(collections, core)]

extern crate sodiumoxide;

use sodiumoxide::crypto::auth::hmacsha256::{KEYBYTES};
use sodiumoxide::crypto::auth::hmacsha256::{Tag, Key, authenticate};
use sodiumoxide::crypto::hash::sha256::{Digest, hash};
use std::iter::range_inclusive;
use std::num::Float;
use std::slice::bytes::copy_memory;
use std::vec::Vec;

pub const HASH_LEN: usize = 32;

pub struct Input<'r>(pub &'r [u8]);

pub struct Salt<'r>(pub &'r [u8]);

pub struct Info<'r>(pub &'r [u8]);

/// Length of output keying material in octets (`<= 255 * HASH_LEN`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Len(u16);

impl Len {
    pub fn new(i: u16) -> Option<Len> {
        if i as usize > 255 * HASH_LEN { None } else { Some(Len(i)) }
    }
}

/// HMAC-based KDF implementing RFC 5869.
/// Only SHA-256 is supported as hash function.
pub fn hkdf(salt: Salt, input: Input, info: Info, Len(len): Len) -> Vec<u8> {
    expand(extract(salt, input), info, len as usize)
}

// Step1: HKDF-Extract(salt, IKM) -> PRK
fn extract(Salt(s): Salt, Input(i): Input) -> Tag {
    authenticate(i, &Key(mk_salt(s)))
}

// The salt is used as key for HMAC-Hash. It is either padded to the right
// with extra zeroes to the input block size of the hash function, or the
// hash of the original key if it's longer than that block size.
fn mk_salt(input: &[u8]) -> [u8; KEYBYTES] {
    if input.len() > KEYBYTES {
        let Digest(d) = hash(input);
        d
    } else {
        let mut b = [0; KEYBYTES];
        copy_memory(&mut b, input);
        b
    }
}

// Step2: HKDF-Expand(PRK, info, L) -> OKM
fn expand(Tag(prk): Tag, Info(info): Info, len: usize) -> Vec<u8> {
    let     n   = (len as f32 / HASH_LEN as f32).ceil() as usize;
    let mut t   = Vec::new();
    let mut okm = Vec::new();

    for i in range_inclusive(1, n) {
        let mut buf = Vec::with_capacity(t.len() + info.len() + 1);
        buf.push_all(&t);
        buf.push_all(info);
        buf.push(i as u8);

        let t_i = authenticate(&buf, &Key(prk));
        okm.push_all(&t_i.0);

        t.clear();
        t.push_all(&t_i.0);
    }

    okm.into_iter().take(len).collect()
}

// Tests ////////////////////////////////////////////////////////////////////

#[cfg(test)]
extern crate rustc_serialize;

#[test]
fn test_case_1() {
    use rustc_serialize::hex::FromHex;

    let ikm  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".from_hex().unwrap();
    let salt = "000102030405060708090a0b0c".from_hex().unwrap();
    let info = "f0f1f2f3f4f5f6f7f8f9".from_hex().unwrap();
    let len  = 42;

    let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5".from_hex().unwrap();
    let expected_okm = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865".from_hex().unwrap();

    let prk = extract(Salt(&salt), Input(&ikm));
    let okm = expand(prk, Info(&info), len);

    assert_eq!(&expected_prk, &prk.0);
    assert_eq!(&expected_okm, &okm);
}

#[test]
fn test_case_2() {
    use rustc_serialize::hex::FromHex;

    let ikm  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".from_hex().unwrap();
    let salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".from_hex().unwrap();
    let info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".from_hex().unwrap();
    let len  = 82;

    let expected_prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244".from_hex().unwrap();
    let expected_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".from_hex().unwrap();

    let prk = extract(Salt(&salt), Input(&ikm));
    let okm = expand(prk, Info(&info), len);

    assert_eq!(&expected_prk, &prk.0);
    assert_eq!(&expected_okm, &okm);
}

#[test]
fn test_case_3() {
    use rustc_serialize::hex::FromHex;

    let ikm  = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b".from_hex().unwrap();
    let salt = b"";
    let info = b"";
    let len  = 42;

    let expected_prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04".from_hex().unwrap();
    let expected_okm = "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8".from_hex().unwrap();

    let prk = extract(Salt(salt), Input(&ikm));
    let okm = expand(prk, Info(info), len);

    assert_eq!(&expected_prk, &prk.0);
    assert_eq!(&expected_okm, &okm);
}
