use hkdf::*;
use rustc_serialize::hex::FromHex;

use serde::{self, Deserialize, Serialize};
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;

#[test]
fn test_case_1() {
    let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        .from_hex()
        .unwrap();
    let salt = "000102030405060708090a0b0c".from_hex().unwrap();
    let info = "f0f1f2f3f4f5f6f7f8f9".from_hex().unwrap();
    let len = 42;

    let expected_prk = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        .from_hex()
        .unwrap();
    let expected_okm =
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            .from_hex()
            .unwrap();

    let prk = extract(Salt(&salt), Input(&ikm));
    let okm = expand(prk, Info(&info), len);

    assert_eq!(&expected_prk, &prk.0);
    assert_eq!(&expected_okm, &okm);
}

#[test]
fn test_case_2() {
    let ikm  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f".from_hex().unwrap();
    let salt = "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf".from_hex().unwrap();
    let info = "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".from_hex().unwrap();
    let len = 82;

    let expected_prk = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        .from_hex()
        .unwrap();
    let expected_okm = "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87".from_hex().unwrap();

    let prk = extract(Salt(&salt), Input(&ikm));
    let okm = expand(prk, Info(&info), len);

    assert_eq!(&expected_prk, &prk.0);
    assert_eq!(&expected_okm, &okm);
}

#[test]
fn test_case_3() {
    let ikm = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
        .from_hex()
        .unwrap();
    let salt = b"";
    let info = b"";
    let len = 42;

    let expected_prk = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        .from_hex()
        .unwrap();
    let expected_okm =
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
            .from_hex()
            .unwrap();

    let prk = extract(Salt(salt), Input(&ikm));
    let okm = expand(prk, Info(info), len);

    assert_eq!(&expected_prk, &prk.0);
    assert_eq!(&expected_okm, &okm);
}

#[allow(non_snake_case)]
#[test]
fn test_wycheproof() {
    // Defining the test vector.
    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct Test {
        tcId: usize,
        comment: String,
        ikm: String,
        salt: String,
        info: String,
        size: usize,
        okm: String,
        result: String,
        flags: Vec<String>,
    }
    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct TestGroup {
        keySize: usize,
        r#type: String,
        tests: Vec<Test>,
    }
    #[derive(Serialize, Deserialize, Debug, Clone)]
    struct TestVector {
        algorithm: String,
        generatorVersion: String,
        numberOfTests: usize,
        header: Vec<Value>,   // not used
        notes: Option<Value>, // text notes (might not be present), keys correspond to flags
        schema: String,
        testGroups: Vec<TestGroup>,
    }

    // Read JSON file.
    let file = "tests/hkdf_sha256_test.json";
    let file = match File::open(file) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file),
    };
    let reader = BufReader::new(file);
    let tests: TestVector = match serde_json::from_reader(reader) {
        Ok(r) => r,
        Err(e) => {
            println!("{:?}", e);
            panic!("Error reading file.")
        }
    };

    // Run all tests
    let num_tests = tests.numberOfTests;
    let mut skipped_tests = 0;
    let mut tests_run = 0;
    match tests.algorithm.as_ref() {
        "HKDF-SHA-256" => (),
        _ => panic!("This is not an HKDF-SHA-256 test vector."),
    };
    for testGroup in tests.testGroups.iter() {
        assert_eq!(testGroup.r#type, "HkdfTest");
        for test in testGroup.tests.iter() {
            let valid = test.result.eq("valid");
            if test.comment == "invalid output size" {
                // This panicks.
                skipped_tests += 1;
                continue;
            }
            println!("Test {:?}: {:?}", test.tcId, test.comment);

            let ikm = test.ikm.from_hex().unwrap();
            let salt = test.salt.from_hex().unwrap();
            let info = test.info.from_hex().unwrap();
            let len = test.size;
            let expected_okm = Key(test.okm.from_hex().unwrap());

            let okm = hkdf(
                Salt(&salt),
                Input(&ikm),
                Info(&info),
                Len::new(len as u16).unwrap(),
            );

            if valid {
                assert_eq!(&expected_okm.0, &okm.0);
            } else {
                assert_ne!(&expected_okm.0, &okm.0);
            }
            tests_run += 1;
        }
    }
    // Check that we ran all tests.
    println!(
        "Ran {} out of {} tests and skipped {}.",
        tests_run, num_tests, skipped_tests
    );
    assert_eq!(num_tests - skipped_tests, tests_run);
}

#[test]
fn test_case_special() {
    let ikm = "a319ff7b5ba9b14ac72b681cecf0f742".from_hex().unwrap();
    let salt = "d7e3bc6daed343ce77ef793e15a8246e4bfcbaf83d2ac956d0661d1df7262b2e7311623dfe4152caddbfda8fa8ed7a82656ec00b72c5adf7c9d388e5b3bc8d24".from_hex().unwrap();
    let info = "".from_hex().unwrap();
    let len = 42;

    let expected_okm =
        "31e7b971f165eb923b499460c94937477fd61cc4e96c27fa2abb552accceef42aa3a35637bce32d996e9"
            .from_hex()
            .unwrap();

    let prk = extract(Salt(&salt), Input(&ikm));
    let okm = expand(prk, Info(&info), len);

    assert_eq!(&expected_okm, &okm);
}
