//! Panic sweep for libinjectionrs.
//!
//! The crate denies unwrap/expect/panic by lint but keeps 229 direct
//! slice-indexing sites, which its README names as the residual risk. A panic
//! in a WAF's inspection path on attacker-controlled input is a denial of
//! service, so this hammers both entry points with the input shapes a WAF
//! actually receives, including the NUL bytes the upstream differential fuzz
//! target skips.
use std::panic::{catch_unwind, AssertUnwindSafe};

fn main() {
    let mut rng: u64 = 0x243F6A8885A308D3;
    let mut next = move || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };

    // Bytes that matter to a SQL or HTML tokenizer, plus NUL and high bytes.
    let alphabet: Vec<u8> = b"\0\x01\x09\x0a\x0b\x0c\x0d '\"`\\/*-+=<>()[]{};:,.!?#%&|^~$@0123456789abcdefABCDEFxXuUselctSELECTunioUNION<script>onerror"
        .iter()
        .copied()
        .chain([0x7f, 0x80, 0xc0, 0xfe, 0xff])
        .collect();

    let seeds: Vec<&[u8]> = vec![
        b"", b"\0", b"'", b"\"", b"`", b"\\", b"/*", b"--", b"#", b"0x", b"%", b"%u",
        b"1' OR '1'='1", b"<script>alert(1)</script>", b"<img src=x onerror=alert(1)>",
        b"1 into outfile 'a'", b"\0'\0OR\0'1'='1", b"<a href=\0javascript:alert(1)>",
        b"' UNION SELECT NULL,NULL--", b"<!--", b"<![CDATA[", b"</", b"<>",
    ];

    let mut cases = 0usize;
    let mut panics: Vec<(String, Vec<u8>)> = Vec::new();

    let mut run = |input: &[u8], cases: &mut usize, panics: &mut Vec<(String, Vec<u8>)>| {
        *cases += 1;
        let owned = input.to_vec();
        let a = catch_unwind(AssertUnwindSafe(|| {
            libinjectionrs::detect_sqli(&owned).is_injection()
        }));
        if a.is_err() && panics.len() < 20 {
            panics.push(("detect_sqli".into(), owned.clone()));
        }
        let b = catch_unwind(AssertUnwindSafe(|| {
            libinjectionrs::detect_xss(&owned).is_injection()
        }));
        if b.is_err() && panics.len() < 20 {
            panics.push(("detect_xss".into(), owned));
        }
    };

    // Seeds, and every single-byte and two-byte value.
    for s in &seeds {
        run(s, &mut cases, &mut panics);
    }
    for a in 0u16..=255 {
        run(&[a as u8], &mut cases, &mut panics);
        for b in 0u16..=255 {
            run(&[a as u8, b as u8], &mut cases, &mut panics);
        }
    }

    // Random strings over the tokenizer-relevant alphabet, all lengths to 64.
    for _ in 0..300_000 {
        let len = (next() % 64) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            buf.push(alphabet[(next() as usize) % alphabet.len()]);
        }
        run(&buf, &mut cases, &mut panics);
    }

    // Mutations of the seeds: splice, truncate, repeat.
    for _ in 0..100_000 {
        let seed = seeds[(next() as usize) % seeds.len()];
        let mut buf = seed.to_vec();
        for _ in 0..(next() % 4) {
            match next() % 4 {
                0 => buf.push(alphabet[(next() as usize) % alphabet.len()]),
                1 => {
                    if !buf.is_empty() {
                        let at = (next() as usize) % buf.len();
                        buf.remove(at);
                    }
                }
                2 => {
                    if !buf.is_empty() {
                        let at = (next() as usize) % buf.len();
                        buf[at] = alphabet[(next() as usize) % alphabet.len()];
                    }
                }
                _ => buf.extend_from_slice(seed),
            }
        }
        run(&buf, &mut cases, &mut panics);
    }

    // Long and pathological inputs.
    for pattern in [&b"'"[..], b"/*", b"--", b"0x", b"<", b"\0", b"("] {
        for reps in [500usize, 5_000, 50_000] {
            let buf: Vec<u8> = pattern.iter().cycle().take(reps).copied().collect();
            run(&buf, &mut cases, &mut panics);
        }
    }

    println!("inputs exercised : {cases} (x2 entry points)");
    println!("panics           : {}", panics.len());
    for (which, input) in &panics {
        println!("  {which} panicked on {:?}", String::from_utf8_lossy(input));
    }
    if !panics.is_empty() {
        std::process::exit(1);
    }
}
