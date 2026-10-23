#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| warden_fuzz::auth_log(data));
