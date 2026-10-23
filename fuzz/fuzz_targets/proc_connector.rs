#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| warden_fuzz::proc_connector(data));
