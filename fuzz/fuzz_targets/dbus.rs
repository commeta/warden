#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| warden_fuzz::dbus_message(data));
