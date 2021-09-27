// #![no_main]
// use libfuzzer_sys::fuzz_target;

// fuzz_target!(|data: &[u8]| {
//     if let Ok(s) = std::str::from_utf8(data) {
//         let mut loader = snmp_mib::loader::Loader::new();
//         if loader.load(&s).is_err() { return; }
//         let _: snmp_mib::mib::MIB = loader.into();
//     }
// });

fn main() {
    afl::fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            let mut loader = snmp_mib::loader::Loader::new();
            if loader.load(&s).is_err() { return; }
            let _: snmp_mib::mib::MIB = loader.into();
        }
    });
}
