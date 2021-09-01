use std::collections::HashMap;

use lazy_static::lazy_static;

#[derive(Clone, Debug, Copy)]
pub enum SMIWellKnown {
    Counter,
    Counter32,
    Counter64,
    DisplayString,
    Gauge,
    Gauge32,
    Integer32,
    IpAddress,
    Opaque,
    TimeTicks,
    Unsigned32,
    Bits,
    InetAddress,
}

lazy_static! {
    pub static ref SMI_WELL_KNOWN_TYPES: HashMap<&'static str, SMIWellKnown> = [
        // RFCs 1155, 2578
        ("Counter", SMIWellKnown::Counter),
        ("Counter32", SMIWellKnown::Counter32),
        ("Counter64", SMIWellKnown::Counter64),
        ("DisplayString", SMIWellKnown::DisplayString),
        ("Gauge", SMIWellKnown::Gauge),
        ("Gauge32", SMIWellKnown::Gauge32),
        ("Integer32", SMIWellKnown::Integer32),
        ("IpAddress", SMIWellKnown::IpAddress),
        ("Opaque", SMIWellKnown::Opaque),
        ("TimeTicks", SMIWellKnown::TimeTicks),
        ("Unsigned32", SMIWellKnown::Unsigned32),
        // RFC 2578
        ("BITS", SMIWellKnown::Bits),
        // RFC 3291
        ("InetAddress", SMIWellKnown::InetAddress),
    ]
    .iter()
    .cloned()
    .collect();
}
