# SNMP MIB

A Rust implementation of the SNMP Management Information Base, for use
alongside an SNMP protocol implementation.

**Work in progress**

## Description

`snmp-mib` can be used to load and compile MIB module definitions, allowing you
to look up interpretations of SNMP objects and variable bindings such as
counter/gauge/etc semantics or units of measure, look up and convert between
numeric OIDs and names, and decode and organize collections of tabular bindings
into indexed SNMP tables according to the loaded MIB module schemata.

This is *not* intended to be an implementation of the SNMP protocol, but rather
to be used along side existing Rust SNMP protocol implementations in order to
navigate and interpret the objects the SNMP client is interacting with.

## License

Licensed under either of

- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
