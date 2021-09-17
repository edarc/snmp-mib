//! The error types emitted by this crate.

use std::num::ParseIntError;

use thiserror::Error;

use crate::mib::{SMIInterpretation, SMIScalar};
use crate::types::{IdentifiedObj, Identifier, NumericOid};

/// A failure to parse an [`OidExpr`][crate::types::OidExpr].
#[derive(Error, Debug, PartialEq, Eq)]
#[error("Can't parse OID expression")]
pub struct ParseOidExprError {
    #[from]
    source: ParseIntError,
}

/// A failure to parse a [`NumericOid`][crate::types::NumericOid].
#[derive(Error, Debug, PartialEq, Eq)]
#[error("Can't parse numeric OID")]
pub struct ParseNumericOidError {
    #[from]
    source: ParseIntError,
}

/// A failure to load a MIB from a file.
#[derive(Error, Debug)]
pub enum LoadFileError {
    /// An I/O error occurred trying to load the contents of the MIB file.
    #[error("I/O error reading MIB file")]
    IOError {
        #[from]
        source: std::io::Error,
    },
    /// The MIB file was not valid UTF-8.
    #[error("UTF-8 decoding error loading MIB file")]
    Utf8Error {
        #[from]
        source: std::string::FromUtf8Error,
    },
    /// The MIB file was not syntactically valid, or contained ASN.1 syntax that `snmp-mib` does
    /// not (yet) support.
    #[error("Parse error while loading MIB file")]
    ParseError {
        source: nom::Err<nom::error::Error<String>>,
    },
}

mod load_file_error {
    use nom::error::Error as NError;
    use nom::Err as NErr;

    use super::LoadFileError;

    impl<'a> From<NErr<NError<&'a str>>> for LoadFileError {
        fn from(e: NErr<NError<&'a str>>) -> Self {
            Self::ParseError {
                source: match e {
                    NErr::Incomplete(needed) => NErr::Incomplete(needed),
                    NErr::Error(NError { input, code }) => NErr::Error(NError {
                        input: input.to_string(),
                        code,
                    }),
                    NErr::Failure(NError { input, code }) => NErr::Failure(NError {
                        input: input.to_string(),
                        code,
                    }),
                },
            }
        }
    }
}

/// A failure to look up some object in the MIB.
#[derive(Error, Debug, Clone)]
pub enum LookupError {
    /// An identifier was referenced in an OID definition which was not defined in any other loaded
    /// module. Anything defined (directly or transitively) in terms of that identifier will be
    /// dropped from the MIB.
    #[error("Can't resolve identifier `{identifier}` referenced in OID definition")]
    OrphanIdentifier { identifier: Identifier },

    /// A numeric OID was not defined by any modules loaded into the MIB.
    #[error("No such numeric OID defined in the MIB: {oid}")]
    NoSuchNumericOID { oid: NumericOid },

    /// An identifier was not defined by any modules loaded into the MIB.
    #[error("No such identifier defined in the MIB: `{identifier}`")]
    NoSuchIdentifier { identifier: Identifier },

    /// An object which refers to an SMI table cell had an index field that could not be decoded.
    #[error("Table cell index field can't be decoded")]
    IndexNotDecodable {
        object: IdentifiedObj,
        source: IndexDecodeError,
    },
}

/// A failure to decode an index value from an OID fragment.
#[derive(Error, Debug, Clone)]
pub enum IndexDecodeError {
    /// An SMI table is malformed due to a column mentioned in its `INDEX` (or the `INDEX` of the
    /// table referenced by `AUGMENTS`) having a non-scalar SMI interpretation. Such columns are
    /// not encodable as an OID fragment.
    #[error("Index field is non-scalar: {interpretation:?}")]
    NonScalarType { interpretation: SMIInterpretation },

    /// An SMI table is malformed due to a column mentioned in its `INDEX` (or the `INDEX` of the
    /// table referenced by `AUGMENTS`) having a scalar type which doesn't have a encoding as a
    /// numeric OID fragment. This is either a bad MIB module definition or a bug.
    #[error("Index field has type with no defined index encoding: {scalar_type:?}")]
    UnsupportedScalarType { scalar_type: SMIScalar },

    /// The OID contained an InetAddress whose address family (v4 or v6) could not be determined.
    #[error("Internet address index value has unrecognized address family ({len} octets)")]
    UnrecognizedInetAddrFamily { len: usize },

    /// The index was an enum but the encoded value does not match any of the variants.
    #[error("Unknown enumeration variant {val}")]
    UnknownEnumVariant { val: u32 },

    /// An index's value was incomplete, i.e. the remaining OID fragment was shorter than expected.
    /// This error does not occur if the index's value is completely omitted, only if there were
    /// *some* elements in the OID fragment but not enough to correctly decode the value.
    #[error("Incomplete index value, expected {expect_len} got {got_len} OID elements")]
    IncompleteValue { expect_len: usize, got_len: usize },

    /// An index which expected only octet-range (0..256) values got a value outside that range.
    #[error("Index expected octet encoding, got out-of-range element {val}")]
    InvalidOctet { val: u32 },
}
