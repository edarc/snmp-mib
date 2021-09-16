//! The error types emitted by this crate.

use std::num::ParseIntError;

use thiserror::Error;

use crate::mib::SMIInterpretation;
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

    /// An SMI table is malformed due to a column mentioned in its `INDEX` (or the `INDEX` of the
    /// table referenced by `AUGMENTS`) having a non-scalar SMI interpretation. Such columns are
    /// not encodable as an OID fragment.
    #[error("Malformed SMI table: index field {object:?} is non-scalar: {interpretation:?}")]
    NonScalarTableIndex {
        object: IdentifiedObj,
        interpretation: SMIInterpretation,
    },
}
