//! The error types emitted by this crate.

use std::num::ParseIntError;

use thiserror::Error;

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
