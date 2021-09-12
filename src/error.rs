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
