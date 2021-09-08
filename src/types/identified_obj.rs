use std::fmt::{Debug, Error as FmtError, Formatter};
use std::ops::Deref;

use crate::types::{Identifier, NumericOid};

/// The identifier and numeric OID of an object that is specifically defined in the MIB.
///
/// This type pairs an identifier and its defined numeric OID, and is used in a variety of return
/// values in the `snmp-mib` API where specifically identified objects are referenced.
///
/// * `IdentifiedObj` is usable in API surfaces that accept a `NumericOid`, as it can be `Deref`ed
///   as [`NumericOid`].
/// * `IdentifiedObj` is usable in API surfaces that accept an `impl IntoOidExpr`, as it can be
///   `Deref`ed as `NumericOid` which in turn implements
///   [`IntoOidExpr`][crate::types::IntoOidExpr].
///
/// Note that `IdentifiedObj` is not user-constructible; the `snmp-mib` crate returns them from
/// APIs only to maintain the invariant that for any extant `IdentifiedObj`, the identifier and
/// numeric OID contained are actually equivalent as defined by the MIB.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct IdentifiedObj(pub(super) NumericOid, pub(super) Identifier);

impl IdentifiedObj {
    pub(crate) fn new(numeric_oid: NumericOid, name: Identifier) -> Self {
        IdentifiedObj(numeric_oid, name)
    }

    /// Use this `IdentifiedObj` as an `Identifier`.
    pub fn identifier(&self) -> &Identifier {
        &self.1
    }
}

impl Debug for IdentifiedObj {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, r#"IdentifiedObj("{}" = {})"#, self.1, self.0)
    }
}

impl Deref for IdentifiedObj {
    type Target = NumericOid;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
