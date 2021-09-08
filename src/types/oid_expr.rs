use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};

use smallvec::SmallVec;

use crate::types::Identifier;

/// Root reference, OID fragment
#[derive(Clone, Debug, PartialEq)]
pub struct OidExpr {
    parent: Identifier,
    fragment: SmallVec<[u32; 1]>,
}

impl OidExpr {
    pub fn new<I, U>(parent: Identifier, fragment: I) -> Self
    where
        I: IntoIterator<Item = U>,
        U: Borrow<u32>,
    {
        Self {
            parent,
            fragment: fragment.into_iter().map(|u| *u.borrow()).collect(),
        }
    }

    pub fn parent(&self) -> &Identifier {
        &self.parent
    }

    pub fn fragment(&self) -> &[u32] {
        &self.fragment
    }
}

impl Display for OidExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(
            f,
            "{}",
            Some(&self.parent)
                .iter()
                .filter(|p| !p.is_root())
                .map(ToString::to_string)
                .chain(self.fragment.iter().map(ToString::to_string))
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}

/// Types that can be converted to [`OidExpr`].
///
/// `OidExpr` is the most general form of OID that `snmp-mib` currently supports, and other types,
/// such as [`Identifier`] and [`NumericOid`][crate::types::NumericOid], are infallibly and
/// losslessly convertible to it.  This trait allows all such types to be used in any API surface
/// that expects an OID expression.
pub trait IntoOidExpr {
    /// Convert `self` to an `OidExpr`. Must be lossless and panic-free.
    fn into_oid_expr(self) -> OidExpr;
}

impl IntoOidExpr for OidExpr {
    fn into_oid_expr(self) -> OidExpr {
        self
    }
}

impl<'a> IntoOidExpr for &'a OidExpr {
    fn into_oid_expr(self) -> OidExpr {
        self.clone()
    }
}
