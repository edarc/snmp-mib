use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};

use smallvec::SmallVec;

use crate::types::{Identifier, IntoIdentifier};

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

/// A trait for types that can be converted to OidExpr.
pub trait IntoOidExpr {
    fn into_oid_expr(self) -> Option<OidExpr>;
}

impl<P: IntoIdentifier, F: AsRef<[u32]>> IntoOidExpr for (P, F) {
    fn into_oid_expr(self) -> Option<OidExpr> {
        Some(OidExpr {
            parent: self.0.into_identifier(),
            fragment: self.1.as_ref().into(),
        })
    }
}

impl IntoOidExpr for &str {
    fn into_oid_expr(self) -> Option<OidExpr> {
        let split = self.split(".").collect::<Vec<_>>();
        let mut fragments = split
            .iter()
            .rev()
            .map(|f| f.parse::<u32>())
            .take_while(|r| r.is_ok())
            .map(|r| r.unwrap())
            .collect::<Vec<_>>();
        fragments.reverse();
        match (fragments.len(), split.len()) {
            (f, s) if f == s => Some(OidExpr {
                parent: Identifier::root(),
                fragment: fragments.into(),
            }),
            (f, s) if f == s - 1 => Some(OidExpr {
                parent: split[0].into_identifier(),
                fragment: fragments.into(),
            }),
            _ => None,
        }
    }
}

impl IntoOidExpr for NumericOid {
    fn into_oid_expr(self) -> Option<OidExpr> {
        (&self).into_oid_expr()
    }
}

impl<'a> IntoOidExpr for &'a NumericOid {
    fn into_oid_expr(self) -> Option<OidExpr> {
        ("", self).into_oid_expr()
    }
}

impl IntoOidExpr for OidExpr {
    fn into_oid_expr(self) -> Option<OidExpr> {
        Some(self)
    }
}

impl<'a> IntoOidExpr for &'a OidExpr {
    fn into_oid_expr(self) -> Option<OidExpr> {
        Some(self.clone())
    }
}
