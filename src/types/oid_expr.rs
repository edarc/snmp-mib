use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::str::FromStr;

use smallvec::SmallVec;

use crate::types::{Identifier, Indexable};

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

impl FromStr for OidExpr {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split = s.split(".").collect::<Vec<_>>();
        let mut fragments = split
            .iter()
            .rev()
            .map(|f| f.parse::<u32>())
            .take_while(|r| r.is_ok())
            .map(|r| r.unwrap())
            .collect::<Vec<_>>();
        fragments.reverse();
        match (fragments.len(), split.len()) {
            (f, s) if f == s => Ok(Identifier::root().index_by_fragment(fragments)),
            (f, s) if f == s - 1 => Ok(split[0]
                .parse::<Identifier>()
                .unwrap()
                .index_by_fragment(fragments)),
            _ => Err(()),
        }
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

impl Indexable for OidExpr {
    type Output = OidExpr;

    fn index_by_fragment<I, U>(&self, fragment: I) -> Self::Output
    where
        I: IntoIterator<Item = U>,
        U: Borrow<u32>,
    {
        let additional_fragment = fragment.into_iter().map(|u| *u.borrow());
        OidExpr::new(
            self.parent.clone(),
            self.fragment.iter().copied().chain(additional_fragment),
        )
    }
}
