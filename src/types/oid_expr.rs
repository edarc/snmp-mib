use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::str::FromStr;

use smallvec::SmallVec;

use crate::types::{Identifier, Indexable};

/// An OID expression consisting of a base identifier with an appended numeric fragment.
///
/// This permits the expression of OIDs that are descendants of named objects, but which may or may
/// not themselves have names. Examples of this can be OIDs that are table cells, where the column
/// OID has a name, but individual cells are defined by dyanmic indices.
///
/// There are a number of ways to write expressions to refer to OIDs that `OidExpr` does not
/// support, for example `OidExpr` does not allow identifiers to appear anywhere except at the
/// beginning of the expression.
#[derive(Clone, Debug, PartialEq)]
pub struct OidExpr {
    base: Identifier,
    fragment: SmallVec<[u32; 1]>,
}

impl OidExpr {
    /// Construct an OID expression from an [`Identifier`] and an OID fragment.
    ///
    /// ```
    /// # use snmp_mib::types::{OidExpr, Identifier};
    /// let expr = OidExpr::new(Identifier::new("MY-MODULE", "myObj"), [4, 3]);
    /// assert_eq!(format!("{}", expr), "MY-MODULE::myObj.4.3");
    /// ```
    pub fn new<I, U>(base: Identifier, fragment: I) -> Self
    where
        I: IntoIterator<Item = U>,
        U: Borrow<u32>,
    {
        Self {
            base,
            fragment: fragment.into_iter().map(|u| *u.borrow()).collect(),
        }
    }

    /// Get the base [`Identifier`] from this OID expression.
    ///
    /// ```
    /// # use snmp_mib::types::{OidExpr, Identifier};
    /// let ident = Identifier::new("MY-MODULE", "myObj");
    /// let expr = OidExpr::new(ident.clone(), [4, 3]);
    /// assert_eq!(expr.base_identifier(), &ident);
    /// ```
    pub fn base_identifier(&self) -> &Identifier {
        &self.base
    }

    /// Get the numeric OID fragment from this OID expression.
    ///
    /// ```
    /// # use snmp_mib::types::{OidExpr, Identifier};
    /// let frag = [4, 3];
    /// let expr = OidExpr::new(Identifier::new("MY-MODULE", "myObj"), &frag);
    /// assert_eq!(expr.fragment(), &frag);
    /// ```
    pub fn fragment(&self) -> &[u32] {
        &self.fragment
    }
}

impl Display for OidExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(
            f,
            "{}",
            Some(&self.base)
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
            self.base.clone(),
            self.fragment.iter().copied().chain(additional_fragment),
        )
    }
}
