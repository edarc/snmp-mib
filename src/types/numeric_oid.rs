use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::iter::FromIterator;
use std::ops::Deref;
use std::slice::Iter;

use crate::types::{Indexable, IntoOidExpr, OidExpr};

/// A numeric object identifier.
///
/// Object identifiers are sequences of integers, typically written as decimal values with dot
/// separators, that are compact representations for paths in the MIB's tree of objects.
///
/// * `NumericOid` is convertible to [`OidExpr`], and usable in API surfaces that accept `impl
///   IntoOidExpr`, as it directly implements [`IntoOidExpr`].
/// * `NumericOid` can be `Deref`ed as a `&[u32]` to access or iterate over the path elements.
/// * `NumericOid` is convertible to an iterator of `u32` or `&u32` via [`IntoIterator`] impls.
/// * `NumericOid` is constructible from iterators of `u32` or `&u32` using [`Iterator::collect`]
///   via [`FromIterator`] impls.
/// * The `Display` and `Debug` impls print the `NumericOid` in the customary dotted format.
///
/// ```
/// # use snmp_mib::types::{NumericOid,IntoOidExpr};
/// // Conversion to OidExpr
/// let oid_expr = NumericOid::new([1, 3, 6]).into_oid_expr().unwrap();
/// assert_eq!(oid_expr.parent().is_root(), true);
/// assert_eq!(oid_expr.fragment(), [1, 3, 6]);
///
/// // Deref as &[u32]
/// let oid = NumericOid::new([1, 3, 7]);
/// let slice = &oid[1..];
/// assert_eq!(slice, &[3, 7]);
///
/// // IntoIterator
/// let filt = NumericOid::new([1, 9, 4])
///     .into_iter()
///     .filter(|&v| v > 2)
///     .collect::<Vec<_>>();
/// assert_eq!(filt, vec![9, 4]);
///
/// // FromIterator
/// let from_iter = std::iter::repeat(4).take(5).collect::<NumericOid>();
/// assert_eq!(format!("{}", from_iter), "4.4.4.4.4");
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct NumericOid(Vec<u32>);

impl NumericOid {
    /// Construct a `NumericOid` from a slice of `u32`.
    ///
    /// ```
    /// # use snmp_mib::types::NumericOid;
    /// let oid_from_array = NumericOid::new([1, 3, 6, 1, 4, 1]);
    /// assert_eq!(format!("{}", oid_from_array), "1.3.6.1.4.1");
    ///
    /// let a_vec = vec![1, 3, 6, 1, 4, 2];
    /// let oid_from_slice = NumericOid::new(&a_vec);
    /// assert_eq!(format!("{}", oid_from_slice), "1.3.6.1.4.2");
    /// ```
    pub fn new(path: impl AsRef<[u32]>) -> Self {
        NumericOid(path.as_ref().to_vec())
    }

    /// Return the parent numeric OID of `self`.
    ///
    /// This is equivalent to creating a numeric OID that contains every path element in `self`
    /// except the last.
    ///
    /// ```
    /// # use snmp_mib::types::NumericOid;
    /// let oid = NumericOid::new([1, 3, 6, 1, 4, 1]);
    /// let parent = oid.parent();
    /// assert_eq!(format!("{}", parent), "1.3.6.1.4");
    /// ```
    pub fn parent(&self) -> Self {
        self.0[..(self.0.len() - 1)].iter().collect()
    }
}

impl Deref for NumericOid {
    type Target = [u32];
    fn deref(&self) -> &[u32] {
        &self.0
    }
}

impl AsRef<[u32]> for NumericOid {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl IntoIterator for NumericOid {
    type Item = u32;
    type IntoIter = <Vec<u32> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a NumericOid {
    type Item = &'a u32;
    type IntoIter = Iter<'a, u32>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl FromIterator<u32> for NumericOid {
    fn from_iter<T: IntoIterator<Item = u32>>(iter: T) -> Self {
        NumericOid(iter.into_iter().collect())
    }
}

impl<'a> FromIterator<&'a u32> for NumericOid {
    fn from_iter<T: IntoIterator<Item = &'a u32>>(iter: T) -> Self {
        NumericOid(iter.into_iter().copied().collect())
    }
}

impl From<Vec<u32>> for NumericOid {
    fn from(v: Vec<u32>) -> Self {
        NumericOid(v)
    }
}

impl From<&[u32]> for NumericOid {
    fn from(v: &[u32]) -> Self {
        NumericOid(v.to_vec())
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

impl Display for NumericOid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}", dotted_oid(self))
    }
}

impl Debug for NumericOid {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, r"NumericOid({})", self)
    }
}

impl Indexable for NumericOid {
    type Output = NumericOid;

    fn index_by_fragment<I, U>(&self, fragment: I) -> Self::Output
    where
        I: IntoIterator<Item = U>,
        U: Borrow<u32>,
    {
        self.0
            .iter()
            .copied()
            .chain(fragment.into_iter().map(|u| *u.borrow()))
            .collect()
    }
}

fn dotted_oid(numeric_oid: impl AsRef<[u32]>) -> String {
    numeric_oid
        .as_ref()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
