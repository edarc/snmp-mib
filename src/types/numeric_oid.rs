use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::iter::FromIterator;
use std::ops::Deref;
use std::slice::Iter;

use crate::types::{IntoOidExpr, OidExpr};

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

    /// Index this OID by an integer.
    ///
    /// Indexing an OID simply means finding some child OID by creating a new OID with path
    /// elements appended. SMI specifies several ways of indexing; integer is the simplest.
    ///
    /// ```
    /// # use snmp_mib::types::NumericOid;
    /// let parent = NumericOid::new([1, 2, 3, 4]);
    /// let child_fourteen = parent.index_by_integer(14);
    /// assert_eq!(format!("{}", child_fourteen), "1.2.3.4.14");
    /// ````
    // TODO: Move this to a FragmentIndex trait.
    pub fn index_by_integer(&self, fragment: u32) -> Self {
        self.index_by_fragment(&[fragment])
    }

    /// Index this OID by an OID fragment.
    ///
    /// Indexing an OID simply means finding some child OID by creating a new OID with path
    /// elements appended. "Fragment" refers, in `snmp-mib`, to a piece of a numeric OID which is
    /// relative to some parent. Indexing an OID by a fragment simply returns a new OID which is
    /// the concatenation of the parent OID and the fragment.
    ///
    /// For this method, the fragment can be any iterable of `u32`.
    ///
    /// ```
    /// # use snmp_mib::types::NumericOid;
    /// let parent = NumericOid::new([1, 2, 3]);
    /// let fragment = vec![10, 20, 30];
    /// let indexed = parent.index_by_fragment(fragment);
    /// assert_eq!(format!("{}", indexed), "1.2.3.10.20.30");
    /// ```
    // TODO: Move this to a FragmentIndex trait.
    pub fn index_by_fragment<I, U>(&self, fragment: I) -> Self
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

fn dotted_oid(numeric_oid: impl AsRef<[u32]>) -> String {
    numeric_oid
        .as_ref()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}
