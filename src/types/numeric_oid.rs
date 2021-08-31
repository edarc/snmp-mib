use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};
use std::iter::FromIterator;
use std::ops::Deref;
use std::slice::Iter;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct NumericOid(Vec<u32>);

impl NumericOid {
    pub fn new(path: impl AsRef<[u32]>) -> Self {
        NumericOid(path.as_ref().to_vec())
    }

    pub fn parent(&self) -> Self {
        self.0[..(self.0.len() - 1)].iter().collect()
    }

    pub fn index_by_integer(&self, fragment: u32) -> Self {
        self.index_by_fragment(&[fragment])
    }

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
