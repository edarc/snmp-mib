use std::borrow::Borrow;

/// OID types that can be indexed.
///
/// Indexing an OID simply means finding some child OID by creating a new OID with path elements
/// appended. SMI specifies several ways of indexing; `Indexable` supplies default implementations
/// of all of them based on `index_by_fragment`, the only required method.
pub trait Indexable {
    type Output;

    /// Index this OID by an OID fragment.
    ///
    /// Indexing an OID simply means finding some child OID by creating a new OID with path
    /// elements appended. "Fragment" refers, in `snmp-mib`, to a piece of a numeric OID which is
    /// relative to some parent. Indexing an OID by a fragment simply returns a new OID which is
    /// the concatenation of the parent OID and the fragment.
    ///
    /// For this method, the fragment can be any iterable of `u32`.
    fn index_by_fragment<I, U>(&self, fragment: I) -> Self::Output
    where
        I: IntoIterator<Item = U>,
        U: Borrow<u32>;

    /// Index this OID by an integer.
    ///
    /// Indexing by integer is used for column OIDs that have integer indexes in their parent
    /// table.
    fn index_by_integer(&self, fragment: u32) -> Self::Output {
        self.index_by_fragment(&[fragment])
    }
}
