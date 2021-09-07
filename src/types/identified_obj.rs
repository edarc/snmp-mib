use std::fmt::{Debug, Error as FmtError, Formatter};
use std::ops::Deref;

use crate::types::identifier::Identifier;
use crate::types::numeric_oid::NumericOid;

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct IdentifiedObj(pub(super) NumericOid, pub(super) Identifier);

impl IdentifiedObj {
    pub fn new(numeric_oid: NumericOid, name: Identifier) -> Self {
        IdentifiedObj(numeric_oid, name)
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
