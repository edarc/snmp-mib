use std::fmt::{Debug, Display, Error as FmtError, Formatter};

use crate::types::IdentifiedObj;

/// Module name, identifier
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Identifier(pub String, pub String);

impl Identifier {
    pub fn new(modname: impl AsRef<str>, name: impl AsRef<str>) -> Self {
        Identifier(modname.as_ref().to_string(), name.as_ref().to_string())
    }

    pub fn root() -> Self {
        Identifier::new("", "")
    }

    pub fn is_root(&self) -> bool {
        self.0 == "" && self.1 == ""
    }
}

impl Debug for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, r#"Identifier("{}")"#, self)
    }
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}::{}", self.0, self.1)
    }
}

/// A trait for types that can be converted to Identifier.
pub trait IntoIdentifier {
    fn into_identifier(self) -> Identifier;
}

impl<M: AsRef<str>, N: AsRef<str>> IntoIdentifier for (M, N) {
    fn into_identifier(self) -> Identifier {
        Identifier::new(self.0.as_ref(), self.1.as_ref())
    }
}

impl IntoIdentifier for &str {
    fn into_identifier(self) -> Identifier {
        let mut split = self.splitn(2, "::").collect::<Vec<_>>();
        let rest = split.pop().unwrap();
        let first = split.pop().unwrap_or("");
        (first, rest).into_identifier()
    }
}

impl IntoIdentifier for IdentifiedObj {
    fn into_identifier(self) -> Identifier {
        self.1
    }
}
