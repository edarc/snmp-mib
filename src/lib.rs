pub mod loader;
pub mod mib;
mod parser;

use std::collections::HashMap;

use smallvec::SmallVec;

pub fn dotted_oid(oid: impl AsRef<[u32]>) -> String {
    oid.as_ref()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

/// Module name, identifier
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
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

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}::{}", self.0, self.1)
    }
}

/// Root reference, OID fragment
#[derive(Clone, Debug)]
pub struct OidDef {
    pub parent: Identifier,
    pub fragment: SmallVec<[u32; 1]>,
}

impl std::fmt::Display for OidDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            Some(&self.parent)
                .iter()
                .map(ToString::to_string)
                .chain(self.fragment.iter().map(ToString::to_string))
                .collect::<Vec<String>>()
                .join(".")
        )
    }
}

/// Type information, which may or may not be interpreted.
///
/// Some kinds of type information are interesting for the interpretation of binding values, such
/// as bitfields, named value enumerations, and OIDs. Many types are currently "uninterpreted"
/// however, and the type declaration is just given as a string.
#[derive(Clone, Debug)]
pub enum TypeInfo {
    BitField(HashMap<u16, String>),
    Enumeration(HashMap<i64, String>),
    Oid,
    Uninterpreted(String),
}
