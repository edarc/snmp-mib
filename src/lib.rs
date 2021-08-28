pub mod loader;
pub mod mib;
mod parser;

use smallvec::SmallVec;

pub use crate::parser::Type;

pub fn dotted_oid(oid: impl AsRef<[u32]>) -> String {
    oid.as_ref()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

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

// Manually derived to make {:#?} not uselessly linebreak these.
impl std::fmt::Debug for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, r#"Identifier("{}", "{}")"#, self.0, self.1)
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
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

/// Root reference, OID fragment
#[derive(Clone, Debug)]
pub struct OidExpr {
    pub parent: Identifier,
    pub fragment: SmallVec<[u32; 1]>,
}

impl std::fmt::Display for OidExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
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
        if fragments.len() == split.len() - 1 {
            Some(OidExpr {
                parent: split[0].into_identifier(),
                fragment: fragments.into(),
            })
        } else {
            None
        }
    }
}
