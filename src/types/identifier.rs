use std::borrow::Borrow;
use std::fmt::{Debug, Display, Error as FmtError, Formatter};

use crate::types::{Indexable, OidExpr};

/// A module-qualified name.
///
/// An identifier consists of a local name and a module name, and so uniquely names some object,
/// which may or may not exist in the MIB.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Identifier(String, String);

impl Identifier {
    /// Construct an identifier from a module name and a local name.
    ///
    /// ```
    /// # use snmp_mib::types::Identifier;
    /// let ident = Identifier::new("MY-MODULE", "myLocalName");
    /// ```
    pub fn new(module_name: impl AsRef<str>, local_name: impl AsRef<str>) -> Self {
        Identifier(
            module_name.as_ref().to_string(),
            local_name.as_ref().to_string(),
        )
    }

    /// Construct an identifier that refers to the root of the MIB. This is generally only used in
    /// `OidExpr` where it means that the expression is entirely numeric and has no named parent.
    pub fn root() -> Self {
        Identifier::new("", "")
    }

    /// Predicate to query whether this identifier is the root identifier.
    ///
    /// ```
    /// # use snmp_mib::types::Identifier;
    /// let root = Identifier::root();
    /// let not_root = Identifier::new("NOT", "root");
    /// assert_eq!(root.is_root(), true);
    /// assert_eq!(not_root.is_root(), false);
    /// ```
    pub fn is_root(&self) -> bool {
        self.0 == "" && self.1 == ""
    }

    /// Return the module name portion of the identifier.
    ///
    /// ```
    /// # use snmp_mib::types::Identifier;
    /// let ident = Identifier::new("MY-MODULE", "myLocalName");
    /// assert_eq!(ident.module_name(), "MY-MODULE");
    /// ```
    pub fn module_name(&self) -> &str {
        &self.0
    }

    /// Return the module local name portion of the identifier.
    ///
    /// ```
    /// # use snmp_mib::types::Identifier;
    /// let ident = Identifier::new("MY-MODULE", "myLocalName");
    /// assert_eq!(ident.local_name(), "myLocalName");
    /// ```
    pub fn local_name(&self) -> &str {
        &self.1
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

impl Indexable for Identifier {
    type Output = OidExpr;

    fn index_by_fragment<I, U>(&self, fragment: I) -> Self::Output
    where
        I: IntoIterator<Item = U>,
        U: Borrow<u32>,
    {
        OidExpr::new(self.clone(), fragment)
    }
}
