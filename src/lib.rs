pub mod loader;
pub mod mib;
mod parser;

use std::collections::{BTreeMap, HashMap};

use radix_trie::{Trie, TrieCommon};
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

#[derive(Clone, Debug)]
pub struct MIBDefs {
    oid_defs: BTreeMap<Identifier, OidDef>,
    oid_tree: Trie<Vec<u32>, Identifier>,
}

impl MIBDefs {
    pub fn new() -> Self {
        let mut oid_defs = BTreeMap::new();
        oid_defs.insert(
            Identifier::new("", "iso"),
            OidDef {
                parent: Identifier::root(),
                fragment: [1].into(),
            },
        );
        let ret = Self {
            oid_defs,
            oid_tree: Trie::new(),
        };
        ret
    }

    pub fn dump(&self) {
        for (exp, id) in self.oid_tree.iter() {
            let def = &self.oid_defs[id];
            println!("{} ::= {} => {}", id, def, dotted_oid(exp));
        }
    }

    pub fn reindex(&mut self) {
        self.oid_tree = Trie::new();

        for (id, def) in self.oid_defs.iter() {
            let mut expanded_def = def.clone();
            let OidDef {
                ref mut parent,
                ref mut fragment,
            } = expanded_def;

            fragment.reverse();
            while let Some(parent_def) = self.oid_defs.get(parent) {
                fragment.extend(parent_def.fragment.iter().rev().cloned());
                *parent = parent_def.parent.clone();
            }
            fragment.reverse();

            if expanded_def.parent.is_root() {
                self.oid_tree
                    .insert(expanded_def.fragment.to_vec(), id.clone());
            } else {
                //println!("Orphan {}", expanded_def);
            }
        }
    }

    pub fn translate(&self, oid: impl AsRef<[u32]>) -> OidDef {
        let oid = oid.as_ref().iter().cloned().collect::<Vec<_>>();
        let st = self.oid_tree.get_ancestor(&oid).unwrap();
        let id = st.value().unwrap().clone();
        let suffix = &oid[st.key().unwrap().len()..];
        OidDef {
            parent: id,
            fragment: suffix.into(),
        }
    }
}
