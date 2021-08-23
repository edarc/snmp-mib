mod loader;
mod parser;

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

use radix_trie::{Trie, TrieCommon};
use smallvec::SmallVec;

use crate::parser::ModuleDecl;

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
    pub root: Identifier,
    pub fragment: SmallVec<[u32; 1]>,
}

impl std::fmt::Display for OidDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "{}",
            Some(&self.root)
                .iter()
                .map(ToString::to_string)
                .chain(self.fragment.iter().map(ToString::to_string))
                .collect::<Vec<String>>()
                .join(".")
        )
    }
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
            Identifier("".to_string(), "iso".to_string()),
            OidDef {
                root: Identifier("".to_string(), "".to_string()),
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

    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
        let file = String::from_utf8(std::fs::read(path)?)?;
        let (_, mut parsed) = parser::parse_module(&file).map_err(|e| e.to_string())?;
      //parsed.imports.insert("iso".to_string(), "".to_string());
      //
      //let lookup = {
      //    let imports = &parsed.imports;
      //    let name = &parsed.name;
      //    move |id: &str| {
      //        let mod_name = if id == "" {
      //            ""
      //        } else {
      //            imports.get(id).unwrap_or(&name)
      //        }
      //        .to_string();
      //        Identifier(mod_name, id.to_string())
      //    }
      //};
      //
      //for decl in parsed.decls.iter() {
      //    match decl {
      //        ModuleDecl::AgentCapabilities(n, rd)
      //        | ModuleDecl::ModuleCompliance(n, rd)
      //        | ModuleDecl::ModuleIdentity(n, rd)
      //        | ModuleDecl::NotificationGroup(n, rd, _)
      //        | ModuleDecl::NotificationType(n, rd, _)
      //        | ModuleDecl::ObjectGroup(n, rd, _)
      //        | ModuleDecl::ObjectIdentity(n, rd)
      //        | ModuleDecl::ObjectType(n, rd, _, _)
      //        | ModuleDecl::PlainOidDef(n, rd) => {
      //            self.oid_defs.insert(lookup(&n), rd.clone().qualify(lookup));
      //        }
      //        ModuleDecl::Irrelevant
      //        | ModuleDecl::MacroDef(_)
      //        | ModuleDecl::Sequence(_)
      //        | ModuleDecl::TextualConvention(_, _)
      //        | ModuleDecl::TypeDef(_, _) => {}
      //    }
      //}

        Ok(())
    }

    pub fn reindex(&mut self) {
        self.oid_tree = Trie::new();

        for (id, def) in self.oid_defs.iter() {
            let mut expanded_def = def.clone();
            let OidDef {
                ref mut root,
                ref mut fragment,
            } = expanded_def;

            fragment.reverse();
            while let Some(rootdef) = self.oid_defs.get(root) {
                fragment.extend(rootdef.fragment.iter().rev().cloned());
                *root = rootdef.root.clone();
            }
            fragment.reverse();

            if expanded_def.root.is_root() {
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
            root: id,
            fragment: suffix.into(),
        }
    }
}
