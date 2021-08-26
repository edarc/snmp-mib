use std::collections::{BTreeMap, BTreeSet};

use radix_trie::{Trie, TrieCommon};

use crate::loader::{Loader, QualifiedDecl};
use crate::parser::{BuiltinType, PlainType, Type};
use crate::{/*dotted_oid,*/ Identifier, IntoOidExpr, OidExpr};

#[derive(Clone, Debug)]
pub enum EntryKind {
    Scalar,
    Table(Identifier),
    TableEntry(Vec<Identifier>),
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: Identifier,
    pub kind: EntryKind,
}

#[derive(Clone, Debug)]
pub struct MIB {
    by_oid: Trie<Vec<u32>, Entry>,
    by_name: BTreeMap<Identifier, Vec<u32>>,
}

impl MIB {
    /// Look up a numeric OID and translate it to a maximally-specific `OidExpr`.
    ///
    /// The returned `OidExpr`'s parent will be whichever identifier known to this MIB matches the
    /// largest prefix of the given OID. The fragment will contain any suffix for which the MIB
    /// does not define a name.
    pub fn translate_to_name(&self, oid: impl AsRef<[u32]>) -> OidExpr {
        let oid = oid.as_ref().iter().cloned().collect::<Vec<_>>();
        let lookup = || {
            let subtree = self.by_oid.get_ancestor(&oid)?;
            let parent = subtree.value()?.clone();
            let prefix_len = subtree.key()?.len();
            let suffix = &oid[prefix_len..];
            Some(OidExpr {
                parent: parent.id,
                fragment: suffix.into(),
            })
        };
        lookup().unwrap_or_else(|| OidExpr {
            parent: Identifier::root(),
            fragment: oid.into(),
        })
    }

    pub fn lookup_oid(&self, name: impl IntoOidExpr) -> Option<Vec<u32>> {
        let oe = name.into_oid_expr()?;
        let mut oid = self.by_name.get(&oe.parent)?.clone();
        oid.extend(oe.fragment);
        Some(oid)
    }

    pub fn dump(&self) {
        println!("{} names, {} OIDs", self.by_name.len(), self.by_oid.len());
    }
}

impl From<Loader> for MIB {
    fn from(loader: Loader) -> Self {
        let linker = Linker::new(loader.0);

        let mut by_oid = Trie::new();
        let mut by_name = BTreeMap::new();

        for (id, oid) in linker.absolute_oids.iter() {
            by_oid.insert(
                oid.clone(),
                Entry {
                    id: id.clone(),
                    kind: EntryKind::Unknown,
                },
            );
            by_name.insert(id.clone(), oid.clone());
        }

        //for (k, v) in by_oid.iter() {
        //    println!("{} => {:#?}", dotted_oid(k), v);
        //}
        //for (k, v) in by_name.iter() {
        //    println!("{:?} => {}", k, dotted_oid(v));
        //}

        Self { by_oid, by_name }
    }
}

struct Linker {
    pub type_defs: BTreeMap<Identifier, Type<Identifier>>,
    pub relative_oid_defs: BTreeMap<Identifier, OidExpr>,
    pub absolute_oids: BTreeMap<Identifier, Vec<u32>>,
    pub orphan_identifiers: BTreeSet<Identifier>,
}

impl Linker {
    fn new_empty() -> Self {
        Self {
            type_defs: BTreeMap::new(),
            absolute_oids: BTreeMap::new(),
            orphan_identifiers: BTreeSet::new(),
            relative_oid_defs: Some((
                Identifier::new("", "iso"),
                OidExpr {
                    parent: Identifier::root(),
                    fragment: [1].into(),
                },
            ))
            .into_iter()
            .collect(),
        }
    }

    fn new<'a>(decls: impl IntoIterator<Item = QualifiedDecl>) -> Self {
        let mut new = Self::new_empty();

        for decl in decls {
            if let Some((id, oidexpr)) = decl.oid_definition() {
                new.relative_oid_defs.insert(id, oidexpr);
            }

            match decl {
                QualifiedDecl::PlainTypeDef(id, ty) => {
                    match &ty {
                        Type {
                            ty: PlainType::Builtin(BuiltinType::Sequence(_)),
                            ..
                        } => {}
                        ty => {
                            println!("{} => {:#?}", id, ty);
                        }
                    }
                    new.type_defs.insert(id, ty);
                }
                _ => {}
            }
        }

        for (id, oidexpr) in new.relative_oid_defs.iter() {
            if let Err(orphan) = Self::link_oidexpr_to_absolute_oid(
                id,
                oidexpr,
                &new.relative_oid_defs,
                &mut new.absolute_oids,
            ) {
                new.orphan_identifiers.insert(orphan);
            }
        }

        new
    }

    /// Link an Identifier-to-OidExpr binding with parent bindings to get an absolute OID.
    ///
    /// Given a map of relative bindings `rel` like
    ///
    ///   N::A ::= { N::B 1 }
    ///   N::B ::= { iso 42 }
    ///
    /// and a map of absolute bindings `abs`, like
    ///
    ///   iso ::= { 1 }
    ///
    /// then a call to this function with `id` = N::A and `def` = { N::B 1 } that returns `Ok(v)`
    /// will, as postconditions:
    ///
    /// - Ensure `abs` contains a N::A ::= { 1 42 1 }
    /// - Return `v` = { 1 42 1 }
    ///
    /// It does this by first ensuring that `abs` contains a binding for the parent of N::A, in
    /// this case N::B.
    ///
    /// The recursive case is `abs` does not contain N::B, but `rel` does -- look up N::B in `rel`
    /// and recur. The base cases are one of:
    ///
    /// - The parent of `def` is the root already;
    /// - `id` exists in `abs` already;
    /// - The parent of `def` is neither in `abs` nor in `rel`, meaning there is no path to the
    ///   root possible (this is an error).
    fn link_oidexpr_to_absolute_oid(
        id: &Identifier,
        def: &OidExpr,
        rel: &BTreeMap<Identifier, OidExpr>,
        abs: &mut BTreeMap<Identifier, Vec<u32>>,
    ) -> Result<Vec<u32>, Identifier> {
        let linked_def = if def.parent.is_root() {
            // The parent is root, so this def is linked already.
            def.clone()
        } else if let Some(parent_fragment) = abs.get(&def.parent) {
            // Parent is linked. Link this one by chaining its fragment to the parent fragment.
            let this_fragment = parent_fragment
                .iter()
                .chain(def.fragment.iter())
                .cloned()
                .collect::<Vec<_>>();
            OidExpr {
                parent: Identifier::root(),
                fragment: this_fragment.into(),
            }
        } else if let Some(parent_def) = rel.get(&def.parent) {
            // Parent is not linked. Recursively link it first.
            let mut linked_parent_fragment =
                Self::link_oidexpr_to_absolute_oid(&def.parent, parent_def, rel, abs)?;
            linked_parent_fragment.extend(def.fragment.iter().cloned());
            OidExpr {
                parent: Identifier::root(),
                fragment: linked_parent_fragment.into(),
            }
        } else {
            // This def's parent is not root, and was in neither the rel or abs maps, so there is
            // no path to root. Throw this def's parent as an Err indicating which identifier is
            // orphaned.
            return Err(def.parent.clone());
        };

        abs.insert(id.clone(), linked_def.fragment.to_vec());
        Ok(linked_def.fragment.to_vec())
    }
}
