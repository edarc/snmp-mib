use std::collections::BTreeMap;

use radix_trie::{Trie, TrieCommon};

use crate::loader::Loader;
use crate::{dotted_oid, Identifier, OidDef};

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: Identifier,
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
    pub fn translate_to_name(&self, oid: impl AsRef<[u32]>) -> OidDef {
        let oid = oid.as_ref().iter().cloned().collect::<Vec<_>>();
        let lookup = || {
            let subtree = self.by_oid.get_ancestor(&oid)?;
            let parent = subtree.value()?.clone();
            let prefix_len = subtree.key()?.len();
            let suffix = &oid[prefix_len..];
            Some(OidDef {
                parent: parent.id,
                fragment: suffix.into(),
            })
        };
        lookup().unwrap_or_else(|| OidDef {
            parent: Identifier::root(),
            fragment: oid.into(),
        })
    }
}

impl From<Loader> for MIB {
    fn from(loader: Loader) -> Self {
        let mut by_oid = Trie::new();
        let mut by_name = BTreeMap::new();

        let iso_def = (
            Identifier::new("", "iso"),
            OidDef {
                parent: Identifier::root(),
                fragment: [1].into(),
            },
        );

        let rel_defs = loader
            .0
            .iter()
            .filter_map(|d| d.oid_definition())
            .chain(Some(iso_def).into_iter())
            .collect::<BTreeMap<_, _>>();

        for (id, def) in rel_defs.iter() {
            match link_to_root(id, def, &rel_defs, &mut by_name) {
                Ok(oid) => {
                    let entry = Entry { id: id.clone() };
                    by_oid.insert(oid, entry);
                }
                Err(orphan) => {
                    eprintln!("{:?} orphan at {:?}", id, orphan);
                }
            }
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

/// Link an Identifier-to-OidDef binding to the root of the OID tree.
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
/// then a call to this function with `id` = N::A and `def` = { N::B 1 } that returns `Ok(v)` will,
/// as postconditions:
///
/// - Ensure `abs` contains a N::A ::= { 1 42 1 }
/// - Return `v` = { 1 42 1 }
///
/// It does this by first ensuring that `abs` contains a binding for the parent of N::A, in
/// this case N::B.
///
/// The recursive case is `abs` does not contain N::B, but `rel` does -- look up N::B in `rel` and
/// recur. The base cases are one of:
///
/// - The parent of `def` is the root already;
/// - `id` exists in `abs` already;
/// - The parent of `def` is neither in `abs` nor in `rel`, meaning there is no path to the root
///   possible (this is an error).
fn link_to_root(
    id: &Identifier,
    def: &OidDef,
    rel: &BTreeMap<Identifier, OidDef>,
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
        OidDef {
            parent: Identifier::root(),
            fragment: this_fragment.into(),
        }
    } else if let Some(parent_def) = rel.get(&def.parent) {
        // Parent is not linked. Recursively link it first.
        let mut linked_parent_fragment = link_to_root(&def.parent, parent_def, rel, abs)?;
        linked_parent_fragment.extend(def.fragment.iter().cloned());
        OidDef {
            parent: Identifier::root(),
            fragment: linked_parent_fragment.into(),
        }
    } else {
        // This def's parent is not root, and was in neither the rel or abs maps, so there is no
        // path to root. Throw this def's parent as an Err indicating which identifier is orphaned.
        return Err(def.parent.clone());
    };

    abs.insert(id.clone(), linked_def.fragment.to_vec());
    Ok(linked_def.fragment.to_vec())
}
