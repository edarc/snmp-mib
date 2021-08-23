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

fn link(
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
        let mut linked_parent_fragment = link(&def.parent, parent_def, rel, abs)?;
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
            match link(id, def, &rel_defs, &mut by_name) {
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
