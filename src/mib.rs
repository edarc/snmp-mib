use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use lazy_static::lazy_static;
use num::BigInt;
use sequence_trie::SequenceTrie;

use crate::loader::{Loader, QualifiedDecl};
use crate::parser::{BuiltinType, PlainType, Type};
use crate::{dotted_oid, Identifier, IntoOidExpr, OidExpr};

lazy_static! {
    static ref SMI_WELL_KNOWN_TYPES: HashMap<&'static str, SMIWellKnown> = [
        ("BITS", SMIWellKnown::Bits),
        ("Counter", SMIWellKnown::Counter),
        ("Counter32", SMIWellKnown::Counter32),
        ("Counter64", SMIWellKnown::Counter64),
        ("DisplayString", SMIWellKnown::DisplayString),
        ("Gauge", SMIWellKnown::Gauge),
        ("Gauge32", SMIWellKnown::Gauge32),
        ("Integer32", SMIWellKnown::Integer32),
        ("IpAddress", SMIWellKnown::IpAddress),
        ("Opaque", SMIWellKnown::Opaque),
        ("TimeTicks", SMIWellKnown::TimeTicks),
        ("Unsigned32", SMIWellKnown::Unsigned32),
    ]
    .iter()
    .cloned()
    .collect();
}

#[derive(Clone, Debug, Copy)]
pub enum SMIWellKnown {
    Bits,
    Counter,
    Counter32,
    Counter64,
    DisplayString,
    Gauge,
    Gauge32,
    Integer32,
    IpAddress,
    Opaque,
    TimeTicks,
    Unsigned32,
}

#[derive(Clone, Debug)]
pub enum SMIScalar {
    Bits(HashMap<BigInt, String>),
    Bytes,
    Counter,
    Enumeration(HashMap<BigInt, String>),
    Gauge,
    Integer,
    IpAddress,
    ObjectIdentifier,
    Text,
    TimeTicks,
}

impl From<SMIWellKnown> for SMIScalar {
    fn from(swk: SMIWellKnown) -> Self {
        use SMIScalar as SS;
        use SMIWellKnown as SWK;
        match swk {
            SWK::Bits => SS::Integer,
            SWK::Counter => SS::Counter,
            SWK::Counter32 => SS::Counter,
            SWK::Counter64 => SS::Counter,
            SWK::DisplayString => SS::Text,
            SWK::Gauge => SS::Gauge,
            SWK::Gauge32 => SS::Gauge,
            SWK::Integer32 => SS::Integer,
            SWK::IpAddress => SS::IpAddress,
            SWK::Opaque => SS::Bytes,
            SWK::TimeTicks => SS::TimeTicks,
            SWK::Unsigned32 => SS::Integer,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SMIInterpretation {
    Scalar(SMIScalar),
    Table(SMITable),
    TableRow(SMITable),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SMITable {
    entry_id: Identifier,
    entry_type_id: Identifier,
    field_interpretation: BTreeMap<Identifier, SMIInterpretation>,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: Identifier,
    pub declared_type: Option<Type<Identifier>>,
    pub smi_interpretation: SMIInterpretation,
}

#[derive(Clone, Debug)]
pub struct MIB {
    by_oid: SequenceTrie<u32, InternalEntry>,
    by_name: BTreeMap<Identifier, Vec<u32>>,
}

impl MIB {
    /// Look up a numeric OID and translate it to a maximally-specific `OidExpr`.
    ///
    /// The returned `OidExpr`'s parent will be whichever identifier known to this MIB matches the
    /// largest prefix of the given OID. The fragment will contain any suffix for which the MIB
    /// does not define a name.
    pub fn translate_to_name(&self, oid: impl AsRef<[u32]>) -> OidExpr {
        // Decrement to skip the root.
        let prefix_len = self.by_oid.prefix_iter(oid.as_ref()).count() - 1;
        let (parent_oid, fragment) = oid.as_ref().split_at(prefix_len);
        let parent = self.by_oid.get(parent_oid).unwrap();
        OidExpr {
            parent: parent.id.clone(),
            fragment: fragment.into(),
        }
    }

    pub fn lookup_oid(&self, name: impl IntoOidExpr) -> Option<Vec<u32>> {
        let oe = name.into_oid_expr()?;
        let mut oid = self.by_name.get(&oe.parent)?.clone();
        oid.extend(oe.fragment);
        Some(oid)
    }

    pub fn get_entry(&self, oid: impl AsRef<[u32]>) -> Option<Entry> {
        self.by_oid.get(&oid.as_ref().to_vec()).map(|ie| Entry {
            id: ie.id.clone(),
            declared_type: ie.declared_type.clone(),
            smi_interpretation: ie.smi_interpretation.clone(),
        })
    }
}

impl From<Loader> for MIB {
    fn from(loader: Loader) -> Self {
        let linker = Linker::new(loader.0);

        let mut by_oid = SequenceTrie::new();
        let mut by_name = BTreeMap::new();

        for (id, oid) in linker.absolute_oids.iter() {
            by_oid.insert(oid, linker.make_entry(&id));
            by_name.insert(id.clone(), oid.clone());
        }

        Self { by_oid, by_name }
    }
}

struct Linker {
    pub type_defs: BTreeMap<Identifier, Type<Identifier>>,
    pub object_units: BTreeMap<Identifier, String>,
    pub relative_oid_defs: BTreeMap<Identifier, OidExpr>,
    pub absolute_oids: BTreeMap<Identifier, Vec<u32>>,
    pub by_oid: SequenceTrie<u32, Identifier>,
    pub orphan_identifiers: BTreeSet<Identifier>,
    interpreted_type_cache: RefCell<BTreeMap<Identifier, SMIInterpretation>>,
}

#[derive(Clone, Debug)]
struct InternalEntry {
    pub id: Identifier,
    pub declared_type: Option<Type<Identifier>>,
    pub smi_interpretation: SMIInterpretation,
}

impl Linker {
    fn new_empty() -> Self {
        Self {
            type_defs: BTreeMap::new(),
            object_units: BTreeMap::new(),
            absolute_oids: BTreeMap::new(),
            by_oid: SequenceTrie::new(),
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
            interpreted_type_cache: RefCell::new(BTreeMap::new()),
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
                    new.type_defs.insert(id, ty);
                }
                QualifiedDecl::ObjectType(id, _, ty, u) => {
                    new.type_defs.insert(id.clone(), ty);
                    u.map(|u| new.object_units.insert(id, u));
                }
                _ => {}
            }
        }

        for (id, oidexpr) in new.relative_oid_defs.iter() {
            match Self::link_oidexpr_to_absolute_oid(
                id,
                oidexpr,
                &new.relative_oid_defs,
                &mut new.absolute_oids,
            ) {
                Ok(oid) => {
                    new.by_oid.insert(&oid, id.clone());
                }
                Err(orphan) => {
                    new.orphan_identifiers.insert(orphan);
                }
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

    pub fn make_entry(&self, id: &Identifier) -> InternalEntry {
        let decl_type = self.type_defs.get(&id);

        InternalEntry {
            id: id.clone(),
            declared_type: decl_type.cloned(),
            smi_interpretation: decl_type
                .as_ref()
                .map(|dt| self.interpret_type(id, dt))
                .unwrap_or(SMIInterpretation::Unknown),
        }
    }

    fn interpret_type(&self, id: &Identifier, ty: &Type<Identifier>) -> SMIInterpretation {
        if let Some(cached_interpretation) = self.interpreted_type_cache.borrow().get(&id) {
            return cached_interpretation.clone();
        }

        let interpretation = self.interpret_type_miss(id, ty);
        self.interpreted_type_cache
            .borrow_mut()
            .insert(id.clone(), interpretation.clone());
        interpretation
    }

    fn interpret_type_miss(&self, id: &Identifier, ty: &Type<Identifier>) -> SMIInterpretation {
        use BuiltinType as BI;
        use PlainType as PI;
        use SMIInterpretation as SI;
        use SMIScalar as SS;
        use SMIWellKnown as SWK;

        match &ty.ty {
            PI::Builtin(BI::SequenceOf(elem_type)) => match &elem_type.ty {
                PI::Referenced(ref_id, _) => {
                    if self.match_sequence_type(&elem_type).is_some() {
                        // A SEQUENCE OF some referenced type which is effectively a SEQUENCE is an
                        // SNMP table.
                        if let Some(smi_table) = self.interpret_table(id, ref_id) {
                            return SI::Table(smi_table);
                        }
                    }
                }
                _ => {}
            },

            PI::Referenced(ref_id, nvs) => match SMI_WELL_KNOWN_TYPES.get(ref_id.1.as_str()) {
                // Referenced types which are well-known Integer32 or BITS types that have named
                // values are enumerations.
                Some(SWK::Integer32) | Some(SWK::Bits) if nvs.is_some() => {
                    return SI::Scalar(SS::Enumeration(
                        nvs.as_ref()
                            .unwrap()
                            .iter()
                            .map(|(n, v)| (v.clone(), n.clone()))
                            .collect(),
                    ));
                }

                // Referenced types that are any other well-known type are scalars.
                Some(other_wkt) => return SI::Scalar((*other_wkt).into()),

                None => match &self.find_effective_type(&ty) {
                    // Referenced types that are effectively a SEQUENCE are table rows. This is
                    // handled here instead of in the penultimate clause because effective type
                    // will be a plain type def and won't have an OID we can use to find the parent
                    // table.
                    Some(Type {
                        ty: PI::Builtin(BI::Sequence(_)),
                        ..
                    }) => {
                        if let Some(smi_table) = self.interpret_table_entry(&id, ref_id) {
                            return SI::TableRow(smi_table);
                        }
                    }

                    // Referenced types that aren't well-known, and whose effective type is
                    // identical to this type, aren't interpretable. Without bailing out here
                    // specifically, the next clause will match and infintely recur.
                    Some(Type {
                        ty: PI::Referenced(eid, _),
                        ..
                    }) if eid == ref_id => {}

                    // Referenced types that have effective type that is NOT a reference are
                    // interpreted recursively (i.e. as the interpretation of the effective type).
                    Some(effective) => return self.interpret_type(&ref_id, &effective),

                    // Referenced types with uninterpretable effective types are uninterpretable.
                    None => {}
                },
            },

            // Built-in INTEGER with named values is an enumeration.
            PI::Builtin(BI::Integer(Some(nvs))) => {
                return SI::Scalar(SS::Enumeration(
                    nvs.iter().map(|(n, v)| (v.clone(), n.clone())).collect(),
                ))
            }

            // Other primitive built-ins (including INTEGER with no named values) are themselves.
            PI::Builtin(BI::Integer(None)) => return SI::Scalar(SS::Integer),
            PI::Builtin(BI::ObjectIdentifier) => return SI::Scalar(SS::ObjectIdentifier),
            PI::Builtin(BI::OctetString) => return SI::Scalar(SS::Bytes),

            // These theoretically don't occur in SMI, so don't interpret them.
            PI::Builtin(BI::Sequence(_))
            | PI::Builtin(BI::Boolean)
            | PI::Builtin(BI::Choice(_))
            | PI::Builtin(BI::Null) => {}
        };
        SI::Unknown
    }

    fn interpret_table(&self, id: &Identifier, entry_id: &Identifier) -> Option<SMITable> {
        let table_oid = self.absolute_oids.get(id)?;
        let table_subtrie = self.by_oid.get_node(table_oid)?;
        let table_entry = table_subtrie.iter().nth(1)?;

        let table_entry_oid = table_oid
            .into_iter()
            .copied()
            .chain(table_entry.0.into_iter().copied())
            .collect::<Vec<_>>();
        let table_entry_id = table_entry.1;

        let table_fields = self.interpret_table_fields(&table_entry_id)?;

        Some(SMITable {
            entry_id: table_entry_id.clone(),
            entry_type_id: entry_id.clone(),
            field_interpretation: table_fields,
        })
    }

    fn interpret_table_fields(
        &self,
        entry_id: &Identifier,
    ) -> Option<BTreeMap<Identifier, SMIInterpretation>> {
        let table_entry_type = self.find_effective_type(self.type_defs.get(entry_id)?)?;
        let table_fields = self
            .match_sequence_type(&table_entry_type)?
            .into_iter()
            .map(|(fid, fty)| {
                let interp = self.interpret_type(&fid, &fty);
                (fid, interp)
            })
            .collect::<BTreeMap<_, _>>();

        Some(table_fields)
    }

    fn interpret_table_entry(
        &self,
        entry_id: &Identifier,
        entry_type_id: &Identifier,
    ) -> Option<SMITable> {
        let table_entry_oid = self.absolute_oids.get(entry_id)?;
        let table_id = self
            .by_oid
            .get(&table_entry_oid[..(table_entry_oid.len() - 1)])?;
        self.interpret_table(table_id, entry_type_id)
    }

    fn match_sequence_type(
        &self,
        ty: &Type<Identifier>,
    ) -> Option<Vec<(Identifier, Type<Identifier>)>> {
        use BuiltinType as BI;
        use PlainType as PI;
        match &self.find_effective_type(ty).as_ref()?.ty {
            PI::Builtin(BI::Sequence(fields)) => Some(fields.iter().cloned().collect()),
            _ => None,
        }
    }

    fn find_effective_type(&self, ty: &Type<Identifier>) -> Option<Type<Identifier>> {
        let mut effective_type = Some(ty.clone());

        loop {
            let new_effective_type = if let Some(Type {
                ty: PlainType::Referenced(ref id, _),
                ..
            }) = effective_type
            {
                // If the current effective_type is a reference, check if it's an SMI well-known
                // type. Otherwise, try to dereference it into new_effective_type.
                if SMI_WELL_KNOWN_TYPES.get(id.1.as_str()).is_some() {
                    break;
                } else {
                    self.type_defs.get(&id)
                }
            } else {
                // The current effective_type is either None, or a Builtin type. We're done.
                break;
            };

            // If the dereference into new_effective_type worked, update effective_type and go
            // around again. Otherwise effective_type is as good as we can do, so break and return
            // it.
            match new_effective_type {
                Some(new) => {
                    // TODO: constraint should be intersected
                    effective_type.as_mut().unwrap().ty = new.ty.clone();
                }
                None => {
                    break;
                }
            }
        }

        effective_type
    }
}
