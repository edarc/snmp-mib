use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use sequence_trie::SequenceTrie;

use crate::loader::{QualifiedDecl, TableIndexing};
use crate::mib::interpretation::{SMIInterpretation, SMIScalar, SMITable};
use crate::mib::smi_well_known::{SMIWellKnown, SMI_WELL_KNOWN_TYPES};
use crate::parser::asn_type::{BuiltinType, PlainType, Type};
use crate::types::{IdentifiedObj, Identifier, IntoOidExpr, NumericOid, OidExpr};

pub(crate) struct Linker {
    numeric_oid_names: SequenceTrie<u32, Identifier>,
    object_indexes: BTreeMap<Identifier, TableIndexing>,
    pub(crate) object_numeric_oids: BTreeMap<Identifier, NumericOid>,
    object_oidexpr_defs: BTreeMap<Identifier, OidExpr>,
    object_uoms: BTreeMap<Identifier, String>,
    orphan_identifiers: BTreeSet<Identifier>,
    type_defs: BTreeMap<Identifier, Type<Identifier>>,
    type_interpretation_cache: RefCell<BTreeMap<Identifier, SMIInterpretation>>,
}

#[derive(Clone, Debug)]
pub(crate) struct InternalObjectDescriptor {
    pub(crate) name: Identifier,
    pub(crate) declared_type: Option<Type<Identifier>>,
    pub(crate) smi_interpretation: SMIInterpretation,
}

impl Linker {
    fn new_empty() -> Self {
        Self {
            numeric_oid_names: SequenceTrie::new(),
            object_indexes: BTreeMap::new(),
            object_numeric_oids: Some((Identifier::root(), vec![].into()))
                .into_iter()
                .collect(),
            object_oidexpr_defs: Some((
                Identifier::new("", "iso"),
                NumericOid::new([1]).into_oid_expr().unwrap(),
            ))
            .into_iter()
            .collect(),
            object_uoms: BTreeMap::new(),
            orphan_identifiers: BTreeSet::new(),
            type_defs: BTreeMap::new(),
            type_interpretation_cache: RefCell::new(BTreeMap::new()),
        }
    }

    pub(crate) fn new<'a>(decls: impl IntoIterator<Item = QualifiedDecl>) -> Self {
        use QualifiedDecl as QD;

        let mut new = Self::new_empty();

        for decl in decls {
            if let Some((name, oidexpr)) = decl.oid_definition() {
                new.object_oidexpr_defs.insert(name, oidexpr);
            }

            match decl {
                QD::PlainTypeDef(name, ty) => {
                    new.type_defs.insert(name, ty);
                }
                QD::ObjectType(name, _, ty, detail) => {
                    new.type_defs.insert(name.clone(), ty);
                    detail
                        .unit_of_measure
                        .map(|uom| new.object_uoms.insert(name.clone(), uom));
                    detail
                        .indexing
                        .map(|idx| new.object_indexes.insert(name, idx));
                }
                QD::TextualConvention(name, ty) => {
                    new.type_defs.insert(name.clone(), ty);
                }
                QD::AgentCapabilities(..)
                | QD::Irrelevant
                | QD::MacroDef(..)
                | QD::ModuleCompliance(..)
                | QD::ModuleIdentity(..)
                | QD::NotificationGroup(..)
                | QD::NotificationType(..)
                | QD::PlainOidDef(..)
                | QD::ObjectIdentity(..)
                | QD::ObjectGroup(..) => {}
            }
        }

        for (name, oidexpr) in new.object_oidexpr_defs.iter() {
            match Self::link_oidexpr_to_numeric_oid(
                name,
                oidexpr,
                &new.object_oidexpr_defs,
                &mut new.object_numeric_oids,
            ) {
                Ok(oid) => {
                    new.numeric_oid_names.insert(&oid, name.clone());
                }
                Err(orphan) => {
                    new.orphan_identifiers.insert(orphan);
                }
            }
        }

        new
    }

    /// Link an Identifier-to-OidExpr binding with parent bindings to get a numeric OID.
    ///
    /// Given a map of relative OidExpr bindings `rel` like
    ///
    ///   N::A ::= { N::B 1 }
    ///   N::B ::= { iso 42 }
    ///
    /// and a map of absolute numeric OID bindings `abs`, like
    ///
    ///   iso ::= { 1 }
    ///
    /// then a call to this function with `name` = N::A and `def` = { N::B 1 } that returns `Ok(v)`
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
    /// - `name` exists in `abs` already;
    /// - The parent of `def` is neither in `abs` nor in `rel`, meaning there is no path to the
    ///   root possible (this is an error).
    fn link_oidexpr_to_numeric_oid(
        name: &Identifier,
        def: &OidExpr,
        rel: &BTreeMap<Identifier, OidExpr>,
        abs: &mut BTreeMap<Identifier, NumericOid>,
    ) -> Result<NumericOid, Identifier> {
        let linked_def = if def.parent().is_root() {
            // The parent is root, so this def is linked already.
            def.clone()
        } else if let Some(parent_fragment) = abs.get(def.parent()) {
            // Parent is linked. Link this one by indexing the parent by this fragment.
            let this_fragment = parent_fragment.index_by_fragment(def.fragment());
            NumericOid::new(this_fragment).into_oid_expr().unwrap()
        } else if let Some(parent_def) = rel.get(def.parent()) {
            // Parent is not linked. Recursively link it first.
            let linked_parent_fragment =
                Self::link_oidexpr_to_numeric_oid(def.parent(), parent_def, rel, abs)?
                    .index_by_fragment(def.fragment());
            NumericOid::new(linked_parent_fragment)
                .into_oid_expr()
                .unwrap()
        } else {
            // This def's parent is not root, and was in neither the rel or abs maps, so there is
            // no path to root. Throw this def's parent as an Err indicating which identifier is
            // orphaned.
            return Err(def.parent().clone());
        };

        abs.insert(name.clone(), linked_def.fragment().to_vec().into());
        Ok(linked_def.fragment().to_vec().into())
    }

    pub(crate) fn make_entry(&self, name: &Identifier) -> InternalObjectDescriptor {
        let num_oid = self.object_numeric_oids.get(name);
        let declared_type = self.type_defs.get(&name);

        let interpretation = if let Some(declared_type) = declared_type {
            self.interpret_type(name, declared_type)
        } else if let Some(num_oid) = num_oid {
            let children = self
                .numeric_oid_names
                .get_node(num_oid)
                .unwrap()
                .children_with_keys();
            if !children.is_empty() {
                SMIInterpretation::Namespace(
                    children
                        .into_iter()
                        .filter_map(|(fragment, subtrie)| {
                            subtrie.value().map(|name| (fragment, name))
                        })
                        .map(|(fragment, name)| {
                            IdentifiedObj::new(num_oid.index_by_integer(*fragment), name.clone())
                        })
                        .collect(),
                )
            } else {
                SMIInterpretation::Unknown
            }
        } else {
            SMIInterpretation::Unknown
        };

        InternalObjectDescriptor {
            name: name.clone(),
            declared_type: declared_type.cloned(),
            smi_interpretation: interpretation,
        }
    }

    fn interpret_type(&self, name: &Identifier, ty: &Type<Identifier>) -> SMIInterpretation {
        use SMIInterpretation as SI;
        use SMIScalar as SS;

        if let Some(cached_interpretation) = self.type_interpretation_cache.borrow().get(&name) {
            return cached_interpretation.clone();
        }

        let interpretation = match self.interpret_type_miss(name, ty) {
            SI::Scalar(SS::Counter(uom)) => {
                SI::Scalar(SS::Counter(self.object_uoms.get(name).cloned().or(uom)))
            }
            SI::Scalar(SS::Gauge(uom)) => {
                SI::Scalar(SS::Gauge(self.object_uoms.get(name).cloned().or(uom)))
            }
            SI::Scalar(SS::Integer(uom)) => {
                SI::Scalar(SS::Integer(self.object_uoms.get(name).cloned().or(uom)))
            }
            other => other,
        };

        self.type_interpretation_cache
            .borrow_mut()
            .insert(name.clone(), interpretation.clone());
        interpretation
    }

    fn interpret_type_miss(
        &self,
        name: &Identifier,
        decl_type: &Type<Identifier>,
    ) -> SMIInterpretation {
        use BuiltinType as BI;
        use PlainType as PI;
        use SMIInterpretation as SI;
        use SMIScalar as SS;
        use SMIWellKnown as SWK;

        match &decl_type.ty {
            PI::Builtin(BI::SequenceOf(elem_type)) => match &elem_type.ty {
                PI::Referenced(referent_name, _) => {
                    if self.match_sequence_type(&elem_type).is_some() {
                        // A SEQUENCE OF some referenced type which is effectively a SEQUENCE is an
                        // SNMP table.
                        if let Some(smi_table) = self.interpret_table(name, referent_name) {
                            return SI::Table(smi_table);
                        }
                    }
                }
                _ => {}
            },

            PI::Referenced(referent_name, named_vals) => match SMI_WELL_KNOWN_TYPES
                .get(referent_name.local_name())
            {
                // Referenced types which are well-known Integer32 or BITS types that have named
                // values are enumerations.
                Some(SWK::Integer32) | Some(SWK::Bits) if named_vals.is_some() => {
                    return SI::Scalar(SS::Enumeration(
                        named_vals
                            .as_ref()
                            .unwrap()
                            .iter()
                            .map(|(n, v)| (v.clone(), n.clone()))
                            .collect(),
                    ));
                }

                // Referenced types that are any other well-known type are scalars.
                Some(other_wkt) => return SI::Scalar((*other_wkt).into()),

                None => match &self.find_effective_type(&decl_type) {
                    // Referenced types that are effectively a SEQUENCE are table rows. This is
                    // handled here instead of in the penultimate clause because effective type
                    // will be a plain type def and won't have an OID we can use to find the parent
                    // table.
                    Some(Type {
                        ty: PI::Builtin(BI::Sequence(_)),
                        ..
                    }) => {
                        if let Some(smi_table) = self.interpret_table_entry(&name, referent_name) {
                            return SI::TableRow(smi_table);
                        }
                    }

                    // Referenced types that aren't well-known, and whose effective type is
                    // identical to this type, aren't interpretable. Without bailing out here
                    // specifically, the next clause will match and infintely recur.
                    Some(Type {
                        ty: PI::Referenced(effective_referent_name, _),
                        ..
                    }) if effective_referent_name == referent_name => {}

                    // Referenced types that have effective type that is NOT a reference are
                    // interpreted recursively (i.e. as the interpretation of the effective type).
                    Some(non_referenced_type) => {
                        return self.interpret_type(&referent_name, &non_referenced_type)
                    }

                    // Referenced types with uninterpretable effective types are uninterpretable.
                    None => {}
                },
            },

            // Built-in INTEGER with named values is an enumeration.
            PI::Builtin(BI::Integer(Some(named_vals))) => {
                return SI::Scalar(SS::Enumeration(
                    named_vals
                        .iter()
                        .map(|(n, v)| (v.clone(), n.clone()))
                        .collect(),
                ))
            }

            // Other primitive built-ins (including INTEGER with no named values) are themselves.
            PI::Builtin(BI::Integer(None)) => return SI::Scalar(SS::Integer(None)),
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

    fn interpret_table(
        &self,
        table_name: &Identifier,
        entry_type_name: &Identifier,
    ) -> Option<SMITable> {
        let table_num_oid = self.object_numeric_oids.get(table_name)?;
        let table_subtrie = self.numeric_oid_names.get_node(table_num_oid)?;
        let (fragment, table_entry_name) = table_subtrie.iter().nth(1)?;
        let entry_num_oid = table_num_oid.index_by_fragment(fragment);

        let table_fields = self.interpret_table_fields(&table_entry_name)?;

        let effective_index_fields = match self.object_indexes.get(&table_entry_name)? {
            TableIndexing::Index(cols) => cols,
            TableIndexing::Augments(name) => match self.object_indexes.get(&name)? {
                TableIndexing::Index(cols) => cols,
                _ => return None,
            },
        };
        let index_fields = effective_index_fields
            .iter()
            .filter_map(|(name, implied)| {
                self.object_numeric_oids.get(&name).map(|num_oid| {
                    (
                        IdentifiedObj::new(num_oid.clone(), name.clone()),
                        (*implied).into(),
                    )
                })
            })
            .collect();

        Some(SMITable {
            table_object: IdentifiedObj::new(table_num_oid.clone(), table_name.clone()),
            entry_object: IdentifiedObj::new(entry_num_oid, table_entry_name.clone()),
            entry_type_name: entry_type_name.clone(),
            field_interpretation: table_fields,
            index_fields,
        })
    }

    fn interpret_table_fields(
        &self,
        table_entry_name: &Identifier,
    ) -> Option<BTreeMap<IdentifiedObj, SMIInterpretation>> {
        let table_entry_type = self.find_effective_type(self.type_defs.get(table_entry_name)?)?;
        let table_fields = self
            .match_sequence_type(&table_entry_type)?
            .into_iter()
            // Nearly always, each SEQUENCE field identifier is the same as some OBJECT-TYPE
            // definition that has the "best" type information, so we look up that identifier in
            // type_defs and interpret its type to get the field interpretation. If the SEQUENCE
            // field identifier doesn't refer to anything in type_defs, it means it definitely
            // won't be in object_numeric_oids, so it's probably useless anyway and should just get
            // filtered out.
            .filter_map(|(field_name, _)| {
                self.type_defs.get(&field_name).and_then(|decl_type| {
                    let field_num_oid = self.object_numeric_oids.get(&field_name)?;
                    let interp = self.interpret_type(&field_name, &decl_type);
                    Some((
                        IdentifiedObj::new(field_num_oid.clone(), field_name),
                        interp,
                    ))
                })
            })
            .collect::<BTreeMap<_, _>>();

        Some(table_fields)
    }

    fn interpret_table_entry(
        &self,
        table_entry_name: &Identifier,
        entry_type_name: &Identifier,
    ) -> Option<SMITable> {
        let entry_num_oid = self.object_numeric_oids.get(table_entry_name)?;
        let table_name = self
            .numeric_oid_names
            .get(&entry_num_oid[..(entry_num_oid.len() - 1)])?;
        self.interpret_table(table_name, entry_type_name)
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

    fn find_effective_type(&self, given_type: &Type<Identifier>) -> Option<Type<Identifier>> {
        let mut effective_type = Some(given_type.clone());

        loop {
            let new_effective_type = if let Some(Type {
                ty: PlainType::Referenced(ref referent_name, _),
                ..
            }) = effective_type
            {
                // If the current effective_type is a reference, check if it's an SMI well-known
                // type. Otherwise, try to dereference it into new_effective_type.
                if SMI_WELL_KNOWN_TYPES
                    .get(referent_name.local_name())
                    .is_some()
                {
                    break;
                } else {
                    self.type_defs.get(&referent_name)
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
