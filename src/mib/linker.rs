use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use sequence_trie::SequenceTrie;

use crate::error::InterpretationError;
use crate::loader::{QualifiedDecl, TableIndexing};
use crate::mib::interpretation::{SMIInterpretation, SMIScalar, SMITable};
use crate::mib::smi_well_known::{SMIWellKnown, SMI_WELL_KNOWN_TYPES};
use crate::parser::asn_type::{BuiltinType, PlainType, Type};
use crate::types::{IdentifiedObj, Identifier, Indexable, IntoOidExpr, NumericOid, OidExpr};

pub(crate) struct Linker {
    numeric_oid_names: SequenceTrie<u32, Identifier>,
    object_indexes: BTreeMap<Identifier, TableIndexing>,
    pub(crate) object_numeric_oids: BTreeMap<Identifier, NumericOid>,
    object_oidexpr_defs: BTreeMap<Identifier, OidExpr>,
    object_uoms: BTreeMap<Identifier, String>,
    pub(crate) orphan_identifiers: BTreeMap<Identifier, Identifier>,
    type_defs: BTreeMap<Identifier, Type<Identifier>>,
    type_interpretation_cache:
        RefCell<BTreeMap<Identifier, Result<SMIInterpretation, InterpretationError>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct InternalObjectDescriptor {
    pub(crate) name: Identifier,
    pub(crate) declared_type: Option<Type<Identifier>>,
    pub(crate) smi_interpretation: Result<SMIInterpretation, InterpretationError>,
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
                NumericOid::new([1]).into_oid_expr(),
            ))
            .into_iter()
            .collect(),
            object_uoms: BTreeMap::new(),
            orphan_identifiers: BTreeMap::new(),
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
                    new.orphan_identifiers.insert(name.clone(), orphan);
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
        let mut visited_ids = BTreeSet::new();
        Self::link_oidexpr_to_numeric_oid_internal(name, def, rel, abs, &mut visited_ids)
    }

    fn link_oidexpr_to_numeric_oid_internal(
        name: &Identifier,
        def: &OidExpr,
        rel: &BTreeMap<Identifier, OidExpr>,
        abs: &mut BTreeMap<Identifier, NumericOid>,
        visited_ids: &mut BTreeSet<Identifier>,
    ) -> Result<NumericOid, Identifier> {
        if !visited_ids.insert(name.clone()) {
            return Err(name.clone());
        }
        let linked_def = if def.base_identifier().is_root() {
            // The parent is root, so this def is linked already.
            def.clone()
        } else if let Some(parent_fragment) = abs.get(def.base_identifier()) {
            // Parent is linked. Link this one by indexing the parent by this fragment.
            let this_fragment = parent_fragment.index_by_fragment(def.fragment());
            NumericOid::new(this_fragment).into_oid_expr()
        } else if let Some(parent_def) = rel.get(def.base_identifier()) {
            // Parent is not linked. Recursively link it first.
            let linked_parent_fragment = Self::link_oidexpr_to_numeric_oid_internal(
                def.base_identifier(),
                parent_def,
                rel,
                abs,
                visited_ids,
            )?
            .index_by_fragment(def.fragment());
            NumericOid::new(linked_parent_fragment).into_oid_expr()
        } else {
            // This def's parent is not root, and was in neither the rel or abs maps, so there is
            // no path to root. Throw this def's parent as an Err indicating which identifier is
            // orphaned.
            return Err(def.base_identifier().clone());
        };

        abs.insert(name.clone(), linked_def.fragment().to_vec().into());
        Ok(linked_def.fragment().to_vec().into())
    }

    pub(crate) fn make_entry(
        &self,
        name: &Identifier,
        num_oid: &NumericOid,
    ) -> InternalObjectDescriptor {
        let declared_type = self.type_defs.get(&name);

        let smi_interpretation = match declared_type {
            Some(declared_type) => self.interpret_type(name, declared_type),
            None => self.interpret_namespace(num_oid),
        };

        InternalObjectDescriptor {
            name: name.clone(),
            declared_type: declared_type.cloned(),
            smi_interpretation,
        }
    }

    fn interpret_namespace(
        &self,
        num_oid: &NumericOid,
    ) -> Result<SMIInterpretation, InterpretationError> {
        let children = self
            .numeric_oid_names
            .get_node(num_oid)
            .unwrap()
            .children_with_keys();
        if !children.is_empty() {
            Ok(SMIInterpretation::Namespace(
                children
                    .into_iter()
                    .filter_map(|(fragment, subtrie)| subtrie.value().map(|name| (fragment, name)))
                    .map(|(fragment, name)| {
                        IdentifiedObj::new(num_oid.index_by_integer(*fragment), name.clone())
                    })
                    .collect(),
            ))
        } else {
            Err(InterpretationError::UntypedLeafObject)
        }
    }

    fn interpret_type(
        &self,
        name: &Identifier,
        ty: &Type<Identifier>,
    ) -> Result<SMIInterpretation, InterpretationError> {
        use SMIInterpretation as SI;
        use SMIScalar as SS;

        if let Some(cached_interpretation) = self.type_interpretation_cache.borrow().get(&name) {
            return cached_interpretation.clone();
        }

        let interpretation = match self.interpret_type_miss(name, ty) {
            Ok(SI::Scalar(SS::Counter(uom))) => Ok(SI::Scalar(SS::Counter(
                self.object_uoms.get(name).cloned().or(uom),
            ))),
            Ok(SI::Scalar(SS::Gauge(uom))) => Ok(SI::Scalar(SS::Gauge(
                self.object_uoms.get(name).cloned().or(uom),
            ))),
            Ok(SI::Scalar(SS::Integer(uom))) => Ok(SI::Scalar(SS::Integer(
                self.object_uoms.get(name).cloned().or(uom),
            ))),
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
    ) -> Result<SMIInterpretation, InterpretationError> {
        use BuiltinType as BI;
        use PlainType as PI;
        use SMIInterpretation as SI;
        use SMIScalar as SS;
        use SMIWellKnown as SWK;

        match &decl_type.ty {
            PI::Builtin(BI::SequenceOf(elem_type)) => match &elem_type.ty {
                PI::Referenced(referent_name, _) => {
                    // A SEQUENCE OF some referenced type which is effectively a SEQUENCE is an
                    // SNMP table. interpret_table will fail if the referent isn't a SEQUENCE.
                    Ok(SI::Table(self.interpret_table(name, referent_name)?))
                }
                PI::Builtin(builtin) => Err(InterpretationError::InvalidSequenceOfBuiltin {
                    element_type: builtin.clone(),
                }),
            },

            PI::Referenced(referent_name, named_vals) => {
                match SMI_WELL_KNOWN_TYPES.get(referent_name.local_name()) {
                    // Referenced types which are well-known Integer32 or BITS types that have named
                    // values are enumerations.
                    Some(SWK::Integer32) | Some(SWK::Bits) if named_vals.is_some() => {
                        Ok(SI::Scalar(SS::Enumeration(
                            named_vals
                                .as_ref()
                                .unwrap()
                                .iter()
                                .map(|(n, v)| (v.clone(), n.clone()))
                                .collect(),
                        )))
                    }

                    // Referenced types that are any other well-known type are scalars.
                    Some(other_wkt) => Ok(SI::Scalar((*other_wkt).into())),

                    None => match &self.find_effective_type(&decl_type) {
                        // Referenced types that are effectively a SEQUENCE are table rows. This is
                        // handled here instead of in the penultimate clause because effective type
                        // will be a plain type def and won't have an OID we can use to find the parent
                        // table.
                        Type {
                            ty: PI::Builtin(BI::Sequence(_)),
                            ..
                        } => Ok(SI::TableRow(
                            self.interpret_table_entry(&name, referent_name)
                                .ok_or(InterpretationError::LegacyUnknown)?,
                        )),

                        // Referenced types that aren't well-known, and whose effective type is
                        // identical to this type, aren't interpretable. Without bailing out here
                        // specifically, the next clause will match and infintely recur.
                        Type {
                            ty: PI::Referenced(effective_referent_name, _),
                            ..
                        } if effective_referent_name == referent_name => {
                            Err(InterpretationError::UnresolvableReferencedType {
                                referent: referent_name.clone(),
                            })
                        }

                        // Referenced types that have effective type that is NOT a reference are
                        // interpreted recursively (i.e. as the interpretation of the effective type).
                        non_referenced_type => {
                            self.interpret_type(&referent_name, &non_referenced_type)
                        }
                    },
                }
            }

            // Built-in INTEGER with named values is an enumeration.
            PI::Builtin(BI::Integer(Some(named_vals))) => Ok(SI::Scalar(SS::Enumeration(
                named_vals
                    .iter()
                    .map(|(n, v)| (v.clone(), n.clone()))
                    .collect(),
            ))),

            // Other primitive built-ins (including INTEGER with no named values) are themselves.
            PI::Builtin(BI::Integer(None)) => Ok(SI::Scalar(SS::Integer(None))),
            PI::Builtin(BI::ObjectIdentifier) => Ok(SI::Scalar(SS::ObjectIdentifier)),
            PI::Builtin(BI::OctetString) => Ok(SI::Scalar(SS::Bytes)),

            // These theoretically don't occur in SMI, so don't interpret them.
            PI::Builtin(BI::Sequence(_))
            | PI::Builtin(BI::Boolean)
            | PI::Builtin(BI::Choice(_))
            | PI::Builtin(BI::Null) => Err(InterpretationError::LegacyUnknown),
        }
    }

    fn interpret_table(
        &self,
        table_name: &Identifier,
        entry_type_name: &Identifier,
    ) -> Result<SMITable, InterpretationError> {
        let table_num_oid = self.object_numeric_oids.get(table_name).ok_or_else(|| {
            InterpretationError::MissingNumericOID {
                name: table_name.clone(),
            }
        })?;
        let table_object = IdentifiedObj::new(table_num_oid.clone(), table_name.clone());
        let table_subtrie = self
            .numeric_oid_names
            .get_node(table_num_oid)
            .expect("presence in object_numeric_oids guarantees a subtrie in numeric_oid_names");
        let (fragment, table_entry_name) =
            table_subtrie
                .iter()
                .nth(1)
                .ok_or_else(|| InterpretationError::MissingTableEntry {
                    table: table_object.clone(),
                })?;
        let entry_num_oid = table_num_oid.index_by_fragment(fragment);

        let field_interpretation = self.interpret_table_fields(&table_entry_name)?;

        let empty_index = vec![];
        let effective_index_fields = match self.object_indexes.get(&table_entry_name) {
            Some(TableIndexing::Index(cols)) => cols,
            Some(TableIndexing::Augments(name)) => match self.object_indexes.get(&name) {
                Some(TableIndexing::Index(cols)) => cols,
                Some(TableIndexing::Augments(_)) | None => {
                    return Err(InterpretationError::TableAugmentsTargetBad {
                        target: name.clone(),
                    })
                }
            },
            None => &empty_index,
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

        Ok(SMITable {
            table_object,
            entry_object: IdentifiedObj::new(entry_num_oid, table_entry_name.clone()),
            entry_type_name: entry_type_name.clone(),
            field_interpretation,
            index_fields,
        })
    }

    fn interpret_table_fields(
        &self,
        table_entry_name: &Identifier,
    ) -> Result<BTreeMap<IdentifiedObj, SMIInterpretation>, InterpretationError> {
        let table_fields = self
            .type_defs
            .get(table_entry_name)
            .and_then(|entry_type| self.get_fields_if_sequence_type(entry_type))
            .ok_or_else(|| InterpretationError::InvalidSequenceOfReferent {
                referent: table_entry_name.clone(),
            })?;
        let mut field_interpretations = BTreeMap::new();
        for (field_name, _) in table_fields {
            let field_type = self.type_defs.get(&field_name).ok_or_else(|| {
                InterpretationError::MissingTableFieldType {
                    field_name: field_name.clone(),
                }
            })?;
            let field_num_oid = self.object_numeric_oids.get(&field_name).ok_or_else(|| {
                InterpretationError::MissingNumericOID {
                    name: field_name.clone(),
                }
            })?;
            let interp = self.interpret_type(&field_name, &field_type)?;
            field_interpretations.insert(
                IdentifiedObj::new(field_num_oid.clone(), field_name),
                interp,
            );
        }
        Ok(field_interpretations)
    }

    fn interpret_table_entry(
        &self,
        table_entry_name: &Identifier,
        entry_type_name: &Identifier,
    ) -> Option<SMITable> {
        let entry_num_oid = self.object_numeric_oids.get(table_entry_name)?;
        let table_name = self
            .numeric_oid_names
            .get(&entry_num_oid[..(entry_num_oid.len().checked_sub(1)?)])?;
        self.interpret_table(table_name, entry_type_name).ok()
    }

    fn get_fields_if_sequence_type(
        &self,
        ty: &Type<Identifier>,
    ) -> Option<Vec<(Identifier, Type<Identifier>)>> {
        use BuiltinType as BI;
        use PlainType as PI;
        match &self.find_effective_type(ty).ty {
            PI::Builtin(BI::Sequence(fields)) => Some(fields.iter().cloned().collect()),
            _ => None,
        }
    }

    fn find_effective_type(&self, given_type: &Type<Identifier>) -> Type<Identifier> {
        let mut effective_type = given_type.clone();

        // Track the names of visited referents to detect circular definitions. TODO: This should
        // be an error; for now just break out somewhere to stop interpretation from hanging.
        let mut visited_referent_names = BTreeSet::new();

        loop {
            let new_effective_type =
                if let PlainType::Referenced(ref referent_name, _) = effective_type.ty {
                    // If the current effective_type is a reference, check if it's an SMI well-known
                    // type. Otherwise, try to dereference it into new_effective_type.
                    if SMI_WELL_KNOWN_TYPES
                        .get(referent_name.local_name())
                        .is_some()
                    {
                        None
                    } else if !visited_referent_names.insert(referent_name.clone()) {
                        None
                    } else {
                        self.type_defs.get(&referent_name)
                    }
                } else {
                    // The current effective_type is a Builtin type. We're done.
                    None
                };

            // If the dereference into new_effective_type worked, update effective_type and go
            // around again. Otherwise effective_type is as good as we can do, so break and return
            // it.
            match new_effective_type {
                Some(new) => {
                    // TODO: constraint should be intersected
                    effective_type.ty = new.ty.clone();
                }
                None => {
                    break;
                }
            }
        }

        effective_type
    }
}
