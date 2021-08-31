use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt::Debug;

use lazy_static::lazy_static;
use num::BigInt;
use sequence_trie::SequenceTrie;

use crate::loader::{Loader, QualifiedDecl, TableIndexing};
use crate::parser::{BuiltinType, PlainType, Type};
use crate::{IdentifiedObj, Identifier, IntoOidExpr, NumericOid, OidExpr};

lazy_static! {
    static ref SMI_WELL_KNOWN_TYPES: HashMap<&'static str, SMIWellKnown> = [
        // RFCs 1155, 2578
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
        // RFC 2578
        ("BITS", SMIWellKnown::Bits),
        // RFC 3291
        ("InetAddress", SMIWellKnown::InetAddress),
    ]
    .iter()
    .cloned()
    .collect();
}

#[derive(Clone, Debug, Copy)]
pub enum SMIWellKnown {
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
    Bits,
    InetAddress,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SMIScalar {
    Bits(HashMap<BigInt, String>),
    Bytes,
    Counter(Option<String>),
    Enumeration(HashMap<BigInt, String>),
    Gauge(Option<String>),
    Integer(Option<String>),
    InetAddress(InetAddressEncoding),
    ObjectIdentifier,
    Text,
    TimeTicks,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InetAddressEncoding {
    RFC1155,
    RFC3291,
}

impl From<SMIWellKnown> for SMIScalar {
    fn from(swk: SMIWellKnown) -> Self {
        use SMIScalar as SS;
        use SMIWellKnown as SWK;
        match swk {
            SWK::Counter => SS::Counter(None),
            SWK::Counter32 => SS::Counter(None),
            SWK::Counter64 => SS::Counter(None),
            SWK::DisplayString => SS::Text,
            SWK::Gauge => SS::Gauge(None),
            SWK::Gauge32 => SS::Gauge(None),
            SWK::Integer32 => SS::Integer(None),
            SWK::IpAddress => SS::InetAddress(InetAddressEncoding::RFC1155),
            SWK::Opaque => SS::Bytes,
            SWK::TimeTicks => SS::TimeTicks,
            SWK::Unsigned32 => SS::Integer(None),
            SWK::Bits => SS::Integer(None),
            SWK::InetAddress => SS::InetAddress(InetAddressEncoding::RFC3291),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum SMIInterpretation {
    Namespace(BTreeSet<IdentifiedObj>),
    Scalar(SMIScalar),
    Table(SMITable),
    TableRow(SMITable),
    TableCell(SMITableCell),
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SMITable {
    table_object: IdentifiedObj,
    entry_object: IdentifiedObj,
    entry_type_name: Identifier,
    field_interpretation: BTreeMap<IdentifiedObj, SMIInterpretation>,
    indexing: Vec<(IdentifiedObj, TableIndexEncoding)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SMITableCell {
    cell_interpretation: SMIScalar,
    table: SMITable,
    indices: Vec<(IdentifiedObj, TableIndexVal)>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TableIndexVal {
    Integer(BigInt),
    Enumeration(BigInt, String),
    InetAddress(InetAddress),
    ObjectIdentifier(OidExpr),
}

#[derive(Clone, Debug, PartialEq)]
pub enum InetAddress {
    IP(std::net::IpAddr),
    ZonedIP(std::net::IpAddr, u32),
    Hostname(String),
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TableIndexEncoding {
    Normal,
    Implied,
}

impl From<bool> for TableIndexEncoding {
    fn from(is_implied: bool) -> Self {
        match is_implied {
            true => TableIndexEncoding::Implied,
            false => TableIndexEncoding::Normal,
        }
    }
}

impl SMIScalar {
    fn decode_from_num_oid(
        &self,
        mut fragment_iter: impl Iterator<Item = u32>,
        encoding: TableIndexEncoding,
    ) -> Option<TableIndexVal> {
        use InetAddressEncoding as Enc;
        use SMIScalar as SS;
        use TableIndexVal as TIV;
        match self {
            SS::Bits(_names) => None,
            SS::Bytes => None,
            SS::Counter(_) => None,
            SS::Enumeration(variants) => {
                let value = fragment_iter.next()?.into();
                let name = variants.get(&value)?;
                Some(TIV::Enumeration(value, name.to_string()))
            }
            SS::Gauge(_) => None,
            SS::Integer(_) => fragment_iter.next().map(|v| TIV::Integer(v.into())),
            SS::InetAddress(encoding) => match encoding {
                Enc::RFC1155 => Self::decode_ipv4_from_num_oid(fragment_iter),
                Enc::RFC3291 => {
                    // TODO: This is a terrible heuristic.
                    let bytes = Self::decode_bytes_from_num_oid(fragment_iter)?;
                    match bytes.len() {
                        4 => {
                            let mut octets = [0u8; 4];
                            octets.copy_from_slice(&bytes);
                            Some(TIV::InetAddress(InetAddress::IP(octets.into())))
                        }
                        16 => {
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&bytes);
                            Some(TIV::InetAddress(InetAddress::IP(octets.into())))
                        }
                        _ => None,
                    }
                }
            },
            SS::ObjectIdentifier => {
                let fragment = Self::decode_length_encoded_from_num_oid(fragment_iter)?;
                let oidexpr = NumericOid::from(fragment).into_oid_expr()?;
                Some(TIV::ObjectIdentifier(oidexpr))
            }
            SS::Text => None,
            SS::TimeTicks => None,
        }
    }

    fn decode_ipv4_from_num_oid(fragment_iter: impl Iterator<Item = u32>) -> Option<TableIndexVal> {
        use TableIndexVal as TIV;
        let mut octet_iter = fragment_iter.take(4);
        let mut octets = [0u8; 4];
        // TODO: Handle try_into failing or iterator coming up short.
        octets.fill_with(|| {
            octet_iter
                .next()
                .and_then(|v| v.try_into().ok())
                .unwrap_or(0)
        });
        Some(TIV::InetAddress(InetAddress::IP(octets.into())))
    }

    fn decode_bytes_from_num_oid(fragment_iter: impl Iterator<Item = u32>) -> Option<Vec<u8>> {
        Self::decode_length_encoded_from_num_oid(fragment_iter).map(|vals| {
            vals.into_iter()
                .filter_map(|val| val.try_into().ok())
                .collect()
        })
    }

    fn decode_length_encoded_from_num_oid(
        mut fragment_iter: impl Iterator<Item = u32>,
    ) -> Option<Vec<u32>> {
        let count = fragment_iter.next()?;
        Some(fragment_iter.take(count.try_into().ok()?).collect())
    }
}

#[derive(Clone, Debug)]
pub struct ObjectDescriptor {
    pub object: IdentifiedObj,
    pub declared_type: Option<Type<Identifier>>,
    pub smi_interpretation: SMIInterpretation,
}

#[derive(Clone, Debug)]
pub struct MIB {
    numeric_oid_names: SequenceTrie<u32, InternalObjectDescriptor>,
    by_name: BTreeMap<Identifier, NumericOid>,
}

impl MIB {
    /// Look up any `OidExpr` and translate it to a maximally-specific `OidExpr`.
    ///
    /// The returned `OidExpr`'s parent will be whichever identifier known to this MIB matches the
    /// largest prefix of the given `OidExpr`. The fragment will contain any suffix for which the
    /// MIB does not define a name.
    pub fn lookup_best_oidexpr(&self, expr: impl IntoOidExpr) -> Option<OidExpr> {
        let num_oid = self.lookup_numeric_oid(expr)?;
        self.lookup_best_oidexpr_internal(&num_oid)
            .map(|(_, oidexpr)| oidexpr)
    }

    fn lookup_best_oidexpr_internal(&self, num_oid: &NumericOid) -> Option<(NumericOid, OidExpr)> {
        // Decrement to skip the root.
        let prefix_len = self.numeric_oid_names.prefix_iter(num_oid).count() - 1;
        let (parent_num_oid, fragment) = num_oid.split_at(prefix_len);
        let parent = self.numeric_oid_names.get(parent_num_oid)?;
        Some((
            parent_num_oid.into(),
            OidExpr {
                parent: parent.name.clone(),
                fragment: fragment.into(),
            },
        ))
    }

    pub fn lookup_numeric_oid(&self, expr: impl IntoOidExpr) -> Option<NumericOid> {
        let expr = expr.into_oid_expr()?;
        let oid = self
            .by_name
            .get(&expr.parent)?
            .index_by_fragment(&expr.fragment);
        Some(oid)
    }

    pub fn describe_object(&self, expr: impl IntoOidExpr) -> Option<ObjectDescriptor> {
        use SMIInterpretation as SI;

        let num_oid = self.lookup_numeric_oid(expr)?;
        let (parent_num_oid, best_expr) = self.lookup_best_oidexpr_internal(&num_oid)?;
        let int_descr = self.numeric_oid_names.get(&parent_num_oid)?;

        let interpretation = if let SI::Scalar(cell_scalar) = &int_descr.smi_interpretation {
            let parent_descr = self.describe_object(&parent_num_oid.parent());
            if let Some(ObjectDescriptor {
                smi_interpretation: SI::TableRow(table),
                ..
            }) = parent_descr
            {
                let mut fragment = best_expr.fragment.into_iter();
                println!("{:?}", fragment);
                let mut indices = vec![];

                for (index, encoding) in table.indexing.iter() {
                    let decoded_value = match table.field_interpretation.get(&index) {
                        Some(SI::Scalar(scalar_type)) => {
                            match scalar_type.decode_from_num_oid(&mut fragment, *encoding) {
                                Some(TableIndexVal::ObjectIdentifier(oidexpr)) => {
                                    TableIndexVal::ObjectIdentifier(
                                        self.lookup_best_oidexpr(&oidexpr).unwrap_or(oidexpr),
                                    )
                                }
                                Some(scalar_val) => scalar_val,
                                None => break,
                            }
                        }

                        _ => return None,
                    };
                    indices.push((index.clone(), decoded_value));
                }

                SI::TableCell(SMITableCell {
                    cell_interpretation: cell_scalar.clone(),
                    table,
                    indices,
                })
            } else {
                int_descr.smi_interpretation.clone()
            }
        } else {
            int_descr.smi_interpretation.clone()
        };

        Some(ObjectDescriptor {
            object: IdentifiedObj::new(parent_num_oid, int_descr.name.clone()),
            declared_type: int_descr.declared_type.clone(),
            smi_interpretation: interpretation,
        })
    }
}

impl From<Loader> for MIB {
    fn from(loader: Loader) -> Self {
        let linker = Linker::new(loader.0);

        let mut numeric_oid_names = SequenceTrie::new();
        let mut by_name = BTreeMap::new();

        for (name, oid) in linker.object_numeric_oids.iter() {
            numeric_oid_names.insert(oid, linker.make_entry(&name));
            by_name.insert(name.clone(), oid.clone());
        }

        Self {
            numeric_oid_names,
            by_name,
        }
    }
}

struct Linker {
    pub numeric_oid_names: SequenceTrie<u32, Identifier>,
    pub object_indexes: BTreeMap<Identifier, TableIndexing>,
    pub object_numeric_oids: BTreeMap<Identifier, NumericOid>,
    pub object_oidexpr_defs: BTreeMap<Identifier, OidExpr>,
    pub object_uoms: BTreeMap<Identifier, String>,
    pub orphan_identifiers: BTreeSet<Identifier>,
    pub type_defs: BTreeMap<Identifier, Type<Identifier>>,
    type_interpretation_cache: RefCell<BTreeMap<Identifier, SMIInterpretation>>,
}

#[derive(Clone, Debug)]
struct InternalObjectDescriptor {
    pub name: Identifier,
    pub declared_type: Option<Type<Identifier>>,
    pub smi_interpretation: SMIInterpretation,
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
                OidExpr {
                    parent: Identifier::root(),
                    fragment: [1].into(),
                },
            ))
            .into_iter()
            .collect(),
            object_uoms: BTreeMap::new(),
            orphan_identifiers: BTreeSet::new(),
            type_defs: BTreeMap::new(),
            type_interpretation_cache: RefCell::new(BTreeMap::new()),
        }
    }

    fn new<'a>(decls: impl IntoIterator<Item = QualifiedDecl>) -> Self {
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
        let linked_def = if def.parent.is_root() {
            // The parent is root, so this def is linked already.
            def.clone()
        } else if let Some(parent_fragment) = abs.get(&def.parent) {
            // Parent is linked. Link this one by indexing the parent by this fragment.
            let this_fragment = parent_fragment.index_by_fragment(&def.fragment);
            OidExpr {
                parent: Identifier::root(),
                fragment: this_fragment.to_vec().into(),
            }
        } else if let Some(parent_def) = rel.get(&def.parent) {
            // Parent is not linked. Recursively link it first.
            let linked_parent_fragment =
                Self::link_oidexpr_to_numeric_oid(&def.parent, parent_def, rel, abs)?
                    .index_by_fragment(&def.fragment);
            OidExpr {
                parent: Identifier::root(),
                fragment: linked_parent_fragment.to_vec().into(),
            }
        } else {
            // This def's parent is not root, and was in neither the rel or abs maps, so there is
            // no path to root. Throw this def's parent as an Err indicating which identifier is
            // orphaned.
            return Err(def.parent.clone());
        };

        abs.insert(name.clone(), linked_def.fragment.to_vec().into());
        Ok(linked_def.fragment.to_vec().into())
    }

    pub fn make_entry(&self, name: &Identifier) -> InternalObjectDescriptor {
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
                .get(referent_name.1.as_str())
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

        let effective_indexing = match self.object_indexes.get(&table_entry_name)? {
            TableIndexing::Index(cols) => cols,
            TableIndexing::Augments(name) => match self.object_indexes.get(&name)? {
                TableIndexing::Index(cols) => cols,
                _ => return None,
            },
        };
        let indexing = effective_indexing
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
            indexing,
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
                if SMI_WELL_KNOWN_TYPES.get(referent_name.1.as_str()).is_some() {
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
