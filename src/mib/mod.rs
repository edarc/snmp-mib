//! The SNMP Management Information Base itself.

mod interpretation;
mod linker;
mod smi_well_known;

pub use crate::mib::interpretation::{
    InetAddress, InetAddressEncoding, SMIInterpretation, SMIScalar, SMITable, SMITableCell,
    TableIndexEncoding, TableIndexValue,
};

use std::collections::BTreeMap;
use std::fmt::Debug;

use sequence_trie::SequenceTrie;

use crate::error::{IndexDecodeError, LookupError};
use crate::loader::Loader;
use crate::mib::linker::{InternalObjectDescriptor, Linker};
use crate::parser::asn_type::Type;
use crate::types::{IdentifiedObj, Identifier, Indexable, IntoOidExpr, NumericOid, OidExpr};

/// A description of an object in the MIB.
///
/// The `ObjectDescriptor` includes the identifier of the object, its ASN.1 declared type, plus the
/// interpretation of that type in terms of SMIv2. These are obtained using `MIB::describe_object`.
#[derive(Clone, Debug)]
pub struct ObjectDescriptor {
    /// The object's OID, both as an identifier and numerically.
    ///
    /// This field allows an object to be described based on any OID expression, and this field
    /// will contain both the canonical name and the numeric OID.
    pub object: IdentifiedObj,

    /// The declared type of the object as an ASN.1 type, if it has one.
    ///
    /// This will be a parsed version of the exact ASN.1 type the object is declared as in the MIB.
    /// If that declared type is or contains references to other types defined in the MIB; they are
    /// not dereferenced or expanded in this field.
    ///
    /// Some objects do not have a declared type, for example OIDs that are declared as namespaces
    /// for other OIDs. For such objects, this field will be `None`.
    pub declared_type: Option<Type<Identifier>>,

    /// The interpretation of this field in terms of SMI.
    ///
    /// The SMI interpretation is a value describing the meaning of the declared type of this
    /// object, after dereferencing and expansion of the declared ASN.1 type.
    pub smi_interpretation: SMIInterpretation,
}

/// An SNMP Management Information Base.
///
/// A `MIB` is obtained by using a [`Loader`] to load the MIB module definitions of interest and
/// then compiling them by calling `.into()`. The resultant `MIB` contains the main API for
/// utilizing the compiled information.
#[derive(Clone, Debug)]
pub struct MIB {
    oid_descriptor_tree: SequenceTrie<u32, InternalObjectDescriptor>,
    identifier_table: BTreeMap<Identifier, Result<NumericOid, LookupError>>,
}

impl MIB {
    /// Look up anything convertible to an [`OidExpr`], and translate it to a maximally-specific
    /// `OidExpr`.
    ///
    /// While any named identifiers in the OID expression must be known to this MIB, the exact
    /// object referred to by some or all of a numeric suffix need not be. The returned `OidExpr`'s
    /// parent will be whichever identifier known to this MIB matches the largest prefix of the
    /// given `OidExpr`. The fragment will contain any suffix for which the MIB does not define a
    /// name.
    pub fn lookup_best_oidexpr(&self, expr: impl IntoOidExpr) -> Result<OidExpr, LookupError> {
        let num_oid = self.lookup_numeric_oid(expr)?;
        self.lookup_best_oidexpr_internal(&num_oid)
            .map(|(_, oidexpr)| oidexpr)
    }

    fn lookup_best_oidexpr_internal(
        &self,
        num_oid: &NumericOid,
    ) -> Result<(NumericOid, OidExpr), LookupError> {
        // Decrement to skip the root.
        let prefix_len = self.oid_descriptor_tree.prefix_iter(num_oid).count() - 1;
        let (parent_num_oid, fragment) = num_oid.split_at(prefix_len);
        let parent = self
            .oid_descriptor_tree
            .get(parent_num_oid)
            .ok_or_else(|| LookupError::NoSuchNumericOID {
                oid: parent_num_oid.into(),
            })?;
        Ok((
            parent_num_oid.into(),
            parent.name.index_by_fragment(fragment),
        ))
    }

    /// Look up anything convertible to an [`OidExpr`], and translate it to an equivalent
    /// [`NumericOid`].
    ///
    /// While any named identifiers in the OID expression must be known to this MIB, the exact
    /// object referred to by some or all of a numeric suffix need not be.
    pub fn lookup_numeric_oid(&self, expr: impl IntoOidExpr) -> Result<NumericOid, LookupError> {
        let expr = expr.into_oid_expr();
        let oid = self
            .identifier_table
            .get(expr.base_identifier())
            .ok_or_else(|| LookupError::NoSuchIdentifier {
                identifier: expr.base_identifier().clone(),
            })?
            .as_ref()
            .map_err(Clone::clone)?
            .index_by_fragment(expr.fragment());
        Ok(oid)
    }

    /// Look up a descriptor for an object identified by (anything convertible to) an [`OidExpr`].
    ///
    /// See [`ObjectDescriptor`] for details.
    pub fn describe_object(&self, expr: impl IntoOidExpr) -> Result<ObjectDescriptor, LookupError> {
        use SMIInterpretation as SI;

        let num_oid = self.lookup_numeric_oid(expr)?;
        let (parent_num_oid, best_expr) = self.lookup_best_oidexpr_internal(&num_oid)?;
        let internal_descr = self.oid_descriptor_tree.get(&parent_num_oid).expect(
            "lookup_best_oidexpr_internal guarantees parent_num_oid can be gotten from \
             oid_descriptor_tree",
        );

        let interpretation = if let SI::Scalar(cell_scalar) = &internal_descr.smi_interpretation {
            // If the internal descriptor's interpretation is a Scalar, check the interpretation of
            // the parent OID. It might be a TableRow, in which case the interpretation of this is
            // not just Scalar but specifically a TableCell.
            match self.describe_object(parent_num_oid.parent()) {
                Ok(ObjectDescriptor {
                    smi_interpretation: SI::TableRow(table),
                    ..
                }) => {
                    // The parent is a TableRow, so decode any table index values that are present in
                    // the fragment and re-interpret this as TableCell.
                    let fragment = best_expr.fragment().into_iter().copied();
                    let instance_indices = self.decode_table_cell_indices(fragment, &table)?;
                    SI::TableCell(SMITableCell {
                        cell_interpretation: cell_scalar.clone(),
                        table,
                        instance_indices,
                    })
                }
                _ => internal_descr.smi_interpretation.clone(),
            }
        } else {
            internal_descr.smi_interpretation.clone()
        };

        Ok(ObjectDescriptor {
            object: IdentifiedObj::new(parent_num_oid, internal_descr.name.clone()),
            declared_type: internal_descr.declared_type.clone(),
            smi_interpretation: interpretation,
        })
    }

    fn decode_table_cell_indices(
        &self,
        mut fragment: impl Iterator<Item = u32>,
        table: &SMITable,
    ) -> Result<Vec<(IdentifiedObj, TableIndexValue)>, LookupError> {
        use SMIInterpretation as SI;

        let mut instance_indices = vec![];

        for (index, encoding) in table.index_fields.iter() {
            let decoded_value = match table.field_interpretation.get(&index) {
                Some(SI::Scalar(scalar_type)) => {
                    match scalar_type.decode_from_num_oid(&mut fragment, *encoding) {
                        Ok(Some(TableIndexValue::ObjectIdentifier(oidexpr))) => {
                            TableIndexValue::ObjectIdentifier(
                                self.lookup_best_oidexpr(&oidexpr).unwrap_or(oidexpr),
                            )
                        }
                        Ok(Some(scalar_val)) => scalar_val,
                        Ok(None) => break,
                        Err(e) => {
                            return Err(LookupError::IndexNotDecodable {
                                source: e,
                                object: index.clone(),
                            })
                        }
                    }
                }
                Some(non_scalar_type) => {
                    return Err(LookupError::IndexNotDecodable {
                        object: index.clone(),
                        source: IndexDecodeError::NonScalarType {
                            interpretation: non_scalar_type.clone(),
                        },
                    })
                }
                None => unreachable!(
                    "Linker::interpret_table guarantees index_fields never contains keys that \
                     aren't in field_interpretation"
                ),
            };
            instance_indices.push((index.clone(), decoded_value));
        }
        Ok(instance_indices)
    }
}

impl From<Loader> for MIB {
    fn from(loader: Loader) -> Self {
        let linker = Linker::new(loader.0);

        let mut oid_descriptor_tree = SequenceTrie::new();
        let mut identifier_table = BTreeMap::new();

        for (name, oid) in linker.object_numeric_oids.iter() {
            oid_descriptor_tree.insert(oid, linker.make_entry(&name));
            identifier_table.insert(name.clone(), Ok(oid.clone()));
        }

        for (name, orphan_name) in linker.orphan_identifiers {
            identifier_table.insert(
                name,
                Err(LookupError::OrphanIdentifier {
                    identifier: orphan_name,
                }),
            );
        }

        Self {
            oid_descriptor_tree,
            identifier_table,
        }
    }
}
