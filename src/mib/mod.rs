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
    numeric_oid_names: SequenceTrie<u32, InternalObjectDescriptor>,
    by_name: BTreeMap<Identifier, NumericOid>,
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
            parent.name.index_by_fragment(fragment),
        ))
    }

    /// Look up anything convertible to an [`OidExpr`], and translate it to an equivalent
    /// [`NumericOid`].
    ///
    /// While any named identifiers in the OID expression must be known to this MIB, the exact
    /// object referred to by some or all of a numeric suffix need not be.
    pub fn lookup_numeric_oid(&self, expr: impl IntoOidExpr) -> Option<NumericOid> {
        let expr = expr.into_oid_expr()?;
        let oid = self
            .by_name
            .get(expr.parent())?
            .index_by_fragment(expr.fragment());
        Some(oid)
    }

    /// Look up a descriptor for an object identified by (anything convertible to) an [`OidExpr`].
    ///
    /// See [`ObjectDescriptor`] for details.
    pub fn describe_object(&self, expr: impl IntoOidExpr) -> Option<ObjectDescriptor> {
        use SMIInterpretation as SI;

        let num_oid = self.lookup_numeric_oid(expr)?;
        let (parent_num_oid, best_expr) = self.lookup_best_oidexpr_internal(&num_oid)?;
        let int_descr = self.numeric_oid_names.get(&parent_num_oid)?;

        let interpretation = if let SI::Scalar(cell_scalar) = &int_descr.smi_interpretation {
            let parent_descr = self.describe_object(parent_num_oid.parent());
            if let Some(ObjectDescriptor {
                smi_interpretation: SI::TableRow(table),
                ..
            }) = parent_descr
            {
                let mut fragment = best_expr.fragment().into_iter().copied();
                println!("{:?}", fragment);
                let mut instance_indices = vec![];

                for (index, encoding) in table.index_fields.iter() {
                    let decoded_value = match table.field_interpretation.get(&index) {
                        Some(SI::Scalar(scalar_type)) => {
                            match scalar_type.decode_from_num_oid(&mut fragment, *encoding) {
                                Some(TableIndexValue::ObjectIdentifier(oidexpr)) => {
                                    TableIndexValue::ObjectIdentifier(
                                        self.lookup_best_oidexpr(&oidexpr).unwrap_or(oidexpr),
                                    )
                                }
                                Some(scalar_val) => scalar_val,
                                None => break,
                            }
                        }

                        _ => return None,
                    };
                    instance_indices.push((index.clone(), decoded_value));
                }

                SI::TableCell(SMITableCell {
                    cell_interpretation: cell_scalar.clone(),
                    table,
                    instance_indices,
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
