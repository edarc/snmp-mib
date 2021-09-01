pub mod interpretation;
pub mod linker;
pub mod smi_well_known;

use std::collections::BTreeMap;
use std::fmt::Debug;

use sequence_trie::SequenceTrie;

use crate::loader::Loader;
use crate::mib::interpretation::{SMIInterpretation, SMITableCell, TableIndexVal};
use crate::mib::linker::{InternalObjectDescriptor, Linker};
use crate::parser::asn_type::Type;
use crate::types::{IdentifiedObj, Identifier, IntoOidExpr, NumericOid, OidExpr};

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
