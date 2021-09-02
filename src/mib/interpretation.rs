use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt::Debug;

use num::BigInt;

use crate::mib::smi_well_known::SMIWellKnown;
use crate::types::{IdentifiedObj, Identifier, IntoOidExpr, NumericOid, OidExpr};

/// Describes how an object should be interpreted in terms of an SMIv2 logical model.
///
/// In the case of this crate, the SMI model is composed of a few kinds of things: namespaces,
/// scalars, tables, table rows, and table cells. Other kinds of things may exist in the MIB module
/// declaration which either don't have an SMI interpretation or aren't (yet) supported by this
/// crate; these are `Unknown`.
#[derive(Clone, Debug, PartialEq)]
pub enum SMIInterpretation {
    /// The object is interpretable as an OID namespace. The data member is a set of
    /// [`IdentifiedObj`] values which are the immediate children of the namespace.
    Namespace(BTreeSet<IdentifiedObj>),

    /// The object is interpretable as a scalar value. The [`SMIScalar`] data member describes the
    /// scalar value's type in more detail.
    Scalar(SMIScalar),

    /// The object is interpretable as a table. The [`SMITable`] data member describes the table's
    /// schema in more detail, including row type, columns, and indexing.
    Table(SMITable),

    /// The object is interpretable as a table row. The [`SMITable`] data member describes the
    /// row's parent table (i.e. it is the same data you would obtain in the `Table` interpretation
    /// of the parent table object).
    TableRow(SMITable),

    /// The object is interpretable as a table cell. The [`SMITableCell`] data member describes the
    /// interpretation of the scalar value in that cell, the table it is a member of, and the
    /// values for the table indices decoded from the object's OID.
    TableCell(SMITableCell),

    /// The object doesn't have an interpretation in SMI, or its interpretation is not (yet)
    /// supported by this crate.
    Unknown,
}

/// Describes a SMI scalar value.
///
/// The actual declared type of the object is dereferenced and expanded as necessary until it is
/// expressible in terms of a few either basic primitive ASN.1 types, or well-known SMI types,
/// which are represented by variants here. In cases where several distinct well-known or primitive
/// types are semantically identical but only differ by size or width, they are collapsed into one
/// representative variant --- for example, there is only one `Integer` variant.
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

#[derive(Debug, Clone, PartialEq)]
pub struct SMITable {
    pub table_object: IdentifiedObj,
    pub entry_object: IdentifiedObj,
    pub entry_type_name: Identifier,
    pub field_interpretation: BTreeMap<IdentifiedObj, SMIInterpretation>,
    pub index_fields: Vec<(IdentifiedObj, TableIndexEncoding)>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TableIndexEncoding {
    Normal,
    Implied,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SMITableCell {
    pub cell_interpretation: SMIScalar,
    pub table: SMITable,
    pub instance_indices: Vec<(IdentifiedObj, TableIndexValue)>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TableIndexValue {
    Integer(BigInt),
    EnumVariant(BigInt, String),
    InetAddress(InetAddress),
    ObjectIdentifier(OidExpr),
}

impl From<bool> for TableIndexEncoding {
    fn from(is_implied: bool) -> Self {
        match is_implied {
            true => TableIndexEncoding::Implied,
            false => TableIndexEncoding::Normal,
        }
    }
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
pub enum InetAddress {
    IP(std::net::IpAddr),
    ZonedIP(std::net::IpAddr, u32),
    Hostname(String),
    Unknown(Vec<u8>),
}

impl SMIScalar {
    pub(crate) fn decode_from_num_oid(
        &self,
        mut fragment_iter: impl Iterator<Item = u32>,
        _encoding: TableIndexEncoding,
    ) -> Option<TableIndexValue> {
        use InetAddressEncoding as Enc;
        use SMIScalar as SS;
        use TableIndexValue as TIV;
        match self {
            SS::Bits(_names) => None,
            SS::Bytes => None,
            SS::Counter(_) => None,
            SS::Enumeration(variants) => {
                let value = fragment_iter.next()?.into();
                let name = variants.get(&value)?;
                Some(TIV::EnumVariant(value, name.to_string()))
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

    fn decode_ipv4_from_num_oid(
        fragment_iter: impl Iterator<Item = u32>,
    ) -> Option<TableIndexValue> {
        use TableIndexValue as TIV;
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
