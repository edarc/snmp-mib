use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt::Debug;

use num::BigInt;

use crate::mib::smi_well_known::SMIWellKnown;
use crate::types::identified_obj::IdentifiedObj;
use crate::types::identifier::Identifier;
use crate::types::numeric_oid::NumericOid;
use crate::types::oid_expr::{IntoOidExpr, OidExpr};

#[derive(Clone, Debug, PartialEq)]
pub enum SMIInterpretation {
    Namespace(BTreeSet<IdentifiedObj>),
    Scalar(SMIScalar),
    Table(SMITable),
    TableRow(SMITable),
    TableCell(SMITableCell),
    Unknown,
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

#[derive(Debug, Clone, PartialEq)]
pub struct SMITable {
    pub table_object: IdentifiedObj,
    pub entry_object: IdentifiedObj,
    pub entry_type_name: Identifier,
    pub field_interpretation: BTreeMap<IdentifiedObj, SMIInterpretation>,
    pub indexing: Vec<(IdentifiedObj, TableIndexEncoding)>,
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
    pub indices: Vec<(IdentifiedObj, TableIndexVal)>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TableIndexVal {
    Integer(BigInt),
    Enumeration(BigInt, String),
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
    pub fn decode_from_num_oid(
        &self,
        mut fragment_iter: impl Iterator<Item = u32>,
        _encoding: TableIndexEncoding,
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
