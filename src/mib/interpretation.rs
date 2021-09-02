use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryInto;
use std::fmt::Debug;

use num::BigInt;

use crate::mib::smi_well_known::SMIWellKnown;
use crate::types::{IdentifiedObj, Identifier, IntoOidExpr, NumericOid, OidExpr};

/// Describes how an object should be interpreted in terms of an SMIv2 logical model.
///
/// For the purposeses of this crate, the SMI model is composed of a few kinds of things:
/// namespaces, scalars, tables, table rows, and table cells. These logical concepts are expressed
/// by patterns in their MIB module ASN.1 definitions, which `snmp-mib` recognizes and translates
/// into a higher-level `SMIInterpretation`.
///
/// Other kinds of things may exist in the MIB module declaration which are valid ASN.1, but either
/// don't have an SMI interpretation or aren't (yet) supported by this crate; these are `Unknown`.
#[derive(Clone, Debug, PartialEq)]
pub enum SMIInterpretation {
    /// The object is interpretable as an OID namespace. The data member is a set of
    /// [`IdentifiedObj`] values which are the immediate children of the namespace.
    ///
    /// ## Example
    ///
    /// Assuming a [`MIB`][crate::mib::MIB] with the `UPS-MIB` module and all of its dependencies
    /// loaded, requesting the interpretation for `UPS-MIB::upsObjects`:
    ///
    /// ```ignore
    /// mib.describe_object("UPS-MIB::upsObjects").unwrap().smi_interpretation
    /// ```
    ///
    /// Would yield a structure like this (formatted for clarity):
    ///
    /// ```text
    /// Namespace({
    ///     IdentifiedObj("UPS-MIB::upsIdent" = 1.3.6.1.2.1.33.1.1),
    ///     IdentifiedObj("UPS-MIB::upsBattery" = 1.3.6.1.2.1.33.1.2),
    ///     IdentifiedObj("UPS-MIB::upsInput" = 1.3.6.1.2.1.33.1.3),
    ///     IdentifiedObj("UPS-MIB::upsOutput" = 1.3.6.1.2.1.33.1.4),
    ///     IdentifiedObj("UPS-MIB::upsBypass" = 1.3.6.1.2.1.33.1.5),
    ///     IdentifiedObj("UPS-MIB::upsAlarm" = 1.3.6.1.2.1.33.1.6),
    ///     IdentifiedObj("UPS-MIB::upsTest" = 1.3.6.1.2.1.33.1.7),
    ///     IdentifiedObj("UPS-MIB::upsControl" = 1.3.6.1.2.1.33.1.8),
    ///     IdentifiedObj("UPS-MIB::upsConfig" = 1.3.6.1.2.1.33.1.9),
    /// })
    /// ```
    Namespace(BTreeSet<IdentifiedObj>),

    /// The object is interpretable as a scalar value. The [`SMIScalar`] data member describes the
    /// scalar value's type in more detail. See that type for details and an example.
    Scalar(SMIScalar),

    /// The object is interpretable as a table. The [`SMITable`] data member describes the table's
    /// schema in more detail, including row type, columns, and indexing. See that type for details
    /// and an example.
    Table(SMITable),

    /// The object is interpretable as a table row. The [`SMITable`] data member describes the
    /// row's parent table (i.e. it is the same data you would obtain in the `Table` interpretation
    /// of the parent table object). See that type for details and an example.
    TableRow(SMITable),

    /// The object is interpretable as a table cell. The [`SMITableCell`] data member describes the
    /// interpretation of the scalar value in that cell, the table it is a member of, and the
    /// values for the table indices decoded from the object's OID. See that type for details and
    /// an example.
    TableCell(SMITableCell),

    /// The object doesn't have an interpretation in SMI, or its interpretation is not (yet)
    /// supported or recognized by this crate.
    Unknown,
}

/// Describes an SMI scalar value.
///
/// The actual declared type of the object is dereferenced and expanded as necessary until it is
/// expressible in terms of a few either basic primitive ASN.1 types, or well-known SMI types,
/// which are represented by variants here. In cases where several distinct well-known or primitive
/// types are semantically identical but only differ by size or width, they are collapsed into one
/// representative variant --- for example, there is only one `Integer` variant.
///
/// ## Example
///
/// Assuming a [`MIB`][crate::mib::MIB] with the `IP-MIB` module and all of its dependencies
/// loaded, requesting the interpretation for `IP-MIB::ipForwarding`:
///
/// ```ignore
/// mib.describe_object("IP-MIB::ipForwarding").unwrap().smi_interpretation
/// ```
///
/// Would yield the value:
///
/// ```text
/// Scalar(Enumeration({
///     1: "forwarding",
///     2: "not-forwarding",
/// }))
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum SMIScalar {
    /// The scalar's type evaluates to `BITS`. The data member is a map of bit names, keyed by bit
    /// position.
    Bits(HashMap<BigInt, String>),

    /// The scalar's type evaluates to `OCTET STRING`, but is not also a well-known type alias such
    /// as `DisplayString` or `InetAddress` that has a more specific interpretation.
    Bytes,

    /// The scalar's type evaluates to a well-known counter type, such as `Counter`, `Counter32`,
    /// or `Counter64`. If the MIB module defined a unit of measure for the counter, the data
    /// member contains it as a string.
    Counter(Option<String>),

    /// The scalar's type evaluates to an enumeration, meaning any integer type (primitive or
    /// well-known) which also has named values declared. The data member is a map of the
    /// enumeration's named variants, keyed by their integer-value equivalents.
    Enumeration(HashMap<BigInt, String>),

    /// The scalar's type evaluates to a well-known gauge type, such as `Gauge` or `Gauge32`. If
    /// the MIB module defined a unit of measure for the gauge, the data member contains it as a
    /// string.
    Gauge(Option<String>),

    /// The scalar's type evaluates to an integer, either of primitive or well-known type, such as
    /// `INTEGER`, `Integer32`, or `Unsigned32`. Such an integer type must not be otherwise
    /// specified, meaning it is neither a well-known counter or gauge type, nor does it have named
    /// values declared which would make it an `Enumeration`. If the MIB module defined a unit of
    /// measure for the integer, the data member contains it as a string.
    Integer(Option<String>),

    /// The scalar's type evaluates to an internet address, such as `IpAddress` defined in RFC
    /// 1155, or `InetAddress` defined in RFC 3291. The data member specifies which of these
    /// encodings is used.
    ///
    /// > **Note**: The difference in encoding can generally be ignored by end-users, since it only
    /// > matters when this type is used as a table index; the underlying encoding for variable
    /// > binding values is `OCTET STRING` in all cases. See [`InetAddressEncoding`] for details.
    InetAddress(InetAddressEncoding),

    /// The scalar's type evaluates to an object identifier.
    ObjectIdentifier,

    /// The scalar's type evaluates to a well-known type that is interpretable as plain text, such
    /// as `DisplayString`.
    Text,

    /// The scalar's type evaluates to the well-known `TimeTicks` type, meaning an integer counting
    /// hundredths of a second.
    TimeTicks,
}

/// The encoding used for an internet address.
///
/// RFC 1155 specifies a legacy type `IpAddress` as part of SMIv2's `ObjectSyntax` that only
/// supports IPv4 addresses. RFC 3291 defines a more modern type based on `TEXTUAL-CONVENTION`
/// macro, which supports IPv4, IPv6, zoned versions of same, and DNS names.
///
/// The difference is important for table index OID encoding, where RFC 1155 `IpAddress` is encoded
/// as a 4-element OID fragment, but a RFC 3291 `InetAddress` is length-prefix encoded like an
/// `OCTET STRING` type, in order to support non-IPv4 addresses. For variable bindings, all
/// encodings are defined as `OCTET STRING`, so an IPv4 address is encoded as a binding value
/// identically in both schemes.
///
/// Therefore, in general, this distinction can be ignored since it is only significant during the
/// interpretation of the OIDs of table cells that are indexed by internet address types, a task
/// which `snmp-mib` can perform automatically.
#[derive(Debug, Clone, PartialEq)]
pub enum InetAddressEncoding {
    /// RFC 1155 `IpAddress` --- fixed-length IPv4-only encoding.
    RFC1155,
    /// RFC 3291 `InetAddress` --- length-prefixed extensible encoding.
    RFC3291,
}

/// Describes an SMI table.
///
/// A table in SMI is an object with the type `SEQUENCE OF SomeEntry` where `SomeEntry` is the
/// table entry or row type of the table. The row type must evaluate to an ASN.1 `SEQUENCE` type
/// (analogous to a struct). The field names of the table entry `SEQUENCE` refer to
/// separately-declared objects with their own OIDs that represent columns in the table.
///
/// Additionally, SMI tables generally have indexes, which are one or more columns that form a
/// composite key into the table. The type of an index column will have a defined encoding as an
/// OID suffix. Values for each index column are encoded into suffixes and appended to any column's
/// OID in order to produce descendant OIDs which uniquely identify particular rows in that column.
///
/// ## Example
///
/// Assuming a [`MIB`][crate::mib::MIB] with the `IP-MIB` module and all of its dependencies
/// loaded, requesting the interpretation for `IP-MIB::ipDefaultRouterTable`:
///
/// ```ignore
/// mib.describe_object("IP-MIB::ipDefaultRouterTable").unwrap().smi_interpretation
/// ```
///
/// Would yield a structure like this (formatted for clarity):
///
/// ```text
/// Table(
///     SMITable {
///         table_object: IdentifiedObj("IP-MIB::ipDefaultRouterTable" = 1.3.6.1.2.1.4.37),
///         entry_object: IdentifiedObj("IP-MIB::ipDefaultRouterEntry" = 1.3.6.1.2.1.4.37.1),
///         entry_type_name: Identifier("IP-MIB::IpDefaultRouterEntry"),
///         field_interpretation: {
///             IdentifiedObj("IP-MIB::ipDefaultRouterAddressType" = 1.3.6.1.2.1.4.37.1.1):
///                 Scalar(Enumeration({
///                     3: "ipv4z",
///                     2: "ipv6",
///                     16: "dns",
///                     1: "ipv4",
///                     0: "unknown",
///                     4: "ipv6z",
///                 })),
///             IdentifiedObj("IP-MIB::ipDefaultRouterAddress" = 1.3.6.1.2.1.4.37.1.2):
///                 Scalar(InetAddress(RFC3291)),
///             IdentifiedObj("IP-MIB::ipDefaultRouterIfIndex" = 1.3.6.1.2.1.4.37.1.3):
///                 Scalar(Integer(None)),
///             IdentifiedObj("IP-MIB::ipDefaultRouterLifetime" = 1.3.6.1.2.1.4.37.1.4):
///                 Scalar(Integer(Some("seconds"))),
///             IdentifiedObj("IP-MIB::ipDefaultRouterPreference" = 1.3.6.1.2.1.4.37.1.5):
///                 Scalar(Enumeration({
///                     0: "medium",
///                     1: "high",
///                     -1: "low",
///                     -2: "reserved",
///                 })),
///         },
///         index_fields: [
///             (IdentifiedObj("IP-MIB::ipDefaultRouterAddressType" = 1.3.6.1.2.1.4.37.1.1), Normal),
///             (IdentifiedObj("IP-MIB::ipDefaultRouterAddress" = 1.3.6.1.2.1.4.37.1.2), Normal),
///             (IdentifiedObj("IP-MIB::ipDefaultRouterIfIndex" = 1.3.6.1.2.1.4.37.1.3), Normal),
///         ],
///     },
/// )
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SMITable {
    /// The OID for the table object itself, both as an identifier and numerically.
    ///
    /// This is provided in case this struct is part of a `TableRow` or `TableCell` interpretation,
    /// where the table OID may not be known.
    pub table_object: IdentifiedObj,

    /// The OID for the table's entry object, both as an identifier and numerically.
    ///
    /// This is provided in case this struct is part of a `Table` or `TableCell` interpretation,
    /// where the entry OID may not be known.
    pub entry_object: IdentifiedObj,

    /// The identifier for the type of the table's entry object.
    ///
    /// Note that this is distinct from the entry object itself, as the latter has an OID and the
    /// former (being a plain ASN.1 type definition) does not. The entry object will reference this
    /// type name as its declared type.
    pub entry_type_name: Identifier,

    /// All of the columns/fields in this table and their associated SMI interpretations.
    ///
    /// Columns in a table generally have scalar interpretation, but may be `Unknown`.
    pub field_interpretation: BTreeMap<IdentifiedObj, SMIInterpretation>,

    /// The OIDs for each column in the table that serves as an index, in order.
    ///
    /// The last index may have an encoding of `Implied`, which alters the encoding of a
    /// variable-length type so that it need not be length-prefixed --- the type's length is the
    /// entire remaining suffix of the OID.
    pub index_fields: Vec<(IdentifiedObj, TableIndexEncoding)>,
}

/// Indicates whether a table index column uses `IMPLIED` encoding or normal.
///
/// This is `Normal` in almost all cases, however the final index column of a table, if it is a
/// variable-length type, may use `Implied`, which means that there is no length-prefix, the length
/// is implied to be the total remaining length of the OID suffix after decoding any prior indexes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TableIndexEncoding {
    /// Normal length-prefixed OID encoding.
    Normal,
    /// Implied-length OID encoding.
    Implied,
}

/// Describes an SMI table column or cell.
///
/// This is similar to an [`SMIScalar`], and indeed the interpretation of the scalar value is given
/// in this struct, however the object itself is known by the MIB to be a field in a table. The
/// parent table's interpretation is included in full. If the object's OID refers to a specific row
/// in the table column, then the values for that row's indices are decoded from the OID and
/// included.
///
/// ## Example
///
/// Assuming a [`MIB`][crate::mib::MIB] with the `IP-MIB` module and all of its dependencies
/// loaded, requesting the interpretation for an OID in `IP-MIB::ipDefaultRouterPreference`:
///
/// ```ignore
/// mib.describe_object("1.3.6.1.2.1.4.37.1.5.2.16.254.128\
///                      .0.0.0.0.0.0.0.0.0.0.0.0.0.0.500")
///    .unwrap()
///    .smi_interpretation
/// ```
///
/// Would yield a structure like this (formatted and abbreviated for clarity):
///
/// ```text
/// TableCell(
///     SMITableCell {
///         cell_interpretation: Enumeration({
///             1: "high",
///             -2: "reserved",
///             -1: "low",
///             0: "medium",
///         }),
///         table: SMITable {
///             table_object: IdentifiedObj("IP-MIB::ipDefaultRouterTable" = 1.3.6.1.2.1.4.37),
///             entry_object: IdentifiedObj("IP-MIB::ipDefaultRouterEntry" = 1.3.6.1.2.1.4.37.1),
///             entry_type_name: Identifier("IP-MIB::IpDefaultRouterEntry"),
///             field_interpretation: { ...elided... },
///             index_fields: [
///                 (IdentifiedObj("IP-MIB::ipDefaultRouterAddressType" = 1.3.6.1.2.1.4.37.1.1), Normal),
///                 (IdentifiedObj("IP-MIB::ipDefaultRouterAddress" = 1.3.6.1.2.1.4.37.1.2), Normal),
///                 (IdentifiedObj("IP-MIB::ipDefaultRouterIfIndex" = 1.3.6.1.2.1.4.37.1.3), Normal),
///             ],
///         },
///         instance_indices: [
///             (
///                 IdentifiedObj("IP-MIB::ipDefaultRouterAddressType" = 1.3.6.1.2.1.4.37.1.1),
///                 EnumVariant(2, "ipv6"),
///             ),
///             (
///                 IdentifiedObj("IP-MIB::ipDefaultRouterAddress" = 1.3.6.1.2.1.4.37.1.2),
///                 InetAddress(IP( fe80:: )),
///             ),
///             (
///                 IdentifiedObj("IP-MIB::ipDefaultRouterIfIndex" = 1.3.6.1.2.1.4.37.1.3),
///                 Integer(500),
///             ),
///         ],
///     },
/// ),
/// ```
///
/// In particular, note that the indexing information present in the OID is decoded, so we can see
/// that this OID refers to the `ipDefaultRouterPreference` field in a specific row of the
/// `ipDefaultRouterTable` table, identified by address type `ipv6`, the address `fe80::`, and
/// interface index 500.
#[derive(Clone, Debug, PartialEq)]
pub struct SMITableCell {
    /// The scalar interpretation of this table column or cell.
    pub cell_interpretation: SMIScalar,

    /// The interpretation of the table to which this column or cell belongs.
    pub table: SMITable,

    /// If the OID refers to a specific cell, this field will contain a decoded value for each
    /// index field in the table, corresponding to each entry in `table.index_fields`.
    ///
    /// If the OID refers to the column generally, this will be empty.
    ///
    /// If the OID contains some but not all index values, as many values as could be fully decoded
    /// will be present, and the length of this vector will be less than `table.index_fields`.
    pub instance_indices: Vec<(IdentifiedObj, TableIndexValue)>,
}

/// The value of a table index field for a table cell.
///
/// This type appears in [`SMITableCell`] for the interpretation of an OID that refers to a
/// specific table cell, and holds the decoded value for one of potentially many index fields that
/// identify the row in the table where the cell appears.
///
/// See [`SMITableCell`] for more information and a complete example.
#[derive(Clone, Debug, PartialEq)]
pub enum TableIndexValue {
    /// An integer-valued instance index. The data member contains the integral value for the index
    /// column.
    Integer(BigInt),
    /// An instance index value that represents an enumeration variant. The data members contain
    /// the integral value of the variant, and a string containing the corresponding variant name.
    EnumVariant(BigInt, String),
    /// An internet address instance index. The data member holds the decoded address.
    InetAddress(InetAddress),
    /// An object identifier instance index. The data member holds the decoded OID expression.
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

/// An internet address value.
///
/// This represents any type that is representable in either an RFC 1155 `IpAddress` type, or an
/// RFC 3291 `InetAddress` type.
///
/// > **Note**: Not all of these variants are currently implemented.
#[derive(Clone, Debug, PartialEq)]
pub enum InetAddress {
    /// An IPv4 or IPv6 address in numeric form. Corresponds to `IpAddress`, or the
    /// `InetAddressIPv4`/`InetAddressIPv6` variants of `InetAddress`.
    IP(std::net::IpAddr),
    /// A zoned IPv4 or IPv6 address. Corresponds to the `InetAddressIPv4z`/`InetAddressIPv6z`
    /// variants of `InetAddress`.
    ZonedIP(std::net::IpAddr, u32),
    /// A DNS host name. Corresponds to the `InetAddressDNS` variant of `InetAddress`.
    Hostname(String),
    /// The type was ostensibly an `InetAddress` but the variant could not be identified. The data
    /// member contains the undecoded bytes.
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
