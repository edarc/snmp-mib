//! Parse an ASN.1 `Type`.
//!
//! This parser is not a complete implementation of the `Type` production in X.680, but is as
//! complete as is necessary to parse most SNMP MIB files. In the main output type, missing
//! productions are included as commentary.

use std::collections::HashMap;

use nom::{
    branch::alt,
    combinator::{map, opt, value},
    multi::separated_list1,
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};
use num::{bigint::ToBigInt, integer::Integer, BigInt, Num};

use crate::parser::atoms::{identifier, kw, signed, sym, unsigned};

/// A representation of a complete ASN.1 type.
///
/// An ASN.1 type includes a "plain" type which is optionally constrained, and may optionally have
/// encoding tags attached. In all public APIs, the `ID` parameter is
/// [`Identifier`][crate::types::Identifier].
///
/// This type roughly corresponds to the **TaggedType** grammar production in ITU-T Rec X.680.
///
/// ## Example
///
/// The following ASN.1 type, occurring in the `MY-MIB` module definition where `ImportedType` has
/// been imported from `OTHER-MODULE`:
///
/// ```text
/// SEQUENCE {
///     fancy [APPLICATION 4] IMPLICIT INTEGER (16..42, SIZE(4)),
///     pants [18] ImportedType (SIZE(0..8)),
/// }
/// ```
///
/// Would be parsed as the following structure (of type `Type<Identifier>`):
///
/// ```text
/// Type {
///     ty: Builtin(Sequence([
///         (
///             Identifier("MY-MIB::fancy"),
///             Type {
///                 ty: Builtin(Integer(None)),
///                 constraint: Some(Constraint {
///                     size: Some([4]),
///                     value: Some([16..42])
///                 }),
///                 tag: Some(TypeTag(Implicit, Application, 4))
///             }
///         ),
///         (
///             Identifier("MY-MIB::pants"),
///             Type {
///                 ty: Referenced(
///                     Identifier("OTHER-MODULE::ImportedType"),
///                     None,
///                 ),
///                 constraint: Some(Constraint {
///                     size: Some([0..8]),
///                     value: None
///                 }),
///                 tag: Some(TypeTag(Unspecified, ContextSpecific, 18))
///             }
///         )
///     ])),
///     constraint: None,
///     tag: None
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type<ID>
where
    ID: PartialEq + Eq,
{
    /// The "plain" (unconstrained, untagged) type.
    pub ty: PlainType<ID>,
    /// The constraints applied to the type, if any. Currently supported are size constraints and
    /// value range constraints.
    pub constraint: Option<Constraint>,
    /// ASN.1 encoding tags applied to the type, if any.
    pub tag: Option<TypeTag>,
}

/// A representation of a plain ASN.1 type, excluding constraints and tagging.
///
/// This can be either a built-in, primitive ASN.1 type such as `INTEGER`, or a referenced type,
/// which is an identifier that refers to some other type (either well-known or user defined) that
/// is not built-in. In all public APIs, the `ID` parameter is
/// [`Identifier`][crate::types::Identifier].
///
/// This roughly corresponds to the **Type** grammar production in ITU-T Rec X.680, except that the
/// **ConstrainedType** variant is not used in order to reduce nesting; instead constraints are
/// represented by the `Type::constraint` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlainType<ID>
where
    ID: PartialEq + Eq,
{
    /// A built-in ASN.1 primitive type. The data member describes which built-in type it is.
    Builtin(BuiltinType<ID>),
    /// A referenced type. The data members are the identifier of the referent type, and optionally
    /// a set of named values, which may be present on any referenced type but are generally only
    /// used if the referent is an integer of some kind.
    Referenced(ID, Option<HashMap<String, BigInt>>),
    // Constrained,  <-- this is made non-recursive by moving constraints to Type
}

/// A representation of a built-in ASN.1 type.
///
/// This can express all of the ASN.1 built-in types that occur in SNMP MIB module definitions, but
/// excludes a significant a number of other built-in types that are (to the author's knowledge)
/// never found in MIBs. In all public APIs, the `ID` parameter is
/// [`Identifier`][crate::types::Identifier].
///
/// This type roughly corresponds to the **BuiltinType** grammar production in ITU-T Rec X.680,
/// except that the **PrefixedType** variant is deliberately not used in order to reduce nesting;
/// instead tags are represented by the `Type::tag` field.
///
/// The **BuiltinType** production defined in X.680 contains the following alternates that are not
/// supported here:
///
/// - **BitStringType** (`BIT STRING`) --- SMI defines and uses the well-known type `BITS` instead.
/// - **CharacterStringType** (`CHARACTER STRING`, `BMPString`, `GeneralString`, `GraphicString`,
///   `IA5String`, `ISO646String`, `NumericString`, `PrintableString`, `TeletextString`,
///   `T61String`, `UniversalString`, `UTF8String`, `VideotexString`, `VisibleString`)
/// - **DateType** (`DATE`)
/// - **DateTimeType** (`DATE-TIME`)
/// - **DurationType** (`DURATION`) --- SMI defines and uses the well-known type `TimeTicks`
///   instead.
/// - **EmbeddedPDVType** (`EMBEDDED PDV`)
/// - **EnumeratedType** (`ENUMERATED`) --- SMI uses `INTEGER` with named values instead.
/// - **ExternalType** (`EXTERNAL`)
/// - **InstanceOfType** (ITU-T Rec X.681)
/// - **IRIType** (`OID-IRI`)
/// - **ObjectClassFieldType** (ITU-T Rec X.681)
/// - **RealType** (`REAL`)
/// - **RelativeIRIType** (`RELATIVE-OID-IRI`)
/// - **RelativeOIDType** (`RELATIVE-OID`)
/// - **SetType** (`SET`)
/// - **SetOfType** (`SET OF`)
/// - **TimeType** (`TIME`)
/// - **TimeOfDayType** (`TIME-OF-DAY`)
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuiltinType<ID>
where
    ID: PartialEq + Eq,
{
    /// A `BOOLEAN`.
    Boolean,
    /// A `CHOICE` enum. The data member is the sequence of variant names and their types.
    Choice(Vec<(String, Type<ID>)>),
    /// An `INTEGER`. The data member is a map of named values keyed by their names, if one is
    /// provided. In SNMP MIBs, `INTEGER` with named values is used for C-style enum types instead
    /// of the more expected `ENUMERATION`.
    Integer(Option<HashMap<String, BigInt>>),
    /// The `NULL` type --- analogous to Rust's `()` (unit).
    Null,
    /// An `OBJECT IDENTIFIER`.
    ObjectIdentifier,
    /// An `OCTET STRING`.
    OctetString,
    /// A `SEQUENCE` --- analogous to a struct. The data member is the sequence of field identifiers
    /// and their types.
    Sequence(Vec<(ID, Type<ID>)>),
    /// A `SEQUENCE OF` --- analogous to a `Vec<T>`. The data member is the type of `T` (which must
    /// be boxed to keep `BuiltinType` a bounded size).
    SequenceOf(Box<Type<ID>>),
}

/// A constraint on an ASN.1 type.
///
/// The ASN.1 constraint grammar is extremely expressive, and this type only represents a very
/// small subset of it that appears in MIB module definitions. That subset specifically is
///
/// * Size constraints (which constrain the allowable length of variable-length types), and
/// * Value constraints (which constrain the allowable values out of the range of all possible
///   values the plain type may represent).
///
/// Additionally, union is the only supported set operation; intersection and exclusion is not
/// supported.
///
/// This roughly corresponds to the **Constraint** grammar production in ITU-T Rec X.680, except:
///
/// - **ConstraintSpec** may only be **SubtypeConstraint**,
/// - **ElementSetSpecs** may not include **AdditionalElementSetSpec**,
/// - **ElementSetSpec** may only be **Unions**,
/// - **Intersections** may only contain one **IntersectionElements**,
/// - **IntersectionElements** may only be **Elements**,
/// - **Elements** may only be **SubtypeElements**,
/// - **SubtypeElements** may only be **SingleValue**, **ValueRange**, or **SizeConstraint**.
///
/// ## Example
///
/// The ASN.1 constraint `(16..42, SIZE(4))` is parsed as the following structure:
///
/// ```
/// # use snmp_mib::parser::{Constraint, ConstraintRange};
/// Constraint {
///     size: Some(vec![ConstraintRange::Point(4.into())]),
///     value: Some(vec![ConstraintRange::Closed(16.into(), 42.into())]),
/// };
/// ```
///
/// The constraint `(-1 | 4 | 16)` is parsed as:
///
/// ```
/// # use snmp_mib::parser::{Constraint, ConstraintRange};
/// Constraint {
///     size: None,
///     value: Some(vec![
///         ConstraintRange::Point((-1).into()),
///         ConstraintRange::Point(4.into()),
///         ConstraintRange::Point(16.into()),
///     ]),
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    /// If there is a size constraint, lists the allowable sizes. `None` means the size is
    /// unconstrained.
    pub size: Option<Vec<ConstraintRange>>,
    /// If there is a value constraint, lists the allowable values. `None` means the value is
    /// unconstrained.
    pub value: Option<Vec<ConstraintRange>>,
}

/// A value or range of values that are allowable for a constraint.
///
/// This corresponds to the **SingleValue** and **ValueRange** grammar productions in ITU-T Rec
/// X.680.
#[derive(Clone, PartialEq, Eq)]
pub enum ConstraintRange {
    /// A completely unbounded range; e.g. `MIN..MAX`.
    Full,
    /// A range with an upper bound only; e.g. `MIN..4`. The data member is the upper bound, which
    /// is inclusive.
    LessEq(BigInt),
    /// A range with a lower bound only; e.g. `-1..MAX`. The data member is the lower bound, which
    /// is inclusive.
    GreaterEq(BigInt),
    /// A range with both upper and lower bounds, e.g. `-1..48`. The data members are the lower and
    /// upper bounds, which are both inclusive.
    Closed(BigInt, BigInt),
    /// A singular allowable value, e.g. `16`. The data member is the allowable value. This is
    /// nearly always found in a set of multiple `ConstraintRange`s.
    Point(BigInt),
}

impl std::fmt::Debug for ConstraintRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            ConstraintRange::Full => write!(f, "MIN..MAX"),
            ConstraintRange::LessEq(u) => write!(f, "MIN..{}", u),
            ConstraintRange::GreaterEq(l) => write!(f, "{}..MAX", l),
            ConstraintRange::Closed(l, u) => write!(f, "{}..{}", l, u),
            ConstraintRange::Point(p) => write!(f, "{}", p),
        }
    }
}

/// Encoding tag information for an ASN.1 type.
///
/// The data members are the kind of tag, the class of tag, and the tag value itself.
///
/// This type, when used in the `tag` field of [`Type`], roughly corresponds to the **TaggedType**
/// grammar production in ITU-T Rec X.680. It would correspond to the **Tag** production except
/// that `IMPLICIT`/`EXPLICIT`/unspecified are also included.
///
/// ## Example
///
/// A field or type tagged `[APPLICATION 4] IMPLICIT` would have `Type::tag` ==
/// `TypeTag(TypeTagKind::Implicit, TypeTagClass::Application, 4)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeTag(pub TypeTagKind, pub TypeTagClass, pub u32);

/// The kind of an ASN.1 encoding tag.
///
/// The kind refers to whether the tag is specified to be `IMPLICIT`, `EXPLICIT`, or unspecified.
/// The effective tagging kind is always either implicit or explicit, and is determined by the
/// rules in ITU-T Rec X.680 § 31.2.7. The parser does not implement these rules; this type
/// strictly represents the specific, as-written syntax used in the type expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeTagKind {
    /// The tag specified neither `EXPLICIT` nor `IMPLICIT`.
    Unspecified,
    /// The tag used the `IMPLICIT` keyword.
    Implicit,
    /// The tag used the `EXPLICIT` keyword.
    Explicit,
}

/// The class of an ASN.1 encoding tag.
///
/// In ASN.1, the tag class is a "namespace" for tag numbers. There are 4 such namespaces, one of
/// which (`UNIVERSAL`) is generally reserved for built-in types, but is user-expressible anyway.
/// Tags which do not specify any class are said to be "context-specific" class.
///
/// ## Examples
///
/// * `[APPLICATION 4]` would have the class `TypeTagClass::Application`.
/// * `[42]` would have the class `TypeTagClass::ContextSpecific`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeTagClass {
    /// The tag class was specified as `UNIVERSAL`.
    Universal,
    /// The tag class was specified as `APPLICATION`.
    Application,
    /// The tag class was specified as `PRIVATE`.
    Private,
    /// The tag class was not specified, meaning it is context-specific.
    ContextSpecific,
}

//////////////////////////////////////////////////////////////////////////////////////////

impl<ID> Type<ID>
where
    ID: PartialEq + Eq,
{
    fn new(ty: PlainType<ID>, constraint: Option<Constraint>, tag: Option<TypeTag>) -> Self {
        Self {
            ty,
            constraint,
            tag,
        }
    }

    #[cfg(test)]
    fn plain(ty: PlainType<ID>) -> Self {
        Self::new(ty, None, None)
    }

    #[cfg(test)]
    fn with_constraint(self, constraint: Constraint) -> Self {
        Self {
            constraint: Some(constraint),
            ..self
        }
    }

    #[cfg(test)]
    fn with_tag(self, tag: TypeTag) -> Self {
        Self {
            tag: Some(tag),
            ..self
        }
    }
}

#[cfg(test)]
impl<ID> PlainType<ID>
where
    ID: PartialEq + Eq,
{
    fn into_type(self) -> Type<ID> {
        Type::plain(self)
    }
}

#[cfg(test)]
impl<ID> BuiltinType<ID>
where
    ID: PartialEq + Eq,
{
    fn into_plain(self) -> PlainType<ID> {
        PlainType::Builtin(self)
    }
}

impl Constraint {
    fn empty() -> Self {
        Self {
            size: None,
            value: None,
        }
    }

    #[cfg(test)]
    fn sizes<T: ToConstraintRange>(size: impl IntoIterator<Item = T>) -> Self {
        Self {
            size: Some(
                size.into_iter()
                    .map(ToConstraintRange::to_constraint_range)
                    .collect(),
            ),
            value: None,
        }
    }

    fn values<T: ToConstraintRange>(value: impl IntoIterator<Item = T>) -> Self {
        Self {
            size: None,
            value: Some(
                value
                    .into_iter()
                    .map(ToConstraintRange::to_constraint_range)
                    .collect(),
            ),
        }
    }

    #[cfg(test)]
    fn size(size: impl ToConstraintRange) -> Self {
        Self::sizes([size])
    }

    #[cfg(test)]
    fn value(value: impl ToConstraintRange) -> Self {
        Self::values([value])
    }

    fn union(self, other: Self) -> Self {
        let Self { size, value } = other;
        let union_option =
            |s: Option<Vec<ConstraintRange>>, o: Option<Vec<ConstraintRange>>| match (s, o) {
                (Some(mut s), Some(o)) => {
                    s.extend(o);
                    Some(s)
                }
                (Some(s), None) => Some(s),
                (None, Some(o)) => Some(o),
                (None, None) => None,
            };
        Self {
            size: union_option(self.size, size),
            value: union_option(self.value, value),
        }
    }
}

#[cfg(test)]
impl ConstraintRange {
    fn less_eq(u: impl ToBigInt + Integer) -> Self {
        ConstraintRange::LessEq(u.to_bigint().unwrap())
    }
    fn greater_eq(l: impl ToBigInt + Integer) -> Self {
        ConstraintRange::GreaterEq(l.to_bigint().unwrap())
    }
}

trait ToConstraintRange {
    fn to_constraint_range(self) -> ConstraintRange;
}

impl ToConstraintRange for ConstraintRange {
    fn to_constraint_range(self) -> ConstraintRange {
        self
    }
}

impl<T: ToBigInt + Integer> ToConstraintRange for (T,) {
    fn to_constraint_range(self) -> ConstraintRange {
        ConstraintRange::Point(self.0.to_bigint().unwrap())
    }
}

impl<L: ToBigInt + Integer, U: ToBigInt + Integer> ToConstraintRange for (L, U) {
    fn to_constraint_range(self) -> ConstraintRange {
        let (li, ui) = self;
        let (l, u) = (li.to_bigint().unwrap(), ui.to_bigint().unwrap());
        if l == u {
            ConstraintRange::Point(l)
        } else {
            ConstraintRange::Closed(l, u)
        }
    }
}

#[cfg(test)]
impl TypeTag {
    fn new(val: u32) -> Self {
        TypeTag(TypeTagKind::Unspecified, TypeTagClass::ContextSpecific, val)
    }
    fn implicit(self) -> Self {
        TypeTag(TypeTagKind::Implicit, self.1, self.2)
    }
    fn explicit(self) -> Self {
        TypeTag(TypeTagKind::Explicit, self.1, self.2)
    }
    fn universal(self) -> Self {
        TypeTag(self.0, TypeTagClass::Universal, self.2)
    }
    fn application(self) -> Self {
        TypeTag(self.0, TypeTagClass::Application, self.2)
    }
    fn private(self) -> Self {
        TypeTag(self.0, TypeTagClass::Private, self.2)
    }
}

//////////////////////////////////////////////////////////////////////////////////////////

pub(crate) fn asn_type(input: &str) -> IResult<&str, Type<String>> {
    asn_type_common(&builtin_type)(input)
}

/// Workaround for a compiler hang which occurs if asn_type is used inside a production that is
/// called from asn_type. This calls builtin_type_nonrec instead of builtin_type but is otherwise
/// identical.
fn asn_type_nonrec(input: &str) -> IResult<&str, Type<String>> {
    asn_type_common(&builtin_type_nonrec)(input)
}

fn asn_type_common<'a>(
    builtin_type: &'a dyn Fn(&str) -> IResult<&str, BuiltinType<String>>,
) -> impl 'a + Fn(&str) -> IResult<&str, Type<String>> {
    move |input| {
        map(
            tuple((
                opt(type_tag),
                alt((
                    map(builtin_type, |t| PlainType::Builtin(t)),
                    map(pair(identifier, opt(named_number_list)), |t| {
                        PlainType::Referenced(t.0.to_string(), t.1)
                    }),
                )),
                opt(constraint),
            )),
            |(tag, ty, cstr)| Type::new(ty, cstr, tag),
        )(input)
    }
}

fn builtin_type(input: &str) -> IResult<&str, BuiltinType<String>> {
    alt((
        builtin_type_nonrec,
        builtin_type_sequence,
        builtin_type_sequence_of,
        builtin_type_choice,
    ))(input)
}

/// Workaround for a compiler hang which occurs if asn_type is used inside a production that is
/// called from asn_type. All builtin_type alternates that do not transitively contain an asn_type
/// production go here; alternates which do go in builtin_type directly.
fn builtin_type_nonrec(input: &str) -> IResult<&str, BuiltinType<String>> {
    alt((
        value(BuiltinType::Boolean, kw("BOOLEAN")),
        value(BuiltinType::OctetString, pair(kw("OCTET"), kw("STRING"))),
        value(
            BuiltinType::ObjectIdentifier,
            pair(kw("OBJECT"), kw("IDENTIFIER")),
        ),
        value(BuiltinType::Null, kw("NULL")),
        builtin_type_integer,
    ))(input)
}

fn builtin_type_integer(input: &str) -> IResult<&str, BuiltinType<String>> {
    map(preceded(kw("INTEGER"), opt(named_number_list)), |nnl| {
        BuiltinType::Integer(nnl)
    })(input)
}

fn named_number_list<T>(input: &str) -> IResult<&str, HashMap<String, T>>
where
    T: Num,
{
    let named_number = pair(identifier, delimited(sym("("), signed, sym(")")));
    map(
        delimited(
            sym("{"),
            terminated(separated_list1(sym(","), named_number), opt(sym(","))),
            sym("}"),
        ),
        |nnl| nnl.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    )(input)
}

fn builtin_type_sequence_of(input: &str) -> IResult<&str, BuiltinType<String>> {
    map(
        preceded(pair(kw("SEQUENCE"), kw("OF")), asn_type_nonrec),
        |t| BuiltinType::SequenceOf(Box::new(t)),
    )(input)
}

fn named_type_list_nonrec(input: &str) -> IResult<&str, Vec<(String, Type<String>)>> {
    map(
        terminated(
            separated_list1(sym(","), pair(identifier, asn_type_nonrec)),
            opt(sym(",")),
        ),
        |t| {
            t.iter()
                .map(|(name, ty)| (name.to_string(), ty.clone()))
                .collect()
        },
    )(input)
}

/// Extensions, exceptions, optional fields, default values, and COMPONENTS OF are not supported.
fn builtin_type_sequence(input: &str) -> IResult<&str, BuiltinType<String>> {
    map(
        preceded(
            kw("SEQUENCE"),
            delimited(sym("{"), named_type_list_nonrec, sym("}")),
        ),
        |ntl| BuiltinType::Sequence(ntl),
    )(input)
}

fn builtin_type_choice(input: &str) -> IResult<&str, BuiltinType<String>> {
    map(
        preceded(
            kw("CHOICE"),
            delimited(sym("{"), named_type_list_nonrec, sym("}")),
        ),
        |ntl| BuiltinType::Choice(ntl),
    )(input)
}

//////////////////////////////////////////////////////////////////////////////////////////

/// Significant subset of actual constraint grammar. Supports value and size only, and union of
/// range and single value only.
fn constraint(input: &str) -> IResult<&str, Constraint> {
    let size = map(
        preceded(kw("SIZE"), delimited(sym("("), value_constraint, sym(")"))),
        |Constraint { value, .. }| Constraint {
            size: value,
            value: None,
        },
    );

    map(
        delimited(
            sym("("),
            separated_list1(sym(","), alt((size, value_constraint))),
            sym(")"),
        ),
        |cs| {
            cs.into_iter()
                .fold(Constraint::empty(), |acc, v| acc.union(v))
        },
    )(input)
}

fn value_constraint(input: &str) -> IResult<&str, Constraint> {
    let lower = alt((value(None, sym("MIN")), map(signed, Option::Some)));
    let upper = alt((value(None, kw("MAX")), map(signed, Option::Some)));
    let range = map(separated_pair(lower, sym(".."), upper), |t| match t {
        (Some(l), Some(u)) => ConstraintRange::Closed(l, u),
        (Some(l), None) => ConstraintRange::GreaterEq(l),
        (None, Some(u)) => ConstraintRange::LessEq(u),
        (None, None) => ConstraintRange::Full,
    });
    let union_member = alt((range, map(signed, |v| ConstraintRange::Point(v))));
    map(separated_list1(sym("|"), union_member), |ums| {
        Constraint::values(
            ums.iter()
                .cloned()
                .map(ToConstraintRange::to_constraint_range),
        )
    })(input)
}

//////////////////////////////////////////////////////////////////////////////////////////

/// Encoding references are not supported.
fn type_tag(input: &str) -> IResult<&str, TypeTag> {
    let class = map(
        opt(alt((
            value(TypeTagClass::Universal, kw("UNIVERSAL")),
            value(TypeTagClass::Application, kw("APPLICATION")),
            value(TypeTagClass::Private, kw("PRIVATE")),
        ))),
        |t| t.unwrap_or(TypeTagClass::ContextSpecific),
    );
    let kind = map(
        opt(alt((
            value(TypeTagKind::Implicit, kw("IMPLICIT")),
            value(TypeTagKind::Explicit, kw("EXPLICIT")),
        ))),
        |t| t.unwrap_or(TypeTagKind::Unspecified),
    );
    map(
        pair(delimited(sym("["), pair(class, unsigned), sym("]")), kind),
        |((c, t), k)| TypeTag(k, c, t),
    )(input)
}

//////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::{BuiltinType as BI, *};

    macro_rules! parse_ok {
        ($parser:expr, $case:literal, $val:expr) => {
            assert_eq!($parser($case), Ok(("", $val)))
        };
    }

    macro_rules! type_ok {
        ($case:literal, $val:expr) => {
            parse_ok!(asn_type, $case, $val)
        };
    }

    macro_rules! pair_str_val {
        ($($k:ident = $v:expr),*) => {
            [$((stringify!($k).to_string(), $v.into())),*].iter().cloned().collect()
        };
    }

    #[test]
    fn builtin_type_simple() {
        type_ok!("BOOLEAN", BI::Boolean.into_plain().into_type());
        type_ok!("OCTET STRING", BI::OctetString.into_plain().into_type());
        type_ok!("OCTET  STRING", BI::OctetString.into_plain().into_type());
        type_ok!(
            "OBJECT  IDENTIFIER",
            BI::ObjectIdentifier.into_plain().into_type()
        );
    }

    #[test]
    fn builtin_type_integer() {
        let i = |v| BI::Integer(v).into_plain().into_type();
        type_ok!("INTEGER", i(None));
        type_ok!("INTEGER{ok(0)}", i(Some(pair_str_val!(ok = 0))));
        type_ok!("INTEGER {ok(0),}", i(Some(pair_str_val!(ok = 0))));
        type_ok!(
            "INTEGER { ok(0), bad(1) }",
            i(Some(pair_str_val!(ok = 0, bad = 1)))
        );
        type_ok!("INTEGER { sp ( 1 ) }", i(Some(pair_str_val!(sp = 1))));
        type_ok!("INTEGER { neg(-33)}", i(Some(pair_str_val!(neg = -33))));
    }

    #[test]
    fn builtin_type_sequence() {
        let s = |v| BI::Sequence(v).into_plain().into_type();
        type_ok!(
            "SEQUENCE{ok BOOLEAN}",
            s(pair_str_val!(ok = BI::Boolean.into_plain().into_type()))
        );
        type_ok!(
            "SEQUENCE {
                ok BOOLEAN,
                data OCTET STRING,
             }",
            s(pair_str_val!(
                ok = BI::Boolean.into_plain().into_type(),
                data = BI::OctetString.into_plain().into_type()
            ))
        );
    }

    #[test]
    fn builtin_type_sequence_of() {
        let so = |v| BI::SequenceOf(Box::new(v)).into_plain().into_type();
        type_ok!(
            "SEQUENCE OF BOOLEAN",
            so(BI::Boolean.into_plain().into_type())
        );
        type_ok!(
            "SEQUENCE   OF INTEGER {ok(1)}",
            so(BI::Integer(Some(pair_str_val!(ok = 1)))
                .into_plain()
                .into_type())
        );
    }

    #[test]
    fn builtin_type_choice() {
        let c = |vs| BI::Choice(vs).into_plain().into_type();
        type_ok!(
            "CHOICE { ok BOOLEAN }",
            c(pair_str_val!(ok = BI::Boolean.into_plain().into_type()))
        );
        type_ok!(
            "CHOICE { ok [APPLICATION 4] IMPLICIT OCTET STRING, }",
            c(pair_str_val!(
                ok = BI::OctetString
                    .into_plain()
                    .into_type()
                    .with_tag(TypeTag::new(4).application().implicit())
            ))
        );
        type_ok!(
            "CHOICE { first BOOLEAN, second INTEGER (0..5) }",
            c(pair_str_val!(
                first = BI::Boolean.into_plain().into_type(),
                second = BI::Integer(None)
                    .into_plain()
                    .into_type()
                    .with_constraint(Constraint::value((0, 5)))
            ))
        );
    }

    #[test]
    fn referenced_type() {
        type_ok!(
            "SomeRandomThing",
            PlainType::Referenced("SomeRandomThing".to_string(), None).into_type()
        );
        type_ok!(
            "SomeRandomThing {ok(1)}",
            PlainType::Referenced("SomeRandomThing".to_string(), Some(pair_str_val!(ok = 1)))
                .into_type()
        );
    }

    #[test]
    fn tagged_type() {
        let b = || BI::Boolean.into_plain().into_type();
        parse_ok!(type_tag, "[4]", TypeTag::new(4));
        parse_ok!(type_tag, "[UNIVERSAL 77]", TypeTag::new(77).universal());
        parse_ok!(
            type_tag,
            "[APPLICATION 23] IMPLICIT",
            TypeTag::new(23).application().implicit()
        );

        type_ok!("BOOLEAN", b());
        type_ok!("[4]BOOLEAN", b().with_tag(TypeTag::new(4)));
        type_ok!(
            "[ PRIVATE 17] BOOLEAN",
            b().with_tag(TypeTag::new(17).private())
        );
        type_ok!(
            "[9 ] EXPLICIT BOOLEAN",
            b().with_tag(TypeTag::new(9).explicit())
        );
    }

    #[test]
    fn value_constraint_union_member() {
        parse_ok!(value_constraint, "3", Constraint::value((3, 3)));
        parse_ok!(value_constraint, "-4..4", Constraint::value((-4, 4)));
        parse_ok!(
            value_constraint,
            "MIN.. 4",
            Constraint::value(ConstraintRange::less_eq(4))
        );
        parse_ok!(
            value_constraint,
            "0.. MAX",
            Constraint::value(ConstraintRange::greater_eq(0))
        );
    }

    #[test]
    fn value_constraint_union() {
        parse_ok!(
            value_constraint,
            "3|8",
            Constraint::values(vec![(3, 3), (8, 8)])
        );
        parse_ok!(
            value_constraint,
            "-9 | 0..4",
            Constraint::values(vec![(-9, -9), (0, 4)])
        );
        parse_ok!(
            value_constraint,
            "1|2|3",
            Constraint::values(vec![(1,), (2,), (3,)])
        );
    }

    #[test]
    fn constraint_value() {
        parse_ok!(constraint, "(0..4)", Constraint::value((0, 4)));
        parse_ok!(
            constraint,
            "( -9 | 4..8 )",
            Constraint::values(vec![(-9, -9), (4, 8)])
        );
    }

    #[test]
    fn constraint_size() {
        parse_ok!(constraint, "(SIZE(4))", Constraint::size((4, 4)));
        parse_ok!(constraint, "( SIZE (0..16) )", Constraint::size((0, 16)));
    }

    #[test]
    fn constraint_both() {
        parse_ok!(
            constraint,
            "(0..9, SIZE(1))",
            Constraint::size((1, 1)).union(Constraint::value((0, 9)))
        );
    }

    #[test]
    fn constrained_type() {
        type_ok!(
            "INTEGER (0..9)",
            BI::Integer(None)
                .into_plain()
                .into_type()
                .with_constraint(Constraint::value((0, 9)))
        );
    }

    #[test]
    fn very_fancy_type() {
        type_ok!(
            r#"SEQUENCE {
                fancy [APPLICATION 4] IMPLICIT INTEGER (16..42, SIZE(4)),
                pants [18] OCTET STRING (SIZE(0..8)),
            }"#,
            Type {
                ty: BI::Sequence(vec![
                    (
                        "fancy".to_string(),
                        BI::Integer(None)
                            .into_plain()
                            .into_type()
                            .with_constraint(Constraint {
                                size: Some(vec![ConstraintRange::Point(4.into())]),
                                value: Some(vec![ConstraintRange::Closed(16.into(), 42.into())])
                            })
                            .with_tag(TypeTag::new(4).implicit().application())
                    ),
                    (
                        "pants".to_string(),
                        BI::OctetString
                            .into_plain()
                            .into_type()
                            .with_constraint(Constraint::size((0, 8)))
                            .with_tag(TypeTag::new(18))
                    )
                ])
                .into_plain(),
                constraint: None,
                tag: None
            }
        );
    }
}
