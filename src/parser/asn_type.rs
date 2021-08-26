//! Parse an ASN.1 `Type`.
//!
//! This parser is not a complete implementation of the `Type` production in X.680, but is as
//! complete as is necessary to parse most SNMP MIB files. In the main output type, missing
//! productions are included as commentary.

use std::collections::HashMap;

use num::{bigint::ToBigInt, integer::Integer, BigInt, Num};

#[allow(unused_imports)]
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{
        alpha1, alphanumeric1, char as the_char, digit1, hex_digit1, multispace0, multispace1,
        not_line_ending, one_of,
    },
    combinator::{eof, fail, map, map_opt, not, opt, peek, recognize, value},
    error::{ContextError, ParseError},
    multi::{many0, many1, many_till, separated_list0, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

use crate::parser::{identifier, ptok, tok};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Type<ID>
where
    ID: PartialEq + Eq,
{
    pub ty: PlainType<ID>,
    pub constraint: Option<Constraint>,
    pub tag: Option<TypeTag>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlainType<ID>
where
    ID: PartialEq + Eq,
{
    Builtin(BuiltinType<ID>),
    Referenced(ID, Option<HashMap<String, BigInt>>),
    // Constrained,  <-- this is made non-recursive by moving constraints to Type
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuiltinType<ID>
where
    ID: PartialEq + Eq,
{
    // BitString,
    Boolean,
    // CharacterString,
    Choice(Vec<(String, Type<ID>)>),
    // Date,
    // DateTime,
    // Duration,
    // EmbeddedPDV,
    // Enumerated,
    // External,
    // InstanceOf,
    Integer(Option<HashMap<String, BigInt>>),
    // IRI,
    Null,
    // ObjectClassField,
    ObjectIdentifier,
    OctetString,
    // Real,
    // RelativeIRI,
    // RelativeOID,
    Sequence(Vec<(String, Type<ID>)>),
    SequenceOf(Box<Type<ID>>),
    // Set,
    // SetOf,
    // Prefixed,  <-- this is made non-recursive by moving tags to Type
    // Time,
    // TimeOfDay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Constraint {
    size: Option<Vec<ConstraintRange>>,
    value: Option<Vec<ConstraintRange>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstraintRange {
    Full,
    LessEq(BigInt),
    GreaterEq(BigInt),
    Closed(BigInt, BigInt),
    Point(BigInt),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeTag(TypeTagKind, TypeTagClass, u32);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeTagKind {
    Unspecified,
    Implicit,
    Explicit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeTagClass {
    Universal,
    Application,
    Private,
    ContextSpecific,
}

//////////////////////////////////////////////////////////////////////////////////////////

impl<ID> Type<ID>
where
    ID: PartialEq + Eq + std::hash::Hash,
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
impl<ID> PlainType<ID> {
    fn into_type(self) -> Type {
        Type::plain(self)
    }
}

#[cfg(test)]
impl<ID> BuiltinType<ID> {
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

fn kw<'a, E>(word: &'static str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    tok(tag(word))
}

fn sym<'a, E>(sym: &'static str) -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    ptok(tag(sym))
}

fn signed<'a, T, E>() -> impl FnMut(&'a str) -> IResult<&'a str, T, E>
where
    T: 'a + Num,
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let dec = tok(recognize(pair(tag("-"), digit1)));
    alt((map_opt(dec, |t| T::from_str_radix(t, 10).ok()), unsigned()))
}

fn unsigned<'a, T, E>() -> impl FnMut(&'a str) -> IResult<&'a str, T, E>
where
    T: 'a + Num,
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let dec = map_opt(digit1, |t| T::from_str_radix(t, 10).ok());
    let hex = map_opt(
        delimited(
            tag("'"),
            many1(delimited(multispace0, hex_digit1, multispace0)),
            pair(the_char('\''), one_of("Hh")),
        ),
        |t| T::from_str_radix(&t.join(""), 16).ok(),
    );
    let bin = map_opt(
        delimited(
            tag("'"),
            many1(delimited(multispace0, one_of("01"), multispace0)),
            pair(the_char('\''), one_of("Bb")),
        ),
        |t| T::from_str_radix(&t.into_iter().collect::<String>(), 2).ok(),
    );
    tok(alt((dec, hex, bin)))
}

//////////////////////////////////////////////////////////////////////////////////////////

pub(crate) fn asn_type<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, Type<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    asn_type_common(builtin_type())
}

/// Workaround for a compiler hang which occurs if asn_type is used inside a production that is
/// called from asn_type. This calls builtin_type_nonrec instead of builtin_type but is otherwise
/// identical.
fn asn_type_nonrec<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, Type<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    asn_type_common(builtin_type_nonrec())
}

fn asn_type_common<'a, BI, E>(
    builtin_type: BI,
) -> impl FnMut(&'a str) -> IResult<&'a str, Type<String>, E>
where
    BI: 'a + FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>,
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        tuple((
            opt(type_tag()),
            alt((
                map(builtin_type, |t| PlainType::Builtin(t)),
                map(pair(identifier(), opt(named_number_list())), |t| {
                    PlainType::Referenced(t.0.to_string(), t.1)
                }),
            )),
            opt(constraint()),
        )),
        |(tag, ty, cstr)| Type::new(ty, cstr, tag),
    )
}

fn builtin_type<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    alt((
        builtin_type_nonrec(),
        builtin_type_sequence(),
        builtin_type_sequence_of(),
        builtin_type_choice(),
    ))
}

/// Workaround for a compiler hang which occurs if asn_type is used inside a production that is
/// called from asn_type. All builtin_type alternates that do not transitively contain an asn_type
/// production go here; alternates which do go in builtin_type directly.
fn builtin_type_nonrec<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    alt((
        value(BuiltinType::Boolean, kw("BOOLEAN")),
        value(BuiltinType::OctetString, pair(kw("OCTET"), kw("STRING"))),
        value(
            BuiltinType::ObjectIdentifier,
            pair(kw("OBJECT"), kw("IDENTIFIER")),
        ),
        value(BuiltinType::Null, kw("NULL")),
        builtin_type_integer(),
    ))
}

fn builtin_type_integer<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(preceded(kw("INTEGER"), opt(named_number_list())), |nnl| {
        BuiltinType::Integer(nnl)
    })
}

fn named_number_list<'a, T, E>() -> impl FnMut(&'a str) -> IResult<&'a str, HashMap<String, T>, E>
where
    T: 'a + Num,
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let named_number = pair(identifier(), delimited(sym("("), signed(), sym(")")));
    map(
        delimited(
            sym("{"),
            terminated(separated_list1(sym(","), named_number), opt(sym(","))),
            sym("}"),
        ),
        |nnl| nnl.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
    )
}

fn builtin_type_sequence_of<'a, E>(
) -> impl FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        preceded(pair(kw("SEQUENCE"), kw("OF")), asn_type_nonrec()),
        |t| BuiltinType::SequenceOf(Box::new(t)),
    )
}

fn named_type_list_nonrec<'a, E>(
) -> impl FnMut(&'a str) -> IResult<&'a str, Vec<(String, Type<String>)>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        terminated(
            separated_list1(sym(","), pair(identifier(), asn_type_nonrec())),
            opt(sym(",")),
        ),
        |t| {
            t.iter()
                .map(|(name, ty)| (name.to_string(), ty.clone()))
                .collect()
        },
    )
}

/// Extensions, exceptions, optional fields, default values, and COMPONENTS OF are not supported.
fn builtin_type_sequence<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        preceded(
            kw("SEQUENCE"),
            delimited(sym("{"), named_type_list_nonrec(), sym("}")),
        ),
        |ntl| BuiltinType::Sequence(ntl),
    )
}

fn builtin_type_choice<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, BuiltinType<String>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        preceded(
            kw("CHOICE"),
            delimited(sym("{"), named_type_list_nonrec(), sym("}")),
        ),
        |ntl| BuiltinType::Choice(ntl),
    )
}

//////////////////////////////////////////////////////////////////////////////////////////

/// Significant subset of actual constraint grammar. Supports value and size only, and union of
/// range and single value only.
fn constraint<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, Constraint, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let size = map(
        preceded(
            kw("SIZE"),
            delimited(sym("("), value_constraint(), sym(")")),
        ),
        |Constraint { value, .. }| Constraint {
            size: value,
            value: None,
        },
    );

    map(
        delimited(
            sym("("),
            separated_list1(sym(","), alt((size, value_constraint()))),
            sym(")"),
        ),
        |cs| {
            cs.into_iter()
                .fold(Constraint::empty(), |acc, v| acc.union(v))
        },
    )
}

fn value_constraint<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, Constraint, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let lower = alt((value(None, sym("MIN")), map(signed(), Option::Some)));
    let upper = alt((value(None, kw("MAX")), map(signed(), Option::Some)));
    let range = map(separated_pair(lower, sym(".."), upper), |t| match t {
        (Some(l), Some(u)) => ConstraintRange::Closed(l, u),
        (Some(l), None) => ConstraintRange::GreaterEq(l),
        (None, Some(u)) => ConstraintRange::LessEq(u),
        (None, None) => ConstraintRange::Full,
    });
    let union_member = alt((range, map(signed(), |v| ConstraintRange::Point(v))));
    map(separated_list1(sym("|"), union_member), |ums| {
        Constraint::values(
            ums.iter()
                .cloned()
                .map(ToConstraintRange::to_constraint_range),
        )
    })
}

//////////////////////////////////////////////////////////////////////////////////////////

/// Encoding references are not supported.
pub fn type_tag<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, TypeTag, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
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
        pair(delimited(sym("["), pair(class, unsigned()), sym("]")), kind),
        |((c, t), k)| TypeTag(k, c, t),
    )
}

//////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::{BuiltinType as BI, *};
    use nom::error::VerboseError;

    macro_rules! parse_ok {
        ($parser:expr, $case:literal, $val:expr) => {
            assert_eq!(
                $parser()($case),
                Ok::<_, nom::Err<VerboseError<&str>>>(("", $val))
            )
        };
    }

    #[test]
    fn lexeme_number() {
        parse_ok!(signed::<u8, _>, "123", 123);
        parse_ok!(signed, "-123", -123);

        parse_ok!(signed, "'ff'h", 255);
        parse_ok!(signed, "'1100'b", 0xC);

        parse_ok!(signed, "'01 ff'h", 0x1FF);
        parse_ok!(signed, "'0001 1111'b", 0x1F);

        parse_ok!(signed, "'  01 ff 'h", 0x1FF);
        parse_ok!(signed, "'   0001 1111 'b", 0x1F);
    }

    macro_rules! type_ok {
        ($case:literal, $val:expr) => {
            parse_ok!(asn_type, $case, $val)
        };
    }

    macro_rules! pair_str_val {
        ($($k:ident = $v:expr),*) => {
            [$((stringify!($k).to_string(), $v)),*].iter().cloned().collect()
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
}
