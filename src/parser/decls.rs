use std::collections::HashMap;

use crate::parser::asn_type::asn_type;
use crate::parser::atoms::{identifier, kw, quoted_string, sym, tok, unsigned};
use crate::parser::{ModuleDecl, ObjectTypeDetails, RawOidExpr, TableIndexing};

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::not_line_ending,
    combinator::{map, not, opt, value},
    multi::{many0, many1, many_till, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};

/// Parse an OID expression.
///
/// This requires that every entry in the definition except the first either be a plain integer, or
/// a name with an associated integer like `dod(2)`.
fn oid_expr(input: &str) -> IResult<&str, RawOidExpr> {
    let oid_elem = || {
        alt((
            unsigned,
            delimited(pair(identifier, sym("(")), unsigned, sym(")")),
        ))
    };

    map(
        delimited(
            sym("{"),
            alt((
                map(pair(identifier, many0(oid_elem())), |(name, frag)| {
                    (Some(name), frag)
                }),
                map(many1(oid_elem()), |frag| (None, frag)),
            )),
            sym("}"),
        ),
        |(name, frag)| RawOidExpr {
            parent: name.unwrap_or("").to_string(),
            fragment: frag.into(),
        },
    )(input)
}

/// Parse a `STATUS` stanza in an SMI macro.
fn macro_status(input: &str) -> IResult<&str, &str> {
    preceded(
        kw("STATUS"),
        tok(alt((
            tag("mandatory"),
            tag("optional"),
            tag("current"),
            tag("deprecated"),
            tag("obsolete"),
        ))),
    )(input)
}

/// Parse a `DESCRIPTION` stanza in an SMI macro.
fn macro_description(input: &str) -> IResult<&str, &str> {
    preceded(kw("DESCRIPTION"), quoted_string)(input)
}

/// Parse a `REFERENCE` stanza in an SMI macro.
fn macro_reference(input: &str) -> IResult<&str, Option<&str>> {
    opt(preceded(kw("REFERENCE"), quoted_string))(input)
}

/// Parse a `DEFVAL` stanza in an SMI macro.
fn macro_defval(input: &str) -> IResult<&str, &str> {
    let defval_val = alt((
        delimited(sym("{"), is_not("}"), sym("}")),
        value("", pair(sym("{"), sym("}"))),
        is_not("}"),
    ));
    preceded(kw("DEFVAL"), delimited(sym("{"), defval_val, sym("}")))(input)
}

/// Parse an access specifier.
///
/// Depending on which macro it occurs in, only certain subsets of specifiers are grammatically
/// valid by the standard, but that is ignored here and this parser is used universally to accept
/// any allowed specifiers from every macro defined in SMI.
fn access_specifier(input: &str) -> IResult<&str, &str> {
    tok(alt((
        tag("accessible-for-notify"),
        tag("not-accessible"),
        tag("not-implemented"),
        tag("read-create"),
        tag("read-only"),
        tag("read-write"),
    )))(input)
}

/// Parse an `IMPORTS` stanza.
///
/// Order and structure is not preserved; the parsed result contains a hash with a key for each
/// imported name, and associated value the name of the module from which it was imported.
pub(crate) fn imports(input: &str) -> IResult<&str, ModuleDecl> {
    let import = map(
        separated_pair(
            separated_list1(sym(","), identifier),
            kw("FROM"),
            identifier,
        ),
        |(names, source_module)| {
            names
                .into_iter()
                .map(|name| (name, source_module.clone()))
                .collect::<Vec<_>>()
        },
    );

    map(
        delimited(kw("IMPORTS"), many1(import), opt(sym(";"))),
        |many| {
            let imported_names = many
                .into_iter()
                .flatten()
                .map(|(i, m)| (i.to_string(), m.to_string()))
                .collect::<HashMap<_, _>>();
            ModuleDecl::Imports(imported_names)
        },
    )(input)
}

/// Parse and discard an `EXPORTS` stanza.
///
/// Successful parse always produces a `ModuleDecl::Irrelevant`.
pub(crate) fn exports(input: &str) -> IResult<&str, ModuleDecl> {
    value(
        ModuleDecl::Irrelevant,
        delimited(
            kw("EXPORTS"),
            separated_list1(sym(","), identifier),
            sym(";"),
        ),
    )(input)
}

/// Parse a `MODULE-IDENTITY` macro.
pub(crate) fn module_identity(input: &str) -> IResult<&str, ModuleDecl> {
    let revision = tuple((kw("REVISION"), quoted_string, macro_description));

    map(
        tuple((
            identifier,
            kw("MODULE-IDENTITY"),
            preceded(kw("LAST-UPDATED"), quoted_string),
            preceded(kw("ORGANIZATION"), quoted_string),
            preceded(kw("CONTACT-INFO"), quoted_string),
            macro_description,
            many0(revision),
            sym("::="),
            oid_expr,
        )),
        |t| ModuleDecl::ModuleIdentity(t.0.to_string(), t.8),
    )(input)
}

/// Parse a `TEXTUAL-CONVENTION` macro.
pub(crate) fn textual_convention(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            sym("::="),
            kw("TEXTUAL-CONVENTION"),
            opt(preceded(kw("DISPLAY-HINT"), quoted_string)),
            macro_status,
            macro_description,
            macro_reference,
            preceded(kw("SYNTAX"), asn_type),
        )),
        |t| ModuleDecl::TextualConvention(t.0.to_string(), t.7),
    )(input)
}

/// Parse a plain OID definition (one defined in ASN.1 without an SMI macro).
pub(crate) fn plain_oid_def(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            kw("OBJECT"),
            kw("IDENTIFIER"),
            sym("::="),
            oid_expr,
        )),
        |t| ModuleDecl::PlainOidDef(t.0.to_string(), t.4),
    )(input)
}

/// Parse a plain type definition (one defined in ASN.1 without an SMI macro).
pub(crate) fn plain_type_def(input: &str) -> IResult<&str, ModuleDecl> {
    map(tuple((identifier, sym("::="), asn_type)), |t| {
        ModuleDecl::PlainTypeDef(t.0.to_string(), t.2)
    })(input)
}

/// Parse an `OBJECT-IDENTITY` macro.
pub(crate) fn object_identity(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            kw("OBJECT-IDENTITY"),
            macro_status,
            macro_description,
            macro_reference,
            sym("::="),
            oid_expr,
        )),
        |t| ModuleDecl::ObjectIdentity(t.0.to_string(), t.6),
    )(input)
}

/// Parse an `OBJECT-TYPE` macro.
pub(crate) fn object_type(input: &str) -> IResult<&str, ModuleDecl> {
    let index = map(
        preceded(
            kw("INDEX"),
            delimited(
                sym("{"),
                separated_list1(sym(","), pair(opt(kw("IMPLIED")), identifier)),
                sym("}"),
            ),
        ),
        |cols| {
            TableIndexing::Index(
                cols.into_iter()
                    .map(|(implied, ident)| (ident.to_string(), implied.is_some()))
                    .collect(),
            )
        },
    );
    let augments = map(
        preceded(kw("AUGMENTS"), delimited(sym("{"), identifier, sym("}"))),
        |id| TableIndexing::Augments(id.to_string()),
    );
    map(
        tuple((
            identifier,
            kw("OBJECT-TYPE"),
            preceded(kw("SYNTAX"), asn_type),
            opt(preceded(kw("UNITS"), quoted_string)),
            preceded(
                tok(alt((tag("MAX-ACCESS"), tag("ACCESS")))),
                access_specifier,
            ),
            macro_status,
            macro_description,
            macro_reference,
            opt(alt((index, augments))),
            opt(macro_defval),
            sym("::="),
            oid_expr,
        )),
        |t| {
            ModuleDecl::ObjectType(
                t.0.to_string(),
                t.11,
                t.2,
                ObjectTypeDetails {
                    unit_of_measure: t.3.map(|s| s.to_string()),
                    indexing: t.8,
                },
            )
        },
    )(input)
}

/// Parse a `NOTIFICATION-TYPE` macro.
pub(crate) fn notification_type(input: &str) -> IResult<&str, ModuleDecl> {
    let objects = separated_list1(sym(","), identifier);
    map(
        tuple((
            identifier,
            kw("NOTIFICATION-TYPE"),
            opt(preceded(
                kw("OBJECTS"),
                delimited(sym("{"), objects, sym("}")),
            )),
            macro_status,
            macro_description,
            macro_reference,
            sym("::="),
            oid_expr,
        )),
        |t| {
            ModuleDecl::NotificationType(
                t.0.to_string(),
                t.7,
                t.2.unwrap_or(vec![])
                    .into_iter()
                    .map(|s| s.to_string())
                    .collect(),
            )
        },
    )(input)
}

/// Parse a `MODULE-COMPLIANCE` macro.
pub(crate) fn module_compliance(input: &str) -> IResult<&str, ModuleDecl> {
    let mandatory_groups = preceded(
        kw("MANDATORY-GROUPS"),
        delimited(sym("{"), separated_list1(sym(","), identifier), sym("}")),
    );
    let compliance_group = preceded(kw("GROUP"), terminated(identifier, macro_description));
    let compliance_object = preceded(
        kw("OBJECT"),
        terminated(
            identifier,
            tuple((
                opt(preceded(kw("SYNTAX"), asn_type)),
                opt(preceded(kw("WRITE-SYNTAX"), asn_type)),
                opt(preceded(kw("MIN-ACCESS"), access_specifier)),
                macro_description,
            )),
        ),
    );
    let compliances = many1(alt((compliance_group, compliance_object)));
    let modules = many0(tuple((
        preceded(
            kw("MODULE"),
            opt(pair(
                not(alt((tag("MANDATORY-GROUPS"), tag("OBJECT"), tag("GROUP")))),
                identifier,
            )),
        ),
        opt(mandatory_groups),
        opt(compliances),
    )));

    map(
        tuple((
            identifier,
            kw("MODULE-COMPLIANCE"),
            macro_status,
            macro_description,
            macro_reference,
            modules,
            sym("::="),
            oid_expr,
        )),
        |t| ModuleDecl::ModuleCompliance(t.0.to_string(), t.7),
    )(input)
}

/// Parse an `OBJECT-GROUP` macro.
pub(crate) fn object_group(input: &str) -> IResult<&str, ModuleDecl> {
    let objects = preceded(
        kw("OBJECTS"),
        delimited(sym("{"), separated_list1(sym(","), identifier), sym("}")),
    );
    map(
        tuple((
            identifier,
            kw("OBJECT-GROUP"),
            objects,
            macro_status,
            macro_description,
            macro_reference,
            sym("::="),
            oid_expr,
        )),
        |t| {
            ModuleDecl::ObjectGroup(
                t.0.to_string(),
                t.7,
                t.2.into_iter().map(|s| s.to_string()).collect(),
            )
        },
    )(input)
}

/// Parse a `NOTIFICATION-GROUP` macro.
pub(crate) fn notification_group(input: &str) -> IResult<&str, ModuleDecl> {
    let notifications = preceded(
        kw("NOTIFICATIONS"),
        delimited(sym("{"), separated_list1(sym(","), identifier), sym("}")),
    );
    map(
        tuple((
            identifier,
            kw("NOTIFICATION-GROUP"),
            notifications,
            macro_status,
            macro_description,
            macro_reference,
            sym("::="),
            oid_expr,
        )),
        |t| {
            ModuleDecl::NotificationGroup(
                t.0.to_string(),
                t.7,
                t.2.into_iter().map(|s| s.to_string()).collect(),
            )
        },
    )(input)
}

/// Parse a macro definition.
///
/// The name is returned but the body is thrown away, as the grammars for SMI macros are all
/// hard-coded in this parser.
pub(crate) fn macro_def(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            kw("MACRO"),
            sym("::="),
            kw("BEGIN"),
            many_till(tok(not_line_ending), kw("END")),
        )),
        |t| ModuleDecl::MacroDef(t.0.to_string()),
    )(input)
}

/// Parse an `AGENT-CAPABILITIES` macro.
pub(crate) fn agent_capabilities(input: &str) -> IResult<&str, ModuleDecl> {
    let identifier_list = || separated_list1(sym(","), identifier);
    let variation = tuple((
        preceded(kw("VARIATION"), identifier),
        opt(preceded(kw("SYNTAX"), asn_type)),
        opt(preceded(kw("WRITE-SYNTAX"), asn_type)),
        opt(preceded(kw("ACCESS"), access_specifier)),
        opt(preceded(
            kw("CREATION-REQUIRES"),
            delimited(sym("{"), identifier_list(), sym("}")),
        )),
        opt(macro_defval),
        macro_description,
    ));
    let module = tuple((
        preceded(kw("SUPPORTS"), identifier),
        preceded(
            kw("INCLUDES"),
            delimited(sym("{"), identifier_list(), sym("}")),
        ),
        many0(variation),
    ));
    map(
        tuple((
            identifier,
            kw("AGENT-CAPABILITIES"),
            preceded(kw("PRODUCT-RELEASE"), quoted_string),
            macro_status,
            macro_description,
            macro_reference,
            many0(module),
            sym("::="),
            oid_expr,
        )),
        |t| ModuleDecl::AgentCapabilities(t.0.to_string(), t.8),
    )(input)
}

/// Parse a `TRAP-TYPE` macro.
pub(crate) fn trap_type(input: &str) -> IResult<&str, ModuleDecl> {
    let identifier_list = || separated_list1(sym(","), identifier);
    map(
        tuple((
            identifier,
            kw("TRAP-TYPE"),
            preceded(kw("ENTERPRISE"), identifier),
            preceded(
                kw("VARIABLES"),
                delimited(sym("{"), identifier_list(), sym("}")),
            ),
            macro_description,
            macro_reference,
            sym("::="),
            unsigned::<u32>,
        )),
        |_| ModuleDecl::Irrelevant,
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    //use crate::parser::{ModuleDecl, ObjectTypeDetails, RawOidExpr, TableIndexing};

    macro_rules! parse_ok {
        ($parser:expr, $case:literal, $val:expr) => {
            assert_eq!($parser($case), Ok(("", $val)))
        };
    }

    #[test]
    fn oid_expression() {
        parse_ok!(
            oid_expr,
            "{ bonk 0 1 }",
            RawOidExpr {
                parent: "bonk".to_string(),
                fragment: vec![0, 1].into()
            }
        );

        parse_ok!(
            oid_expr,
            "{ 424 0 1 }",
            RawOidExpr {
                parent: "".to_string(),
                fragment: vec![424, 0, 1].into()
            }
        );

        parse_ok!(
            oid_expr,
            "{ iso foo(42) bar(7) 6 }",
            RawOidExpr {
                parent: "iso".to_string(),
                fragment: vec![42, 7, 6].into()
            }
        );
    }
}
