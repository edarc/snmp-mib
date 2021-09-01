//! The parser for MIB module definitions.
//!
//! The main API surface consists of `ModuleDecl` and `parse_module`, where the latter parses a MIB
//! module into a sequence of the former.

pub mod asn_type;
pub mod atoms;

use std::collections::HashMap;

use crate::parser::asn_type::{asn_type, Type};
use crate::parser::atoms::{identifier, ptok, quoted_string, tok, ws_or_comment};
use crate::types::identifier::Identifier;
use crate::types::oid_expr::OidExpr;

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{digit1, not_line_ending},
    combinator::{map, not, opt, value},
    multi::{many0, many1, many_till, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};
use smallvec::SmallVec;

/// This is like an OidExpr except the root identifier's module name is unresolved. Resolution
/// happens in the `Loader`.
#[derive(Clone, Debug)]
pub struct RawOidExpr {
    parent: String,
    fragment: SmallVec<[u32; 1]>,
}

impl RawOidExpr {
    /// Convert this `RawOidExpr` into an `OidExpr` by qualifying the parent identifier. The
    /// provided function should return a qualified `Identifier` given the unqualified identifier
    /// as a &str.
    pub fn qualify(self, resolve: impl Fn(String) -> Identifier) -> OidExpr {
        let name = resolve(self.parent);
        OidExpr {
            parent: name,
            fragment: self.fragment,
        }
    }
}

/// The various kinds of declarations that occur in a MIB module. A parsed MIB module is
/// essentially a sequence of these.
#[derive(Clone, Debug)]
pub enum ModuleDecl {
    AgentCapabilities(String, RawOidExpr),
    Imports(HashMap<String, String>),
    MacroDef(String),
    ModuleCompliance(String, RawOidExpr),
    ModuleIdentity(String, RawOidExpr),
    NotificationGroup(String, RawOidExpr, Vec<String>),
    NotificationType(String, RawOidExpr, Vec<String>),
    ObjectGroup(String, RawOidExpr, Vec<String>),
    ObjectIdentity(String, RawOidExpr),
    ObjectType(String, RawOidExpr, Type<String>, ObjectTypeDetails),
    PlainOidDef(String, RawOidExpr),
    PlainTypeDef(String, Type<String>),
    TextualConvention(String, Type<String>),
    Irrelevant,
}

#[derive(Clone, Debug)]
pub struct ObjectTypeDetails {
    pub unit_of_measure: Option<String>,
    pub indexing: Option<TableIndexing>,
}

#[derive(Clone, Debug)]
pub enum TableIndexing {
    Index(Vec<(String, bool)>),
    Augments(String),
}

impl ModuleDecl {
    pub fn is_imports(&self) -> bool {
        match self {
            ModuleDecl::Imports(_) => true,
            _ => false,
        }
    }
}

/// This is the result of the parser, consisting of the module name and a sequence of
/// `ModuleDecl`s.
#[derive(Clone, Debug)]
pub struct ParsedModule(pub String, pub Vec<ModuleDecl>);

/// Parse an OID expression.
///
/// This requires that every entry in the definition except the first either be a plain integer, or
/// a name with an associated integer like `dod(2)`.
fn oid_expr(input: &str) -> IResult<&str, RawOidExpr> {
    let num = || map(digit1, |v: &str| v.parse::<u32>().unwrap());
    let oid_elem = alt((
        num(),
        delimited(pair(identifier, tag("(")), num(), tag(")")),
    ));

    map(
        delimited(
            ptok(tag("{")),
            pair(opt(identifier), many0(tok(oid_elem))),
            ptok(tag("}")),
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
        tok(tag("STATUS")),
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
    preceded(tok(tag("DESCRIPTION")), quoted_string)(input)
}

/// Parse a `REFERENCE` stanza in an SMI macro.
fn macro_reference(input: &str) -> IResult<&str, Option<&str>> {
    opt(preceded(tok(tag("REFERENCE")), quoted_string))(input)
}

/// Parse a `DEFVAL` stanza in an SMI macro.
fn macro_defval(input: &str) -> IResult<&str, &str> {
    let defval_val = alt((
        delimited(ptok(tag("{")), is_not("}"), ptok(tag("}"))),
        value("", pair(ptok(tag("{")), ptok(tag("}")))),
        is_not("}"),
    ));
    preceded(
        tok(tag("DEFVAL")),
        delimited(ptok(tag("{")), defval_val, ptok(tag("}"))),
    )(input)
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
fn imports(input: &str) -> IResult<&str, ModuleDecl> {
    let import = map(
        separated_pair(
            separated_list1(ptok(tag(",")), identifier),
            tok(tag("FROM")),
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
        delimited(tok(tag("IMPORTS")), many1(import), opt(tok(tag(";")))),
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
fn exports(input: &str) -> IResult<&str, ModuleDecl> {
    value(
        ModuleDecl::Irrelevant,
        delimited(
            tok(tag("EXPORTS")),
            separated_list1(tok(tag(",")), identifier),
            tok(tag(";")),
        ),
    )(input)
}

/// Parse a `MODULE-IDENTITY` macro.
fn module_identity(input: &str) -> IResult<&str, ModuleDecl> {
    let revision = tuple((tok(tag("REVISION")), quoted_string, macro_description));

    map(
        tuple((
            identifier,
            tok(tag("MODULE-IDENTITY")),
            preceded(tok(tag("LAST-UPDATED")), quoted_string),
            preceded(tok(tag("ORGANIZATION")), quoted_string),
            preceded(tok(tag("CONTACT-INFO")), quoted_string),
            macro_description,
            many0(revision),
            ptok(tag("::=")),
            oid_expr,
        )),
        |t| ModuleDecl::ModuleIdentity(t.0.to_string(), t.8),
    )(input)
}

/// Parse a `TEXTUAL-CONVENTION` macro.
fn textual_convention(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            ptok(tag("::=")),
            tok(tag("TEXTUAL-CONVENTION")),
            opt(preceded(tok(tag("DISPLAY-HINT")), quoted_string)),
            macro_status,
            macro_description,
            macro_reference,
            preceded(tok(tag("SYNTAX")), asn_type),
        )),
        |t| ModuleDecl::TextualConvention(t.0.to_string(), t.7),
    )(input)
}

/// Parse a plain OID definition (one defined in ASN.1 without an SMI macro).
fn plain_oid_def(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            tok(tag("OBJECT")),
            tok(tag("IDENTIFIER")),
            ptok(tag("::=")),
            oid_expr,
        )),
        |t| ModuleDecl::PlainOidDef(t.0.to_string(), t.4),
    )(input)
}

/// Parse a plain type definition (one defined in ASN.1 without an SMI macro).
fn plain_type_def(input: &str) -> IResult<&str, ModuleDecl> {
    map(tuple((identifier, ptok(tag("::=")), asn_type)), |t| {
        ModuleDecl::PlainTypeDef(t.0.to_string(), t.2)
    })(input)
}

/// Parse an `OBJECT-IDENTITY` macro.
fn object_identity(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            tok(tag("OBJECT-IDENTITY")),
            macro_status,
            macro_description,
            macro_reference,
            ptok(tag("::=")),
            oid_expr,
        )),
        |t| ModuleDecl::ObjectIdentity(t.0.to_string(), t.6),
    )(input)
}

/// Parse an `OBJECT-TYPE` macro.
fn object_type(input: &str) -> IResult<&str, ModuleDecl> {
    let index = map(
        preceded(
            tok(tag("INDEX")),
            delimited(
                ptok(tag("{")),
                separated_list1(ptok(tag(",")), pair(opt(tok(tag("IMPLIED"))), identifier)),
                ptok(tag("}")),
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
        preceded(
            tok(tag("AUGMENTS")),
            delimited(ptok(tag("{")), identifier, ptok(tag("}"))),
        ),
        |id| TableIndexing::Augments(id.to_string()),
    );
    map(
        tuple((
            identifier,
            tok(tag("OBJECT-TYPE")),
            preceded(tok(tag("SYNTAX")), asn_type),
            opt(preceded(tok(tag("UNITS")), quoted_string)),
            preceded(
                tok(alt((tag("MAX-ACCESS"), tag("ACCESS")))),
                access_specifier,
            ),
            macro_status,
            macro_description,
            macro_reference,
            opt(alt((index, augments))),
            opt(macro_defval),
            ptok(tag("::=")),
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
fn notification_type(input: &str) -> IResult<&str, ModuleDecl> {
    let objects = separated_list1(tok(tag(",")), identifier);
    map(
        tuple((
            identifier,
            tok(tag("NOTIFICATION-TYPE")),
            opt(preceded(
                tok(tag("OBJECTS")),
                delimited(ptok(tag("{")), objects, ptok(tag("}"))),
            )),
            macro_status,
            macro_description,
            macro_reference,
            ptok(tag("::=")),
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
fn module_compliance(input: &str) -> IResult<&str, ModuleDecl> {
    let mandatory_groups = preceded(
        tok(tag("MANDATORY-GROUPS")),
        delimited(
            ptok(tag("{")),
            separated_list1(ptok(tag(",")), identifier),
            ptok(tag("}")),
        ),
    );
    let compliance_group = preceded(tok(tag("GROUP")), terminated(identifier, macro_description));
    let compliance_object = preceded(
        tok(tag("OBJECT")),
        terminated(
            identifier,
            tuple((
                opt(preceded(tok(tag("SYNTAX")), asn_type)),
                opt(preceded(tok(tag("WRITE-SYNTAX")), asn_type)),
                opt(preceded(tok(tag("MIN-ACCESS")), access_specifier)),
                macro_description,
            )),
        ),
    );
    let compliances = many1(alt((compliance_group, compliance_object)));
    let modules = many0(tuple((
        preceded(
            tok(tag("MODULE")),
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
            tok(tag("MODULE-COMPLIANCE")),
            macro_status,
            macro_description,
            macro_reference,
            modules,
            ptok(tag("::=")),
            oid_expr,
        )),
        |t| ModuleDecl::ModuleCompliance(t.0.to_string(), t.7),
    )(input)
}

/// Parse an `OBJECT-GROUP` macro.
fn object_group(input: &str) -> IResult<&str, ModuleDecl> {
    let objects = preceded(
        tok(tag("OBJECTS")),
        delimited(
            ptok(tag("{")),
            separated_list1(ptok(tag(",")), identifier),
            ptok(tag("}")),
        ),
    );
    map(
        tuple((
            identifier,
            tok(tag("OBJECT-GROUP")),
            objects,
            macro_status,
            macro_description,
            macro_reference,
            ptok(tag("::=")),
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
fn notification_group(input: &str) -> IResult<&str, ModuleDecl> {
    let notifications = preceded(
        tok(tag("NOTIFICATIONS")),
        delimited(
            ptok(tag("{")),
            separated_list1(tok(tag(",")), identifier),
            ptok(tag("}")),
        ),
    );
    map(
        tuple((
            identifier,
            tok(tag("NOTIFICATION-GROUP")),
            notifications,
            macro_status,
            macro_description,
            macro_reference,
            ptok(tag("::=")),
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
fn macro_def(input: &str) -> IResult<&str, ModuleDecl> {
    map(
        tuple((
            identifier,
            tok(tag("MACRO")),
            ptok(tag("::=")),
            tok(tag("BEGIN")),
            many_till(tok(not_line_ending), tok(tag("END"))),
        )),
        |t| ModuleDecl::MacroDef(t.0.to_string()),
    )(input)
}

/// Parse an `AGENT-CAPABILITIES` macro.
fn agent_capabilities(input: &str) -> IResult<&str, ModuleDecl> {
    let identifier_list = || separated_list1(ptok(tag(",")), identifier);
    let variation = tuple((
        preceded(tok(tag("VARIATION")), identifier),
        opt(preceded(tok(tag("SYNTAX")), asn_type)),
        opt(preceded(tok(tag("WRITE-SYNTAX")), asn_type)),
        opt(preceded(tok(tag("ACCESS")), access_specifier)),
        opt(preceded(
            tok(tag("CREATION-REQUIRES")),
            delimited(ptok(tag("{")), identifier_list(), ptok(tag("}"))),
        )),
        opt(macro_defval),
        macro_description,
    ));
    let module = tuple((
        preceded(tok(tag("SUPPORTS")), identifier),
        preceded(
            tok(tag("INCLUDES")),
            delimited(ptok(tag("{")), identifier_list(), ptok(tag("}"))),
        ),
        many0(variation),
    ));
    map(
        tuple((
            identifier,
            tok(tag("AGENT-CAPABILITIES")),
            preceded(tok(tag("PRODUCT-RELEASE")), quoted_string),
            macro_status,
            macro_description,
            macro_reference,
            many0(module),
            ptok(tag("::=")),
            oid_expr,
        )),
        |t| ModuleDecl::AgentCapabilities(t.0.to_string(), t.8),
    )(input)
}

/// Parse a `TRAP-TYPE` macro.
fn trap_type(input: &str) -> IResult<&str, ModuleDecl> {
    let identifier_list = || separated_list1(ptok(tag(",")), identifier);
    map(
        tuple((
            identifier,
            tok(tag("TRAP-TYPE")),
            preceded(tok(tag("ENTERPRISE")), identifier),
            preceded(
                tok(tag("VARIABLES")),
                delimited(ptok(tag("{")), identifier_list(), ptok(tag("}"))),
            ),
            macro_description,
            macro_reference,
            ptok(tag("::=")),
            tok(digit1),
        )),
        |_| ModuleDecl::Irrelevant,
    )(input)
}

/// Parse a MIB module.
///
/// This is the main entry point for the parser module.
pub fn parse_module(data: &str) -> IResult<&str, ParsedModule> {
    let module_decls = many0(alt((
        agent_capabilities,
        exports,
        imports,
        macro_def,
        module_compliance,
        module_identity,
        notification_group,
        notification_type,
        object_group,
        object_identity,
        object_type,
        plain_oid_def,
        textual_convention,
        // Must come after textual_convention.
        plain_type_def,
        trap_type,
    )));

    let module_begin = tuple((tok(tag("DEFINITIONS")), ptok(tag("::=")), tok(tag("BEGIN"))));
    let module_end = tok(tag("END"));
    let mut module = tuple((
        preceded(many0(ws_or_comment), identifier),
        delimited(module_begin, module_decls, module_end),
    ));

    let (rem, res) = module(data.trim())?;
    let ret = ParsedModule(res.0.to_string(), res.1);
    Ok((rem, ret))
}
