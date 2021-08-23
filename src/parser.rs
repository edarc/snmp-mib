//! The parser for MIB module definitions.
//!
//! The main API surface consists of `ModuleDecl` and `parse_module`, where the latter parses a MIB
//! module into a sequence of the former.

use std::collections::HashMap;
use std::convert::TryInto;

use crate::{Identifier, OidDef, TypeInfo};

use nom::{
    branch::alt,
    bytes::complete::{is_not, tag},
    character::complete::{
        alpha1, alphanumeric1, digit1, hex_digit1, multispace1, not_line_ending, one_of,
    },
    combinator::{eof, map, not, opt, peek, recognize, value},
    error::{context, ContextError, ParseError},
    multi::{many0, many1, many_till, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};
use smallvec::SmallVec;

/// This is like an OidDef except the root identifier's module name is unresolved. Resolution
/// happens in the `Loader`.
#[derive(Clone, Debug)]
pub struct RawOidDef {
    root: String,
    fragment: SmallVec<[u32; 1]>,
}

impl RawOidDef {
    /// Convert this `RawOidDef` into an `OidDef` by qualifying the root identifier. The provided
    /// function should return a qualified `Identifier` given the unqualified identifier as a &str.
    pub fn qualify(self, resolve: impl Fn(String) -> Identifier) -> OidDef {
        let id = resolve(self.root);
        OidDef {
            root: id,
            fragment: self.fragment,
        }
    }
}

/// The various kinds of declarations that occur in a MIB module. A parsed MIB module is
/// essentially a sequence of these.
#[derive(Clone, Debug)]
pub enum ModuleDecl {
    AgentCapabilities(String, RawOidDef),
    Imports(HashMap<String, String>),
    MacroDef(String),
    ModuleCompliance(String, RawOidDef),
    ModuleIdentity(String, RawOidDef),
    NotificationGroup(String, RawOidDef, Vec<String>),
    NotificationType(String, RawOidDef, Vec<String>),
    ObjectGroup(String, RawOidDef, Vec<String>),
    ObjectIdentity(String, RawOidDef),
    ObjectType(String, RawOidDef, TypeInfo, Option<String>),
    PlainOidDef(String, RawOidDef),
    Sequence(String),
    TextualConvention(String, TypeInfo),
    TypeDef(String, TypeInfo),
    Irrelevant,
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

/// Parse whitespace or comments and throw them away. Does *not* match zero length.
fn ws_or_comment<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, (), E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let white = || value((), multispace1);
    let comment = || value((), pair(tag("--"), not_line_ending));
    value((), alt((comment(), white())))
}

/// Wrap a punctuation parser to eat trailing whitespace.
///
/// The entire parser is written with the invariant that whitespace and comments are always
/// stripped off the stream *after* each parsed item -- in other words, every parser leaves the
/// remaining string starting with something that is *not* whitespace or comment.
///
/// This whitespace eater is used for punctuation instead of `tok` as it will accept zero-length
/// whitespace or comments after the token.
fn ptok<'a, F, O, E>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    F: 'a + FnMut(&'a str) -> IResult<&'a str, O, E>,
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    terminated(inner, many0(ws_or_comment()))
}

/// Wrap a non-punctuation parser to eat trailing whitespace.
///
/// The entire parser is written with the invariant that whitespace and comments are always
/// stripped off the stream *after* each parsed item -- in other words, every parser leaves the
/// remaining string starting with something that is *not* whitespace or comment.
///
/// This whitespace eater is used for non-punctuation instead of `ptok` as it requires either some
/// amount of whitespace or comments (which it discards), or punctuation or EOF (which it does not
/// consume) after the token. This prevents the problem of `ptok(tag("FOO"))` successfully matching
/// `"FOObar"`, for example, when `FOO` is a keyword and `bar` is an identifier.
fn tok<'a, F, O, E>(inner: F) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    F: 'a + FnMut(&'a str) -> IResult<&'a str, O, E>,
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let punc = || value((), peek(one_of(".,;:(){}<>=|")));
    let end = || value((), eof);
    let del = || alt((value((), many1(ws_or_comment())), punc(), end()));
    terminated(inner, del())
}

/// Parse a MIB identifier.
fn identifier<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    tok(recognize(pair(
        alpha1,
        many0(alt((alphanumeric1, tag("-")))),
    )))
}

/// Parse an OID definition.
///
/// This requires that every entry in the definition except the first either be a plain integer, or
/// a name with an associated integer like `dod(2)`.
fn oid_def<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, RawOidDef, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let num = || map(digit1, |v: &str| v.parse::<u32>().unwrap());
    let oid_elem = alt((
        num(),
        delimited(pair(identifier(), tag("(")), num(), tag(")")),
    ));

    map(
        delimited(
            ptok(tag("{")),
            pair(opt(identifier()), many0(tok(oid_elem))),
            ptok(tag("}")),
        ),
        |(id, frag)| RawOidDef {
            root: id.unwrap_or("").to_string(),
            fragment: frag.into(),
        },
    )
}

/// Parse a `STATUS` stanza in an SMI macro.
fn macro_status<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    preceded(
        tok(tag("STATUS")),
        tok(alt((
            tag("mandatory"),
            tag("optional"),
            tag("current"),
            tag("deprecated"),
            tag("obsolete"),
        ))),
    )
}

/// Parse a `DESCRIPTION` stanza in an SMI macro.
fn macro_description<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    preceded(tok(tag("DESCRIPTION")), quoted_string())
}

/// Parse a `REFERENCE` stanza in an SMI macro.
fn macro_reference<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, Option<&'a str>, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    opt(preceded(tok(tag("REFERENCE")), quoted_string()))
}

/// Parse a `DEFVAL` stanza in an SMI macro.
fn macro_defval<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let defval_val = alt((
        delimited(ptok(tag("{")), is_not("}"), ptok(tag("}"))),
        value("", pair(ptok(tag("{")), ptok(tag("}")))),
        is_not("}"),
    ));
    preceded(
        tok(tag("DEFVAL")),
        delimited(ptok(tag("{")), defval_val, ptok(tag("}"))),
    )
}

/// Parse an access specifier.
///
/// Depending on which macro it occurs in, only certain subsets of specifiers are grammatically
/// valid by the standard, but that is ignored here and this parser is used universally to accept
/// any allowed specifiers from every macro defined in SMI.
fn access_specifier<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    tok(alt((
        tag("accessible-for-notify"),
        tag("not-accessible"),
        tag("not-implemented"),
        tag("read-create"),
        tag("read-only"),
        tag("read-write"),
    )))
}

/// Parse a double-quoted string.
///
/// String may potentially span many lines, as is common in MIB definitions. Does not currently
/// support escaped close-quote.
fn quoted_string<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, &'a str, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    delimited(
        tag("\""),
        map(opt(is_not("\"")), |s| s.unwrap_or("")),
        tok(tag("\"")),
    )
}

/// Parse an `IMPORTS` stanza.
///
/// Order and structure is not preserved; the parsed result contains a hash with a key for each
/// imported name, and associated value the name of the module from which it was imported.
fn imports<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let import = map(
        separated_pair(
            separated_list1(ptok(tag(",")), identifier()),
            tok(tag("FROM")),
            identifier(),
        ),
        |(ids, modname)| {
            ids.into_iter()
                .map(|id| (id, modname.clone()))
                .collect::<Vec<_>>()
        },
    );

    map(
        delimited(tok(tag("IMPORTS")), many1(import), tok(tag(";"))),
        |many| {
            let imported_names = many
                .into_iter()
                .flatten()
                .map(|(i, m)| (i.to_string(), m.to_string()))
                .collect::<HashMap<_, _>>();
            ModuleDecl::Imports(imported_names)
        },
    )
}

/// Parse and discard an `EXPORTS` stanza.
///
/// Successful parse always produces a `ModuleDecl::Irrelevant`.
fn exports<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    value(
        ModuleDecl::Irrelevant,
        delimited(
            tok(tag("EXPORTS")),
            separated_list1(tok(tag(",")), identifier()),
            tok(tag(";")),
        ),
    )
}

/// Parse a `MODULE-IDENTITY` macro.
fn module_identity<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let revision = tuple((tok(tag("REVISION")), quoted_string(), macro_description()));

    map(
        tuple((
            identifier(),
            tok(tag("MODULE-IDENTITY")),
            preceded(tok(tag("LAST-UPDATED")), quoted_string()),
            preceded(tok(tag("ORGANIZATION")), quoted_string()),
            preceded(tok(tag("CONTACT-INFO")), quoted_string()),
            macro_description(),
            many0(revision),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| ModuleDecl::ModuleIdentity(t.0.to_string(), t.8),
    )
}

/// Parse an ASN type specification.
///
/// See `TypeInfo` for more information; tl;dr most types result in
/// `TypeInfo::Uninterpreted("...")` and only "interesting" types are parsed into their own
/// variants.
fn asn_type<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, TypeInfo, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let signed = || {
        alt((
            recognize(pair(opt(tag("-")), digit1)),
            recognize(delimited(tag("'"), hex_digit1, ptok(tag("'h")))),
        ))
    };
    let range = || {
        recognize(separated_pair(
            tok(signed()),
            ptok(tag("..")),
            tok(signed()),
        ))
    };
    let alternates = || {
        context(
            "alternates",
            recognize(separated_list1(
                ptok(tag("|")),
                tok(alt((range(), signed()))),
            )),
        )
    };
    let size = || {
        context(
            "size",
            recognize(pair(
                tok(tag("SIZE")),
                delimited(ptok(tag("(")), alternates(), ptok(tag(")"))),
            )),
        )
    };
    let constraint = || {
        context(
            "constraint",
            opt(delimited(
                ptok(tag("(")),
                alt((alternates(), size())),
                ptok(tag(")")),
            )),
        )
    };

    let type_names = || {
        context(
            "type name",
            alt((
                tok(recognize(pair(tok(tag("OCTET")), tag("STRING")))),
                identifier(),
            )),
        )
    };
    let type_tag = context(
        "type tag",
        tuple((ptok(tag("[")), is_not("]"), ptok(tag("]")))),
    );
    let type_decl = context(
        "type decl",
        tuple((
            opt(type_tag),
            opt(tok(tag("IMPLICIT"))),
            opt(pair(tok(tag("SEQUENCE")), tok(tag("OF")))),
            type_names(),
            constraint(),
        )),
    );

    let variant = || {
        pair(
            identifier(),
            delimited(
                ptok(tag("(")),
                tok(map(signed(), |v: &str| v.parse::<i64>().unwrap())),
                ptok(tag(")")),
            ),
        )
    };
    let variants = || separated_list1(ptok(tag(",")), variant());

    alt((
        map(
            context(
                "bit field",
                pair(
                    tok(tag("BITS")),
                    delimited(ptok(tag("{")), variants(), ptok(tag("}"))),
                ),
            ),
            |t| {
                let vs =
                    t.1.into_iter()
                        .map(|(id, v)| (v.try_into().unwrap(), id.to_string()))
                        .collect();
                TypeInfo::BitField(vs)
            },
        ),
        map(
            context(
                "enum",
                pair(
                    type_names(),
                    delimited(ptok(tag("{")), variants(), ptok(tag("}"))),
                ),
            ),
            |t| {
                let vs = t.1.into_iter().map(|(id, v)| (v, id.to_string())).collect();
                TypeInfo::Enumeration(vs)
            },
        ),
        value(
            TypeInfo::Oid,
            context("oid decl", pair(tok(tag("OBJECT")), tok(tag("IDENTIFIER")))),
        ),
        map(
            context(
                "choice enum",
                recognize(tuple((
                    tok(tag("CHOICE")),
                    ptok(tag("{")),
                    many_till(tok(not_line_ending), ptok(tag("}"))),
                ))),
            ),
            |t| TypeInfo::Uninterpreted(t.trim().to_string()),
        ),
        map(context("type decl", recognize(type_decl)), |t| {
            TypeInfo::Uninterpreted(t.trim().to_string())
        }),
    ))
}

/// Parse a `TEXTUAL-CONVENTION` macro.
fn textual_convention<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        tuple((
            identifier(),
            ptok(tag("::=")),
            tok(tag("TEXTUAL-CONVENTION")),
            opt(preceded(tok(tag("DISPLAY-HINT")), quoted_string())),
            macro_status(),
            macro_description(),
            macro_reference(),
            preceded(tok(tag("SYNTAX")), asn_type()),
        )),
        |t| ModuleDecl::TextualConvention(t.0.to_string(), t.7),
    )
}

/// Parse a plain OID definition (one defined in ASN.1 without an SMI macro).
fn plain_oid_def<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        tuple((
            identifier(),
            tok(tag("OBJECT")),
            tok(tag("IDENTIFIER")),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| ModuleDecl::PlainOidDef(t.0.to_string(), t.4),
    )
}

/// Parse a plain type definition (one defined in ASN.1 without an SMI macro).
fn plain_type_def<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(tuple((identifier(), ptok(tag("::=")), asn_type())), |t| {
        ModuleDecl::TypeDef(t.0.to_string(), t.2)
    })
}

/// Parse an `OBJECT-IDENTITY` macro.
fn object_identity<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        tuple((
            identifier(),
            tok(tag("OBJECT-IDENTITY")),
            macro_status(),
            macro_description(),
            macro_reference(),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| ModuleDecl::ObjectIdentity(t.0.to_string(), t.6),
    )
}

/// Parse an `OBJECT-TYPE` macro.
fn object_type<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let index = value(
        (),
        preceded(
            tok(tag("INDEX")),
            delimited(
                ptok(tag("{")),
                separated_list1(ptok(tag(",")), pair(opt(tok(tag("IMPLIED"))), identifier())),
                ptok(tag("}")),
            ),
        ),
    );
    let augments = value(
        (),
        preceded(
            tok(tag("AUGMENTS")),
            delimited(ptok(tag("{")), identifier(), ptok(tag("}"))),
        ),
    );
    map(
        tuple((
            identifier(),
            tok(tag("OBJECT-TYPE")),
            preceded(tok(tag("SYNTAX")), asn_type()),
            opt(preceded(tok(tag("UNITS")), quoted_string())),
            preceded(
                tok(alt((tag("MAX-ACCESS"), tag("ACCESS")))),
                access_specifier(),
            ),
            macro_status(),
            macro_description(),
            macro_reference(),
            opt(alt((index, augments))),
            opt(macro_defval()),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| ModuleDecl::ObjectType(t.0.to_string(), t.11, t.2, t.3.map(|s| s.to_string())),
    )
}

/// Parse a `NOTIFICATION-TYPE` macro.
fn notification_type<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let objects = separated_list1(tok(tag(",")), identifier());
    map(
        tuple((
            identifier(),
            tok(tag("NOTIFICATION-TYPE")),
            opt(preceded(
                tok(tag("OBJECTS")),
                delimited(ptok(tag("{")), objects, ptok(tag("}"))),
            )),
            macro_status(),
            macro_description(),
            macro_reference(),
            ptok(tag("::=")),
            oid_def(),
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
    )
}

/// Parse a plain sequence definition (one defined in ASN.1 without an SMI macro).
fn plain_sequence_def<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let field = pair(identifier(), asn_type());
    let fields = separated_list1(tok(tag(",")), field);

    map(
        tuple((
            identifier(),
            ptok(tag("::=")),
            tok(tag("SEQUENCE")),
            delimited(ptok(tag("{")), fields, ptok(tag("}"))),
        )),
        |t| ModuleDecl::Sequence(t.0.to_string()),
    )
}

/// Parse a `MODULE-COMPLIANCE` macro.
fn module_compliance<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let mandatory_groups = preceded(
        tok(tag("MANDATORY-GROUPS")),
        delimited(
            ptok(tag("{")),
            separated_list1(tok(tag(",")), identifier()),
            ptok(tag("}")),
        ),
    );
    let compliance_group = preceded(
        tok(tag("GROUP")),
        terminated(identifier(), macro_description()),
    );
    let compliance_object = preceded(
        tok(tag("OBJECT")),
        terminated(
            identifier(),
            tuple((
                opt(preceded(tok(tag("SYNTAX")), asn_type())),
                opt(preceded(tok(tag("WRITE-SYNTAX")), asn_type())),
                opt(preceded(tok(tag("MIN-ACCESS")), access_specifier())),
                macro_description(),
            )),
        ),
    );
    let compliances = many1(alt((compliance_group, compliance_object)));
    let modules = many0(tuple((
        preceded(
            tok(tag("MODULE")),
            opt(pair(
                not(alt((tag("MANDATORY-GROUPS"), tag("OBJECT"), tag("GROUP")))),
                identifier(),
            )),
        ),
        opt(mandatory_groups),
        opt(compliances),
    )));

    map(
        tuple((
            identifier(),
            tok(tag("MODULE-COMPLIANCE")),
            macro_status(),
            macro_description(),
            macro_reference(),
            modules,
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| ModuleDecl::ModuleCompliance(t.0.to_string(), t.7),
    )
}

/// Parse an `OBJECT-GROUP` macro.
fn object_group<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let objects = preceded(
        tok(tag("OBJECTS")),
        delimited(
            ptok(tag("{")),
            separated_list1(tok(tag(",")), identifier()),
            ptok(tag("}")),
        ),
    );
    map(
        tuple((
            identifier(),
            tok(tag("OBJECT-GROUP")),
            objects,
            macro_status(),
            macro_description(),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| {
            ModuleDecl::ObjectGroup(
                t.0.to_string(),
                t.6,
                t.2.into_iter().map(|s| s.to_string()).collect(),
            )
        },
    )
}

/// Parse a `NOTIFICATION-GROUP` macro.
fn notification_group<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let notifications = preceded(
        tok(tag("NOTIFICATIONS")),
        delimited(
            ptok(tag("{")),
            separated_list1(tok(tag(",")), identifier()),
            ptok(tag("}")),
        ),
    );
    map(
        tuple((
            identifier(),
            tok(tag("NOTIFICATION-GROUP")),
            notifications,
            macro_status(),
            macro_description(),
            macro_reference(),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| {
            ModuleDecl::NotificationGroup(
                t.0.to_string(),
                t.7,
                t.2.into_iter().map(|s| s.to_string()).collect(),
            )
        },
    )
}

/// Parse a macro definition.
///
/// The name is returned but the body is thrown away, as the grammars for SMI macros are all
/// hard-coded in this parser.
fn macro_def<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    map(
        tuple((
            identifier(),
            tok(tag("MACRO")),
            ptok(tag("::=")),
            tok(tag("BEGIN")),
            many_till(tok(not_line_ending), tok(tag("END"))),
        )),
        |t| ModuleDecl::MacroDef(t.0.to_string()),
    )
}

/// Parse an `AGENT-CAPABILITIES` macro.
fn agent_capabilities<'a, E>() -> impl FnMut(&'a str) -> IResult<&'a str, ModuleDecl, E>
where
    E: 'a + ParseError<&'a str> + ContextError<&'a str>,
{
    let identifier_list = || separated_list1(ptok(tag(",")), identifier());
    let variation = tuple((
        preceded(tok(tag("VARIATION")), identifier()),
        opt(preceded(tok(tag("SYNTAX")), asn_type())),
        opt(preceded(tok(tag("WRITE-SYNTAX")), asn_type())),
        opt(preceded(tok(tag("ACCESS")), access_specifier())),
        opt(preceded(
            tok(tag("CREATION-REQUIRES")),
            delimited(ptok(tag("{")), identifier_list(), ptok(tag("}"))),
        )),
        opt(macro_defval()),
        macro_description(),
    ));
    let module = tuple((
        preceded(tok(tag("SUPPORTS")), identifier()),
        preceded(
            tok(tag("INCLUDES")),
            delimited(ptok(tag("{")), identifier_list(), ptok(tag("}"))),
        ),
        many0(variation),
    ));
    map(
        tuple((
            identifier(),
            tok(tag("AGENT-CAPABILITIES")),
            preceded(tok(tag("PRODUCT-RELEASE")), quoted_string()),
            macro_status(),
            macro_description(),
            macro_reference(),
            many0(module),
            ptok(tag("::=")),
            oid_def(),
        )),
        |t| ModuleDecl::AgentCapabilities(t.0.to_string(), t.8),
    )
}

/// Parse a MIB module.
///
/// This is the main entry point for the parser module.
pub fn parse_module(data: &str) -> IResult<&str, ParsedModule> {
    let module_decls = many0(alt((
        agent_capabilities(),
        exports(),
        imports(),
        macro_def(),
        module_compliance(),
        module_identity(),
        notification_group(),
        notification_type(),
        object_group(),
        object_identity(),
        object_type(),
        plain_oid_def(),
        plain_sequence_def(),
        textual_convention(),
        // Must come after textual_convention.
        plain_type_def(),
    )));

    let module_begin = tuple((tok(tag("DEFINITIONS")), ptok(tag("::=")), tok(tag("BEGIN"))));
    let module_end = tok(tag("END"));
    let mut module = tuple((
        preceded(many0(ws_or_comment()), identifier()),
        delimited(module_begin, module_decls, module_end),
    ));

    let (rem, res) = module(data.trim())?;
    let ret = ParsedModule(res.0.to_string(), res.1);
    Ok((rem, ret))
}