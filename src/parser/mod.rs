//! The parser for MIB module definitions.
//!
//! In general the parser is an implementation detail, but `snmp-mib` does expose the parsed ASN.1
//! types of objects, and the Rust types that represent those ASN.1 types are defined here.

pub(crate) mod asn_type;
mod atoms;
mod decls;

pub use asn_type::{
    BuiltinType, Constraint, ConstraintRange, PlainType, Type, TypeTag, TypeTagClass, TypeTagKind,
};

use std::collections::HashMap;

use crate::parser::atoms::{identifier, ptok, tok, ws_or_comment};
use crate::types::{Identifier, OidExpr};

use nom::{
    branch::alt,
    bytes::complete::tag,
    multi::many0,
    sequence::{delimited, preceded, tuple},
    IResult,
};
use smallvec::SmallVec;

/// This is like an OidExpr except the root identifier's module name is unresolved. Resolution
/// happens in the `Loader`.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RawOidExpr {
    parent: String,
    fragment: SmallVec<[u32; 1]>,
}

impl RawOidExpr {
    /// Convert this `RawOidExpr` into an `OidExpr` by qualifying the parent identifier. The
    /// provided function should return a qualified `Identifier` given the unqualified identifier
    /// as a &str.
    pub(crate) fn qualify(self, resolve: impl Fn(String) -> Identifier) -> OidExpr {
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
pub(crate) enum ModuleDecl {
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
pub(crate) struct ObjectTypeDetails {
    pub(crate) unit_of_measure: Option<String>,
    pub(crate) indexing: Option<TableIndexing>,
}

#[derive(Clone, Debug)]
pub(crate) enum TableIndexing {
    Index(Vec<(String, bool)>),
    Augments(String),
}

impl ModuleDecl {
    pub(crate) fn is_imports(&self) -> bool {
        match self {
            ModuleDecl::Imports(_) => true,
            _ => false,
        }
    }
}

/// This is the result of the parser, consisting of the module name and a sequence of
/// `ModuleDecl`s.
#[derive(Clone, Debug)]
pub(crate) struct ParsedModule(pub(crate) String, pub(crate) Vec<ModuleDecl>);

/// Parse a MIB module.
///
/// This is the main entry point for the parser module.
pub(crate) fn parse_module(data: &str) -> IResult<&str, ParsedModule> {
    let module_decls = many0(alt((
        decls::agent_capabilities,
        decls::exports,
        decls::imports,
        decls::macro_def,
        decls::module_compliance,
        decls::module_identity,
        decls::notification_group,
        decls::notification_type,
        decls::object_group,
        decls::object_identity,
        decls::object_type,
        decls::plain_oid_def,
        decls::textual_convention,
        // Must come after textual_convention.
        decls::plain_type_def,
        decls::trap_type,
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
