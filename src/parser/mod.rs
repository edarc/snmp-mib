//! The parser for MIB module definitions.
//!
//! The main API surface consists of `ModuleDecl` and `parse_module`, where the latter parses a MIB
//! module into a sequence of the former.

pub mod asn_type;
pub mod atoms;
pub mod decls;

use std::collections::HashMap;

use crate::parser::asn_type::Type;
use crate::parser::atoms::{identifier, ptok, tok, ws_or_comment};
use crate::types::identifier::Identifier;
use crate::types::oid_expr::OidExpr;

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

/// Parse a MIB module.
///
/// This is the main entry point for the parser module.
pub fn parse_module(data: &str) -> IResult<&str, ParsedModule> {
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
