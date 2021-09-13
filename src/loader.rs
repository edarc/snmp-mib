//! Loading and parsing SMIv2 MIB module definitions.

use std::collections::HashMap;
use std::path::Path;

use crate::error::LoadFileError;
use crate::parser::asn_type::{BuiltinType, PlainType, Type};
use crate::parser::{parse_module, ModuleDecl, ParsedModule};
use crate::types::{Identifier, OidExpr};

/// A `ModuleDecl` from the parser, but with all identifiers fully qualified from imports.
#[derive(Clone, Debug)]
pub(crate) enum QualifiedDecl {
    AgentCapabilities(Identifier, OidExpr),
    MacroDef(Identifier),
    ModuleCompliance(Identifier, OidExpr),
    ModuleIdentity(Identifier, OidExpr),
    NotificationGroup(Identifier, OidExpr, Vec<Identifier>),
    NotificationType(Identifier, OidExpr, Vec<Identifier>),
    ObjectGroup(Identifier, OidExpr, Vec<Identifier>),
    ObjectIdentity(Identifier, OidExpr),
    ObjectType(Identifier, OidExpr, Type<Identifier>, ObjectTypeDetails),
    PlainOidDef(Identifier, OidExpr),
    PlainTypeDef(Identifier, Type<Identifier>),
    TextualConvention(Identifier, Type<Identifier>),
    Irrelevant,
}

#[derive(Clone, Debug)]
pub(crate) struct ObjectTypeDetails {
    pub(crate) unit_of_measure: Option<String>,
    pub(crate) indexing: Option<TableIndexing>,
}

#[derive(Clone, Debug)]
pub(crate) enum TableIndexing {
    Index(Vec<(Identifier, bool)>),
    Augments(Identifier),
}

trait Qualify {
    type Output;
    // This is &dyn Fn instead of impl Fn because some of the impls of this trait call each other
    // recursively, and to avoid moving the closure into them we need to ref it, but with impl it
    // recursively instantiates with more and more &'s in the type which explodes the compiler.
    fn qualify(self, resolve: &dyn Fn(String) -> Identifier) -> Self::Output;
}

impl Qualify for Type<String> {
    type Output = Type<Identifier>;
    fn qualify(self, resolve: &dyn Fn(String) -> Identifier) -> Self::Output {
        Type {
            ty: self.ty.qualify(resolve),
            constraint: self.constraint,
            tag: self.tag,
        }
    }
}

impl Qualify for PlainType<String> {
    type Output = PlainType<Identifier>;
    fn qualify(self, resolve: &dyn Fn(String) -> Identifier) -> Self::Output {
        match self {
            PlainType::Builtin(bi) => PlainType::Builtin(bi.qualify(resolve)),
            PlainType::Referenced(n, nvs) => PlainType::Referenced(resolve(n), nvs),
        }
    }
}

impl Qualify for BuiltinType<String> {
    type Output = BuiltinType<Identifier>;
    fn qualify(self, resolve: &dyn Fn(String) -> Identifier) -> Self::Output {
        use BuiltinType as BI;
        match self {
            BI::Boolean => BI::Boolean,
            BI::Choice(vs) => BI::Choice(
                vs.into_iter()
                    .map(|(v, ty)| (v, ty.qualify(resolve)))
                    .collect(),
            ),
            BI::Integer(nvs) => BI::Integer(nvs),
            BI::Null => BI::Null,
            BI::ObjectIdentifier => BI::ObjectIdentifier,
            BI::OctetString => BI::OctetString,
            BI::Sequence(fs) => BI::Sequence(
                fs.into_iter()
                    .map(|(f, ty)| (resolve(f), ty.qualify(resolve)))
                    .collect(),
            ),
            BI::SequenceOf(t) => BI::SequenceOf(Box::new(t.qualify(resolve))),
        }
    }
}

impl Qualify for crate::parser::ObjectTypeDetails {
    type Output = ObjectTypeDetails;
    fn qualify(self, resolve: &dyn Fn(String) -> Identifier) -> Self::Output {
        ObjectTypeDetails {
            unit_of_measure: self.unit_of_measure,
            indexing: self.indexing.map(|idx| idx.qualify(resolve)),
        }
    }
}

impl Qualify for crate::parser::TableIndexing {
    type Output = TableIndexing;
    fn qualify(self, resolve: &dyn Fn(String) -> Identifier) -> Self::Output {
        match self {
            crate::parser::TableIndexing::Index(cols) => TableIndexing::Index(
                cols.into_iter()
                    .map(|(id, implied)| (resolve(id), implied))
                    .collect(),
            ),
            crate::parser::TableIndexing::Augments(name) => TableIndexing::Augments(resolve(name)),
        }
    }
}

impl QualifiedDecl {
    /// Construct a `QualifiedDecl` from a `ModuleDecl` by applying a resolver function `resolve`
    /// to the unqualified identifiers in the `ModuleDecl`.
    fn from_module_decl(md: ModuleDecl, resolve: impl Fn(String) -> Identifier) -> Self {
        use ModuleDecl as MD;
        use QualifiedDecl as QD;
        let resolve = &resolve;
        match md {
            MD::AgentCapabilities(n, rd) => QD::AgentCapabilities(resolve(n), rd.qualify(resolve)),
            MD::MacroDef(n) => QD::MacroDef(resolve(n)),
            MD::ModuleCompliance(n, rd) => QD::ModuleCompliance(resolve(n), rd.qualify(resolve)),
            MD::ModuleIdentity(n, rd) => QD::ModuleIdentity(resolve(n), rd.qualify(resolve)),
            MD::NotificationGroup(n, rd, mi) => QD::NotificationGroup(
                resolve(n),
                rd.qualify(resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::NotificationType(n, rd, mi) => QD::NotificationType(
                resolve(n),
                rd.qualify(resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::ObjectGroup(n, rd, mi) => QD::ObjectGroup(
                resolve(n),
                rd.qualify(resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::ObjectIdentity(n, rd) => QD::ObjectIdentity(resolve(n), rd.qualify(resolve)),
            MD::ObjectType(n, rd, ti, det) => QD::ObjectType(
                resolve(n),
                rd.qualify(resolve),
                ti.qualify(resolve),
                det.qualify(resolve),
            ),
            MD::PlainOidDef(n, rd) => QD::PlainOidDef(resolve(n), rd.qualify(resolve)),
            MD::PlainTypeDef(n, ti) => QD::PlainTypeDef(resolve(n), ti.qualify(resolve)),
            MD::TextualConvention(n, ti) => QD::TextualConvention(resolve(n), ti.qualify(resolve)),
            MD::Imports(_) | MD::Irrelevant => QD::Irrelevant,
        }
    }

    /// Extract an OID definition, if this declaration creates one.
    pub(crate) fn oid_definition(&self) -> Option<(Identifier, OidExpr)> {
        use QualifiedDecl as QD;
        match self {
            QD::AgentCapabilities(n, rd) => Some((n.clone(), rd.clone())),
            QD::ModuleCompliance(n, rd) => Some((n.clone(), rd.clone())),
            QD::ModuleIdentity(n, rd) => Some((n.clone(), rd.clone())),
            QD::NotificationGroup(n, rd, _) => Some((n.clone(), rd.clone())),
            QD::NotificationType(n, rd, _) => Some((n.clone(), rd.clone())),
            QD::ObjectGroup(n, rd, _) => Some((n.clone(), rd.clone())),
            QD::ObjectIdentity(n, rd) => Some((n.clone(), rd.clone())),
            QD::ObjectType(n, rd, ..) => Some((n.clone(), rd.clone())),
            QD::PlainOidDef(n, rd) => Some((n.clone(), rd.clone())),
            QD::MacroDef(_) | QD::PlainTypeDef(..) | QD::TextualConvention(..) | QD::Irrelevant => {
                None
            }
        }
    }
}

/// Loads and parses SMIv2 MIB module definitions.
///
/// It is used to load MIB modules from multiple files. It prepares each parsed module to be
/// compiled into a MIB by resolving all identifiers to fully-qualified ones based on `IMPORTS`.
#[derive(Clone, Debug)]
pub struct Loader(pub(crate) Vec<QualifiedDecl>);

impl Loader {
    /// Create a new `Loader` with no modules loaded.
    pub fn new() -> Self {
        Loader(Vec::new())
    }

    /// Load a MIB module from a file.
    ///
    /// This can be called repeatedly to load multiple MIB modules prior to compiling into a MIB.
    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<(), LoadFileError> {
        let module_name_fixups = vec![("RFC-1213".to_string(), "RFC1213-MIB".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();

        let file = String::from_utf8(std::fs::read(path.as_ref())?)?;
        let (_, ParsedModule(this_module, mut decls)) = parse_module(&file)?;

        // Find the index of every Imports decl.
        let import_idxs = decls
            .iter()
            .enumerate()
            .filter(|(_, decl)| decl.is_imports())
            .map(|(name, _)| name)
            .collect::<Vec<_>>();

        // Pop each index we found above, in reverse order because index invalidation, and flat-map
        // all of the contained HashMaps together.
        let imports = import_idxs
            .into_iter()
            .rev()
            .map(|idx| decls.remove(idx))
            .flat_map(|decl| match decl {
                ModuleDecl::Imports(map) => map,
                _ => HashMap::new(),
            })
            .map(|(name, source_module)| {
                (
                    name,
                    module_name_fixups
                        .get(&source_module)
                        .unwrap_or(&source_module)
                        .to_string(),
                )
            })
            .collect::<HashMap<_, _>>();

        // Generate a closure over the imports for this module that resolves a String containing an
        // unqualified name in that module, to a qualified Identifier.
        let resolve = {
            let imports = &imports;
            let this_module = &this_module;
            move |name: String| {
                let module_name = if name == "" || name == "iso" {
                    ""
                } else {
                    imports.get(&name).unwrap_or(this_module)
                };
                Identifier::new(module_name, name)
            }
        };

        // Extend our vector of declarations with the results of qualifying (with the above
        // closure) all of the declarations from the module just parsed.
        self.0.extend(
            decls
                .into_iter()
                .map(|d| QualifiedDecl::from_module_decl(d, resolve)),
        );

        Ok(())
    }
}
