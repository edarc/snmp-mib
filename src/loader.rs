use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

use crate::parser::{parse_module, BuiltinType, ModuleDecl, ParsedModule, PlainType, Type};
use crate::{Identifier, OidExpr};

/// A `ModuleDecl` from the parser, but with all identifiers fully qualified from imports.
#[derive(Clone, Debug)]
pub enum QualifiedDecl {
    AgentCapabilities(Identifier, OidExpr),
    MacroDef(Identifier),
    ModuleCompliance(Identifier, OidExpr),
    ModuleIdentity(Identifier, OidExpr),
    NotificationGroup(Identifier, OidExpr, Vec<Identifier>),
    NotificationType(Identifier, OidExpr, Vec<Identifier>),
    ObjectGroup(Identifier, OidExpr, Vec<Identifier>),
    ObjectIdentity(Identifier, OidExpr),
    ObjectType(Identifier, OidExpr, Type<Identifier>, Option<String>),
    PlainOidDef(Identifier, OidExpr),
    PlainTypeDef(Identifier, Type<Identifier>),
    TextualConvention(Identifier, Type<Identifier>),
    Irrelevant,
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
            PlainType::Referenced(i, nvs) => PlainType::Referenced(resolve(i), nvs),
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
                    .map(|(f, ty)| (f, ty.qualify(resolve)))
                    .collect(),
            ),
            BI::SequenceOf(t) => BI::SequenceOf(Box::new(t.qualify(resolve))),
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
            MD::AgentCapabilities(i, rd) => QD::AgentCapabilities(resolve(i), rd.qualify(resolve)),
            MD::MacroDef(i) => QD::MacroDef(resolve(i)),
            MD::ModuleCompliance(i, rd) => QD::ModuleCompliance(resolve(i), rd.qualify(resolve)),
            MD::ModuleIdentity(i, rd) => QD::ModuleIdentity(resolve(i), rd.qualify(resolve)),
            MD::NotificationGroup(i, rd, mi) => QD::NotificationGroup(
                resolve(i),
                rd.qualify(resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::NotificationType(i, rd, mi) => QD::NotificationType(
                resolve(i),
                rd.qualify(resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::ObjectGroup(i, rd, mi) => QD::ObjectGroup(
                resolve(i),
                rd.qualify(resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::ObjectIdentity(i, rd) => QD::ObjectIdentity(resolve(i), rd.qualify(resolve)),
            MD::ObjectType(i, rd, ti, u) => {
                QD::ObjectType(resolve(i), rd.qualify(resolve), ti.qualify(resolve), u)
            }
            MD::PlainOidDef(i, rd) => QD::PlainOidDef(resolve(i), rd.qualify(resolve)),
            MD::PlainTypeDef(i, ti) => QD::PlainTypeDef(resolve(i), ti.qualify(resolve)),
            MD::TextualConvention(i, ti) => QD::TextualConvention(resolve(i), ti.qualify(resolve)),
            MD::Imports(_) | MD::Irrelevant => QD::Irrelevant,
        }
    }

    /// Extract an OID definition, if this declaration creates one.
    pub(crate) fn oid_definition(&self) -> Option<(Identifier, OidExpr)> {
        use QualifiedDecl as QD;
        match self {
            QD::AgentCapabilities(i, rd) => Some((i.clone(), rd.clone())),
            QD::ModuleCompliance(i, rd) => Some((i.clone(), rd.clone())),
            QD::ModuleIdentity(i, rd) => Some((i.clone(), rd.clone())),
            QD::NotificationGroup(i, rd, _) => Some((i.clone(), rd.clone())),
            QD::NotificationType(i, rd, _) => Some((i.clone(), rd.clone())),
            QD::ObjectGroup(i, rd, _) => Some((i.clone(), rd.clone())),
            QD::ObjectIdentity(i, rd) => Some((i.clone(), rd.clone())),
            QD::ObjectType(i, rd, ..) => Some((i.clone(), rd.clone())),
            QD::PlainOidDef(i, rd) => Some((i.clone(), rd.clone())),
            QD::MacroDef(_) | QD::PlainTypeDef(..) | QD::TextualConvention(..) | QD::Irrelevant => {
                None
            }
        }
    }
}

/// Loader loads MIB modules from multiple files and resolves all identifiers to fully-qualified
/// ones.
#[derive(Clone, Debug)]
pub struct Loader(pub Vec<QualifiedDecl>);

impl Loader {
    pub fn new() -> Self {
        Loader(Vec::new())
    }

    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<(), Box<dyn Error>> {
        let module_name_fixups = vec![("RFC-1213".to_string(), "RFC1213-MIB".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();

        let file = String::from_utf8(std::fs::read(path.as_ref())?)?;
        let (_, ParsedModule(this_module, mut decls)) =
            parse_module(&file).map_err(|e| e.to_string())?;

        // Find the index of every Imports decl.
        let import_idxs = decls
            .iter()
            .enumerate()
            .filter(|(_, d)| d.is_imports())
            .map(|(i, _)| i)
            .collect::<Vec<_>>();

        // Pop each index we found above, in reverse order because index invalidation, and flat-map
        // all of the contained HashMaps together.
        let imports = import_idxs
            .into_iter()
            .rev()
            .map(|i| decls.remove(i))
            .flat_map(|d| match d {
                ModuleDecl::Imports(h) => h,
                _ => HashMap::new(),
            })
            .map(|(n, m)| (n, module_name_fixups.get(&m).unwrap_or(&m).to_string()))
            .collect::<HashMap<_, _>>();

        // Generate a closure over the imports for this module that resolves a String containing an
        // unqualified name in that module, to a qualified Identifier.
        let resolve = {
            let imports = &imports;
            let this_module = &this_module;
            move |id: String| {
                let module_name = if id == "" || id == "iso" {
                    ""
                } else {
                    imports.get(&id).unwrap_or(this_module)
                }
                .to_string();
                Identifier(module_name, id)
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
