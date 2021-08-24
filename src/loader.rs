use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

use crate::parser::{parse_module, ModuleDecl, ParsedModule};
use crate::{Identifier, OidDef, TypeInfo};

/// A `ModuleDecl` from the parser, but with all identifiers fully qualified from imports.
#[derive(Clone, Debug)]
pub enum QualifiedDecl {
    AgentCapabilities(Identifier, OidDef),
    MacroDef(Identifier),
    ModuleCompliance(Identifier, OidDef),
    ModuleIdentity(Identifier, OidDef),
    NotificationGroup(Identifier, OidDef, Vec<Identifier>),
    NotificationType(Identifier, OidDef, Vec<Identifier>),
    ObjectGroup(Identifier, OidDef, Vec<Identifier>),
    ObjectIdentity(Identifier, OidDef),
    ObjectType(Identifier, OidDef, TypeInfo, Option<String>),
    PlainOidDef(Identifier, OidDef),
    PlainSequence(Identifier),
    PlainTypeDef(Identifier, TypeInfo),
    TextualConvention(Identifier, TypeInfo),
    Irrelevant,
}

impl QualifiedDecl {
    /// Construct a `QualifiedDecl` from a `ModuleDecl` by applying a resolver function `resolve`
    /// to the unqualified identifiers in the `ModuleDecl`.
    fn from_module_decl(md: ModuleDecl, resolve: impl Fn(String) -> Identifier) -> Self {
        use ModuleDecl as MD;
        use QualifiedDecl as RD;
        match md {
            MD::AgentCapabilities(i, rd) => RD::AgentCapabilities(resolve(i), rd.qualify(resolve)),
            MD::MacroDef(i) => RD::MacroDef(resolve(i)),
            MD::ModuleCompliance(i, rd) => RD::ModuleCompliance(resolve(i), rd.qualify(resolve)),
            MD::ModuleIdentity(i, rd) => RD::ModuleIdentity(resolve(i), rd.qualify(resolve)),
            MD::NotificationGroup(i, rd, mi) => RD::NotificationGroup(
                resolve(i),
                rd.qualify(&resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::NotificationType(i, rd, mi) => RD::NotificationType(
                resolve(i),
                rd.qualify(&resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::ObjectGroup(i, rd, mi) => RD::ObjectGroup(
                resolve(i),
                rd.qualify(&resolve),
                mi.into_iter().map(resolve).collect(),
            ),
            MD::ObjectIdentity(i, rd) => RD::ObjectIdentity(resolve(i), rd.qualify(resolve)),
            MD::ObjectType(i, rd, ti, u) => RD::ObjectType(resolve(i), rd.qualify(resolve), ti, u),
            MD::PlainOidDef(i, rd) => RD::PlainOidDef(resolve(i), rd.qualify(resolve)),
            MD::PlainSequence(i) => RD::PlainSequence(resolve(i)),
            MD::PlainTypeDef(i, ti) => RD::PlainTypeDef(resolve(i), ti),
            MD::TextualConvention(i, ti) => RD::TextualConvention(resolve(i), ti),
            MD::Imports(_) | MD::Irrelevant => RD::Irrelevant,
        }
    }

    /// Extract an OID definition, if this declaration creates one.
    pub(crate) fn oid_definition(&self) -> Option<(Identifier, OidDef)> {
        use QualifiedDecl as RD;
        match self {
            RD::AgentCapabilities(i, rd) => Some((i.clone(), rd.clone())),
            RD::ModuleCompliance(i, rd) => Some((i.clone(), rd.clone())),
            RD::ModuleIdentity(i, rd) => Some((i.clone(), rd.clone())),
            RD::NotificationGroup(i, rd, _) => Some((i.clone(), rd.clone())),
            RD::NotificationType(i, rd, _) => Some((i.clone(), rd.clone())),
            RD::ObjectGroup(i, rd, _) => Some((i.clone(), rd.clone())),
            RD::ObjectIdentity(i, rd) => Some((i.clone(), rd.clone())),
            RD::ObjectType(i, rd, ..) => Some((i.clone(), rd.clone())),
            RD::PlainOidDef(i, rd) => Some((i.clone(), rd.clone())),
            RD::MacroDef(_)
            | RD::PlainSequence(_)
            | RD::PlainTypeDef(_, _)
            | RD::TextualConvention(_, _)
            | RD::Irrelevant => None,
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
