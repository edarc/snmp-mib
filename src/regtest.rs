//! Regression tests for bugs found by fuzzing.

/// Cyclic definitions of referenced types don't cause an infinite loop in the linker.
#[test]
fn cyclic_referenced_type_1_edge() {
    let module = r#"
        CYCLIC DEFINITIONS ::= BEGIN
            cycle ::= cycle
            cycle OBJECT IDENTIFIER ::= { 0 }
        END"#;
    let mut loader = crate::loader::Loader::new();
    loader.load(module).expect("load failed");
    let _: crate::mib::MIB = loader.into();
}

#[test]
fn cyclic_referenced_type_2_edge() {
    let module = r#"
        CYCLIC DEFINITIONS ::= BEGIN
            alfa ::= bravo
            bravo ::= alfa
            alfa OBJECT IDENTIFIER ::= { 0 }
        END"#;
    let mut loader = crate::loader::Loader::new();
    loader.load(module).expect("load failed");
    let _: crate::mib::MIB = loader.into();
}

/// Cyclic OID expressions don't cause a stack overflow in the linker.
#[test]
fn cyclic_oid_expression_1_edge() {
    let module = "
        CYCLIC DEFINITIONS ::= BEGIN
            cycle OBJECT IDENTIFIER ::= { cycle }
        END";
    let mut loader = crate::loader::Loader::new();
    loader.load(module).expect("load failed");
    let _: crate::mib::MIB = loader.into();
}

#[test]
fn cyclic_oid_expression_2_edge() {
    let module = "
        CYCLIC DEFINITIONS ::= BEGIN
            alfa OBJECT IDENTIFIER ::= { bravo }
            bravo OBJECT IDENTIFIER ::= { alfa }
        END";
    let mut loader = crate::loader::Loader::new();
    loader.load(module).expect("load failed");
    let _: crate::mib::MIB = loader.into();
}

/// If the parser accepts zero-length OID expressions, assigning one to a table causes an integer
/// underflow panic in the linker. The underflow is checked now for belt-and-suspenders, although
/// zero-length OID expressions are now a parse error and should in theory never get to the linker.
#[test]
fn unsigned_underflow_from_zero_length_table_oid() {
    let module = "
        D DEFINITIONS ::= BEGIN
            alfa ::= SEQUENCE { x y }
            bravo ::= alfa
            bravo OBJECT IDENTIFIER ::= {}
        END";
    let mut loader = crate::loader::Loader::new();
    assert!(loader.load(module).is_err());
}

/// Empty OID expressions should not parse.
#[test]
fn empty_oid_expression() {
    let module = "
        D DEFINITIONS ::= BEGIN
            alfa OBJECT IDENTIFIER ::= {}
        END";
    let mut loader = crate::loader::Loader::new();
    assert!(loader.load(module).is_err());
}
