use foundry_common::TestFunctionExt;
use foundry_evm::coverage::{
    ItemId, ProbeId, ProbeOutcome, SourceKey, SourceLocation,
    analysis::{ProbeSite, ProbeSiteKind},
};
use solar::{
    ast::{self, visit::Visit},
    interface::{BytePos, Session, Span},
};
use std::{
    collections::HashSet,
    ops::{ControlFlow, Range},
    sync::Arc,
};

/// The address used for coverage hit calls.
const COVERAGE_ADDRESS: &str = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D";

pub struct Instrumenter<'ast> {
    pub source_id: u32,
    pub session: &'ast Session,
    edits: Vec<Edit>,
    probe_sites: Vec<ProbeSite>,
    claimed_sites: HashSet<u32>,
    probes: Vec<(ProbeId, u32)>,
    loop_updates: Vec<Option<String>>,
    pub unsupported_constructs: Vec<String>,
    pub contract_name: Arc<str>,
    pub source_key: SourceKey,
    _marker: std::marker::PhantomData<&'ast ()>,
}

#[derive(Clone, Debug)]
struct Edit {
    span: ast::Span,
    replacement: String,
    order: usize,
    suffix: bool,
}

impl<'ast> Instrumenter<'ast> {
    pub fn new(
        session: &'ast Session,
        source_id: u32,
        source_key: SourceKey,
        probe_sites: Vec<ProbeSite>,
    ) -> Self {
        Self {
            source_id,
            session,
            edits: Vec::new(),
            probe_sites,
            claimed_sites: HashSet::new(),
            probes: Vec::new(),
            loop_updates: Vec::new(),
            unsupported_constructs: Vec::new(),
            contract_name: Arc::from(""),
            source_key,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn instrument(&mut self, content: &mut String) -> Result<(), String> {
        if self.edits.is_empty() {
            return Ok(());
        }

        let sf = self.session.source_map().lookup_source_file(self.edits[0].span.lo());
        let base = sf.start_pos.0;

        self.edits.sort_by(|left, right| {
            left.span.lo().cmp(&right.span.lo()).then_with(|| match (left.suffix, right.suffix) {
                (true, true) => right.order.cmp(&left.order),
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                (false, false) => left.order.cmp(&right.order),
            })
        });
        validate_edits(&self.edits, base, content.len())?;
        let mut shift = 0_i64;
        for edit in std::mem::take(&mut self.edits) {
            let lo = edit.span.lo() - base;
            let hi = edit.span.hi() - base;
            let start = ((lo.0 as i64) - shift) as usize;
            let end = ((hi.0 as i64) - shift) as usize;
            content.replace_range(start..end, &edit.replacement);
            shift += (end as i64 - start as i64) - (edit.replacement.len() as i64);
        }
        Ok(())
    }

    fn push_edit(&mut self, span: ast::Span, replacement: impl Into<String>) {
        let order = self.edits.len();
        self.edits.push(Edit { span, replacement: replacement.into(), order, suffix: false });
    }

    fn push_suffix(&mut self, span: ast::Span, replacement: impl Into<String>) {
        let order = self.edits.len();
        self.edits.push(Edit { span, replacement: replacement.into(), order, suffix: true });
    }

    pub fn probes(&self) -> &[(ProbeId, u32)] {
        &self.probes
    }

    pub fn unclaimed_sites(&self) -> Vec<ProbeSite> {
        self.probe_sites
            .iter()
            .filter(|site| !self.claimed_sites.contains(&site.item_id))
            .cloned()
            .collect()
    }

    fn inject_hit(&mut self, span: ast::Span, probe: ProbeId) {
        self.push_edit(span.with_hi(span.lo()), self.coverage_hit(probe));
    }

    fn inject_into_block_or_wrap(&mut self, stmt: &'ast ast::Stmt<'ast>, probe: ProbeId) {
        self.wrap_with_hit(stmt.span, probe);
    }

    fn wrap_with_hit(&mut self, span: ast::Span, probe: ProbeId) {
        self.push_edit(span.with_hi(span.lo()), format!("{{ {} ", self.coverage_hit(probe)));
        self.push_suffix(span.with_lo(span.hi()), " }");
    }

    fn wrap_unbraced(&mut self, stmt: &'ast ast::Stmt<'ast>) {
        if !matches!(stmt.kind, ast::StmtKind::Block(_) | ast::StmtKind::UncheckedBlock(_)) {
            self.push_edit(stmt.span.with_hi(stmt.span.lo()), "{ ");
            self.push_suffix(stmt.span.with_lo(stmt.span.hi()), " }");
        }
    }

    fn coverage_hit(&self, probe: ProbeId) -> String {
        format!(
            "VmCoverage_{}({}).coverageHit({});",
            self.source_key.helper_suffix(),
            COVERAGE_ADDRESS,
            probe.solidity_literal()
        )
    }

    fn claim_site(
        &mut self,
        kind: ProbeSiteKind,
        span: Span,
        outcome: ProbeOutcome,
    ) -> Option<ProbeId> {
        self.claim_site_with_probe(kind, span, outcome, None)
    }

    fn claim_site_with_probe(
        &mut self,
        kind: ProbeSiteKind,
        span: Span,
        outcome: ProbeOutcome,
        shared_probe: Option<ProbeId>,
    ) -> Option<ProbeId> {
        let loc = self.source_location_for(span);
        let site = self.probe_sites.iter().find(|site| {
            site.kind == kind
                && site.loc.source_id == loc.source_id
                && site.loc.contract_name == loc.contract_name
                && site.loc.bytes == loc.bytes
                && !self.claimed_sites.contains(&site.item_id)
        })?;
        let item_id = site.item_id;
        self.claimed_sites.insert(item_id);
        let probe =
            shared_probe.unwrap_or_else(|| ProbeId::new(self.source_key, ItemId(item_id), outcome));
        self.probes.push((probe, item_id));
        Some(probe)
    }

    fn wrap_boolean_condition_value(
        &mut self,
        span: Span,
        if_true: ProbeId,
        if_false: ProbeId,
        condition: String,
    ) {
        let replacement = format!(
            "VmCoverage_{}({}).coverageBranch({},{},{})",
            self.source_key.helper_suffix(),
            COVERAGE_ADDRESS,
            if_true.solidity_literal(),
            if_false.solidity_literal(),
            condition
        );
        self.push_edit(span, replacement);
    }

    fn instrument_expression_tree(&mut self, expr: &'ast ast::Expr<'ast>) {
        let rewritten = self.rewrite_expression_tree(expr, true);
        self.push_edit(expr.span, rewritten);
    }

    fn instrument_value_tree(&mut self, expr: &'ast ast::Expr<'ast>) {
        // A root call may be void- or tuple-valued, neither of which can be placed in a ternary.
        // Its containing statement entry is used below; nested calls necessarily have a value and
        // can use the exact expression wrapper.
        let rewritten = self.rewrite_expression_tree_with_probe(expr, false, None, false);
        self.push_edit(expr.span, rewritten);
    }

    fn instrument_value_tree_at_entry(
        &mut self,
        expr: &'ast ast::Expr<'ast>,
        entry_probe: Option<ProbeId>,
    ) {
        if let Some(entry_probe) = entry_probe {
            self.alias_entry_call(expr, entry_probe);
        }
        self.instrument_value_tree(expr);
    }

    fn alias_entry_call(&mut self, expr: &'ast ast::Expr<'ast>, entry_probe: ProbeId) {
        if matches!(expr.kind, ast::ExprKind::Call(..)) {
            let _ = self.claim_site_with_probe(
                ProbeSiteKind::Expression,
                expr.span,
                ProbeOutcome::Hit,
                Some(entry_probe),
            );
        }
    }

    fn rewrite_expression_tree(
        &mut self,
        expr: &'ast ast::Expr<'ast>,
        expected_bool: bool,
    ) -> String {
        self.rewrite_expression_tree_with_probe(expr, expected_bool, None, true)
    }

    fn rewrite_expression_tree_with_probe(
        &mut self,
        expr: &'ast ast::Expr<'ast>,
        expected_bool: bool,
        shared_probe: Option<ProbeId>,
        wrap_call: bool,
    ) -> String {
        // A short-circuit expression and its left-most evaluated descendant are always reached
        // together. Map those canonical items to one runtime probe instead of wrapping every AST
        // node. Besides reducing bytecode, this prevents long `&&`/`||` chains from exhausting the
        // legacy code generator's stack while keeping skipped right-hand expressions uncovered.
        if let ast::ExprKind::Binary(left, operator, right) = &expr.kind
            && matches!(operator.kind, ast::BinOpKind::And | ast::BinOpKind::Or)
        {
            let probe = self
                .claim_site_with_probe(
                    ProbeSiteKind::Expression,
                    expr.span,
                    ProbeOutcome::Hit,
                    shared_probe,
                )
                .or(shared_probe);
            let replacements = vec![
                (left.span, self.rewrite_expression_tree_with_probe(left, true, probe, true)),
                (right.span, self.rewrite_expression_tree_with_probe(right, true, None, true)),
            ];
            return self.rewrite_snippet(expr.span, replacements);
        }

        let children: Vec<(&ast::Expr<'_>, bool)> = match &expr.kind {
            ast::ExprKind::Binary(left, operator, right) => {
                let operands_are_bool =
                    matches!(operator.kind, ast::BinOpKind::And | ast::BinOpKind::Or);
                vec![(left, operands_are_bool), (right, operands_are_bool)]
            }
            ast::ExprKind::Unary(operator, inner) => {
                vec![(inner, matches!(operator.kind, ast::UnOpKind::Not))]
            }
            ast::ExprKind::Ternary(condition, if_true, if_false) => {
                vec![(condition, true), (if_true, expected_bool), (if_false, expected_bool)]
            }
            ast::ExprKind::Call(callee, args) => std::iter::once((callee.as_ref(), false))
                .chain(args.exprs().map(|arg| (arg, false)))
                .collect(),
            ast::ExprKind::CallOptions(callee, args) => std::iter::once((callee.as_ref(), false))
                .chain(args.iter().map(|arg| (arg.value.as_ref(), false)))
                .collect(),
            _ => Vec::new(),
        };
        let replacements = children
            .into_iter()
            .map(|(child, child_is_bool)| {
                (
                    child.span,
                    self.rewrite_expression_tree_with_probe(child, child_is_bool, None, true),
                )
            })
            .collect();
        let mut rewritten = self.rewrite_snippet(expr.span, replacements);

        let intrinsically_bool = matches!(
            expr.kind,
            ast::ExprKind::Binary(_, operator, _)
                if matches!(
                    operator.kind,
                    ast::BinOpKind::And
                        | ast::BinOpKind::Or
                        | ast::BinOpKind::Eq
                        | ast::BinOpKind::Ne
                        | ast::BinOpKind::Lt
                        | ast::BinOpKind::Le
                        | ast::BinOpKind::Gt
                        | ast::BinOpKind::Ge
                )
        ) || matches!(expr.kind, ast::ExprKind::Unary(operator, _) if matches!(operator.kind, ast::UnOpKind::Not));
        let boolean_wrapper = shared_probe.is_some()
            || (expected_bool || intrinsically_bool)
                && matches!(
                    expr.kind,
                    ast::ExprKind::Unary(..)
                        | ast::ExprKind::Binary(..)
                        | ast::ExprKind::Ternary(..)
                        | ast::ExprKind::Call(..)
                );
        let value_wrapper = matches!(
            expr.kind,
            ast::ExprKind::Unary(..)
                | ast::ExprKind::Binary(..)
                | ast::ExprKind::Ternary(..)
                | ast::ExprKind::Assign(..)
        ) || wrap_call && matches!(expr.kind, ast::ExprKind::Call(..));
        if (boolean_wrapper || value_wrapper)
            && let Some(probe) = self
                .claim_site_with_probe(
                    ProbeSiteKind::Expression,
                    expr.span,
                    ProbeOutcome::Hit,
                    shared_probe,
                )
                .or(shared_probe)
        {
            if boolean_wrapper {
                let probe = probe.solidity_literal();
                rewritten = format!(
                    "VmCoverage_{}({}).coverageBool({probe},{rewritten})",
                    self.source_key.helper_suffix(),
                    COVERAGE_ADDRESS,
                );
            } else {
                let probe = probe.solidity_literal();
                rewritten = format!(
                    "(VmCoverage_{}({}).coverageBranch({probe},{probe},true) ? ({rewritten}) : \
                     ({rewritten}))",
                    self.source_key.helper_suffix(),
                    COVERAGE_ADDRESS,
                );
            }
        }
        rewritten
    }

    fn rewrite_snippet(&self, span: Span, mut replacements: Vec<(Span, String)>) -> String {
        let Ok(mut snippet) = self.session.source_map().span_to_snippet(span) else {
            return String::new();
        };
        replacements.sort_by_key(|(child, _)| std::cmp::Reverse(child.lo()));
        for (child, replacement) in replacements {
            let start = (child.lo() - span.lo()).0 as usize;
            let end = (child.hi() - span.lo()).0 as usize;
            snippet.replace_range(start..end, &replacement);
        }
        snippet
    }

    fn loop_update(&mut self, expr: &'ast ast::Expr<'ast>) -> String {
        let rewritten = self.rewrite_expression_tree_with_probe(expr, false, None, false);
        let entry = self
            .claim_site(ProbeSiteKind::Expression, expr.span, ProbeOutcome::Hit)
            .map(|probe| self.coverage_hit(probe))
            .unwrap_or_default();
        format!("{entry}{rewritten};")
    }

    fn append_loop_update(&mut self, body: &'ast ast::Stmt<'ast>, update: &str) {
        if matches!(body.kind, ast::StmtKind::Block(_) | ast::StmtKind::UncheckedBlock(_)) {
            let position = body.span.hi() - BytePos(1);
            self.push_suffix(Span::new(position, position), format!(" {update} "));
        } else {
            self.push_edit(body.span.with_hi(body.span.lo()), "{ ");
            self.push_suffix(body.span.with_lo(body.span.hi()), format!(" {update} }}"));
        }
    }

    fn visit_loop_body(
        &mut self,
        body: &'ast ast::Stmt<'ast>,
        update: Option<String>,
    ) -> ControlFlow<()> {
        self.loop_updates.push(update);
        let result = self.visit_stmt(body);
        self.loop_updates.pop();
        result
    }

    pub fn interface_definition(&self) -> String {
        format!(
            "\n\ninterface VmCoverage_{} {{ function coverageHit(bytes32) external pure; function coverageBool(bytes32,bool) external pure returns (bool); function coverageBranch(bytes32,bytes32,bool) external pure returns (bool); }}",
            self.source_key.helper_suffix()
        )
    }

    fn source_location_for(&self, mut span: Span) -> SourceLocation {
        // Statements' ranges in the solc source map do not include the semicolon.
        if let Ok(snippet) = self.session.source_map().span_to_snippet(span)
            && let Some(stripped) = snippet.strip_suffix(';')
        {
            let stripped = stripped.trim_end();
            let skipped = snippet.len() - stripped.len();
            span = span.with_hi(span.hi() - BytePos::from_usize(skipped));
        }

        SourceLocation {
            source_id: self.source_id as usize,
            contract_name: self.contract_name.clone(),
            bytes: self.byte_range(span),
            lines: self.line_range(span),
        }
    }

    fn byte_range(&self, span: Span) -> Range<u32> {
        let bytes_usize = self.session.source_map().span_to_source(span).unwrap().data;
        bytes_usize.start as u32..bytes_usize.end as u32
    }

    fn line_range(&self, span: Span) -> Range<u32> {
        let lines = self.session.source_map().span_to_lines(span).unwrap().data;
        assert!(!lines.is_empty());
        let first = lines.first().unwrap();
        let last = lines.last().unwrap();
        first.line_index as u32 + 1..last.line_index as u32 + 2
    }
}

fn is_require_call(expr: &ast::Expr<'_>) -> bool {
    let ast::ExprKind::Call(callee, _) = &expr.kind else { return false };
    matches!(&callee.kind, ast::ExprKind::Ident(name) if name.as_str() == "require")
}

fn validate_edits(edits: &[Edit], base: u32, source_len: usize) -> Result<(), String> {
    let range =
        |edit: &Edit| ((edit.span.lo().0 - base) as usize)..((edit.span.hi().0 - base) as usize);

    for edit in edits {
        let edit_range = range(edit);
        if edit_range.start > edit_range.end || edit_range.end > source_len {
            return Err(format!("source rewrite is out of bounds: {edit_range:?}"));
        }
    }

    for (index, edit) in edits.iter().enumerate() {
        let current = range(edit);
        if current.is_empty() {
            continue;
        }
        for other in &edits[index + 1..] {
            let candidate = range(other);
            if candidate.start >= current.end {
                break;
            }
            let insertion_inside = candidate.is_empty()
                && candidate.start > current.start
                && candidate.start < current.end;
            let replacements_overlap = !candidate.is_empty() && candidate.start < current.end;
            if insertion_inside || replacements_overlap {
                return Err(format!(
                    "ambiguous overlapping source rewrites: {current:?} and {candidate:?}"
                ));
            }
        }
    }

    Ok(())
}

impl<'ast> Visit<'ast> for Instrumenter<'ast> {
    type BreakValue = ();

    fn visit_item_contract(
        &mut self,
        contract: &'ast ast::ItemContract<'ast>,
    ) -> ControlFlow<Self::BreakValue> {
        let has_tests = contract.body.iter().any(|item| {
            let ast::ItemKind::Function(function) = &item.kind else { return false };
            function.header.name.as_ref().is_some_and(|name| name.as_str().is_any_test())
        });
        if contract.kind.is_interface() || has_tests {
            return ControlFlow::Continue(());
        }
        self.contract_name = contract.name.as_str().into();
        self.walk_item_contract(contract)
    }

    fn visit_item_function(
        &mut self,
        func: &'ast ast::ItemFunction<'ast>,
    ) -> ControlFlow<Self::BreakValue> {
        if func.header.virtual_() && !func.is_implemented() {
            return ControlFlow::Continue(());
        }
        let probe = self.claim_site(
            ProbeSiteKind::FunctionEntry,
            func.header.span.to(func.body_span),
            ProbeOutcome::Hit,
        );

        if let (Some(block), Some(probe)) = (&func.body, probe) {
            let injection_span = block.first().map(|s| s.span).unwrap_or_else(|| {
                let lo = block.span.lo() + BytePos(1);
                Span::new(lo, lo)
            });
            self.inject_hit(injection_span, probe);
        }
        self.walk_item_function(func)
    }

    fn visit_stmt(&mut self, stmt: &'ast ast::Stmt<'ast>) -> ControlFlow<Self::BreakValue> {
        match &stmt.kind {
            ast::StmtKind::Assembly(_) => {
                self.unsupported_constructs
                    .push("inline assembly coverage probes are not yet supported".to_string());
                return ControlFlow::Continue(());
            }
            ast::StmtKind::Expr(expr) => {
                let entry_probe =
                    self.claim_site(ProbeSiteKind::Expression, expr.span, ProbeOutcome::Hit);
                if let Some(probe) = entry_probe {
                    self.inject_hit(stmt.span, probe);
                }
                if is_require_call(expr) {
                    return self.visit_expr(expr);
                }
                self.instrument_value_tree_at_entry(expr, entry_probe);
                return ControlFlow::Continue(());
            }
            ast::StmtKind::Return(value) => {
                let entry_probe =
                    self.claim_site(ProbeSiteKind::StatementEntry, stmt.span, ProbeOutcome::Hit);
                if let Some(probe) = entry_probe {
                    self.inject_hit(stmt.span, probe);
                }
                if let Some(value) = value {
                    self.instrument_value_tree_at_entry(value, entry_probe);
                }
                return ControlFlow::Continue(());
            }
            ast::StmtKind::DeclSingle(variable) => {
                let entry_probe =
                    self.claim_site(ProbeSiteKind::StatementEntry, stmt.span, ProbeOutcome::Hit);
                if let Some(probe) = entry_probe {
                    self.inject_hit(stmt.span, probe);
                }
                if let Some(initializer) = &variable.initializer {
                    self.instrument_value_tree_at_entry(initializer, entry_probe);
                }
                return ControlFlow::Continue(());
            }
            ast::StmtKind::DeclMulti(_, value) => {
                let entry_probe =
                    self.claim_site(ProbeSiteKind::StatementEntry, stmt.span, ProbeOutcome::Hit);
                if let Some(probe) = entry_probe {
                    self.inject_hit(stmt.span, probe);
                }
                self.instrument_value_tree_at_entry(value, entry_probe);
                return ControlFlow::Continue(());
            }
            ast::StmtKind::If(cond, then, els_opt) => {
                self.instrument_expression_tree(cond);

                if let Some(probe) = self.claim_site(
                    ProbeSiteKind::Branch { path_id: 0 },
                    then.span,
                    ProbeOutcome::BranchTrue,
                ) {
                    self.inject_into_block_or_wrap(then, probe);
                }
                let _ = self.visit_stmt(then);

                if let Some(els) = els_opt {
                    let false_probe = self.claim_site(
                        ProbeSiteKind::Branch { path_id: 1 },
                        stmt.span,
                        ProbeOutcome::BranchFalse,
                    );
                    // We manually wrap the else block to ensure that the closing brace is added
                    // *after* visiting the statement. This is crucial for `else if` chains where
                    // the inner `if` might generate an implicit `else` block. If we used
                    // `inject_into_block_or_wrap`, the closing brace would be added before the
                    // implicit else, resulting in invalid syntax: `} else { ... }`.
                    if let Some(probe) = false_probe {
                        self.push_edit(
                            els.span.with_hi(els.span.lo()),
                            format!("{{ {} ", self.coverage_hit(probe)),
                        );
                    }
                    let _ = self.visit_stmt(els);
                    if false_probe.is_some() {
                        self.push_suffix(els.span.with_lo(els.span.hi()), " }");
                    }
                }
                return ControlFlow::Continue(());
            }
            ast::StmtKind::For { init, cond, next, body } => {
                if let Some(init) = init {
                    let probe = match &init.kind {
                        ast::StmtKind::Expr(expr) => {
                            let probe = self.claim_site(
                                ProbeSiteKind::Expression,
                                expr.span,
                                ProbeOutcome::Hit,
                            );
                            self.instrument_value_tree(expr);
                            probe
                        }
                        ast::StmtKind::DeclSingle(variable) => {
                            let probe = self.claim_site(
                                ProbeSiteKind::StatementEntry,
                                init.span,
                                ProbeOutcome::Hit,
                            );
                            if let Some(initializer) = &variable.initializer {
                                self.instrument_value_tree_at_entry(initializer, probe);
                            }
                            probe
                        }
                        ast::StmtKind::DeclMulti(_, value) => {
                            let probe = self.claim_site(
                                ProbeSiteKind::StatementEntry,
                                init.span,
                                ProbeOutcome::Hit,
                            );
                            self.instrument_value_tree_at_entry(value, probe);
                            probe
                        }
                        _ => None,
                    };
                    if let Some(probe) = probe {
                        self.inject_hit(stmt.span.with_hi(stmt.span.lo()), probe);
                    }
                }
                if let Some(cond) = cond {
                    self.instrument_expression_tree(cond);
                }
                let update = next.as_deref().map(|next| {
                    let update = self.loop_update(next);
                    self.push_edit(next.span, "");
                    self.append_loop_update(body, &update);
                    update
                });
                if update.is_none() {
                    self.wrap_unbraced(body);
                }

                return self.visit_loop_body(body, update);
            }
            ast::StmtKind::While(cond, body) => {
                self.wrap_unbraced(body);
                self.instrument_expression_tree(cond);

                return self.visit_loop_body(body, None);
            }
            ast::StmtKind::DoWhile(body, cond) => {
                self.wrap_unbraced(body);
                let _ = self.visit_loop_body(body, None);
                self.instrument_expression_tree(cond);
                return ControlFlow::Continue(());
            }
            ast::StmtKind::Try(ast::StmtTry { expr, clauses }) => {
                let entry_probe =
                    self.claim_site(ProbeSiteKind::Expression, expr.span, ProbeOutcome::Hit);
                if let Some(probe) = entry_probe {
                    self.inject_hit(stmt.span, probe);
                }
                self.instrument_value_tree_at_entry(expr, entry_probe);
                let mut path_id = 0;
                for (index, clause) in clauses.iter().enumerate() {
                    if index != 0 && clause.block.is_empty() {
                        if !clause.args.is_empty()
                            && let Some(probe) = self.claim_site(
                                ProbeSiteKind::StatementEntry,
                                clause.span,
                                ProbeOutcome::Hit,
                            )
                        {
                            let position = clause.block.span.lo() + BytePos(1);
                            self.inject_hit(Span::new(position, position), probe);
                        }
                        continue;
                    }
                    let span = if index == 0 { stmt.span.to(clause.span) } else { clause.span };
                    let probe =
                        self.claim_site(ProbeSiteKind::Branch { path_id }, span, ProbeOutcome::Hit);
                    path_id += 1;
                    if let Some(probe) = probe {
                        let injection_span =
                            clause.block.first().map(|stmt| stmt.span).unwrap_or_else(|| {
                                let lo = clause.block.span.lo() + BytePos(1);
                                Span::new(lo, lo)
                            });
                        self.inject_hit(injection_span, probe);
                    }
                }
            }
            ast::StmtKind::Block(_) | ast::StmtKind::UncheckedBlock(_) => {}
            ast::StmtKind::Continue => {
                let statement_probe =
                    self.claim_site(ProbeSiteKind::StatementEntry, stmt.span, ProbeOutcome::Hit);
                if let Some(Some(update)) = self.loop_updates.last().cloned() {
                    let statement_hit =
                        statement_probe.map(|probe| self.coverage_hit(probe)).unwrap_or_default();
                    self.push_edit(
                        stmt.span.with_hi(stmt.span.lo()),
                        format!("{{ {statement_hit}{update}"),
                    );
                    self.push_suffix(stmt.span.with_lo(stmt.span.hi()), " }");
                } else if let Some(probe) = statement_probe {
                    self.inject_hit(stmt.span, probe);
                }
                return ControlFlow::Continue(());
            }
            _ => {
                if let Some(probe) =
                    self.claim_site(ProbeSiteKind::StatementEntry, stmt.span, ProbeOutcome::Hit)
                {
                    self.inject_hit(stmt.span, probe);
                }
            }
        }

        self.walk_stmt(stmt)
    }

    fn visit_expr(&mut self, expr: &'ast ast::Expr<'ast>) -> ControlFlow<Self::BreakValue> {
        let ast::ExprKind::Call(callee, args) = &expr.kind else { return self.walk_expr(expr) };
        let ast::ExprKind::Ident(name) = &callee.kind else { return self.walk_expr(expr) };
        if name.as_str() != "require" {
            return self.walk_expr(expr);
        }
        let Some(condition) = args.exprs().next() else { return self.walk_expr(expr) };

        let true_probe = self.claim_site(
            ProbeSiteKind::Branch { path_id: 0 },
            expr.span,
            ProbeOutcome::BranchTrue,
        );
        let false_probe = self.claim_site(
            ProbeSiteKind::Branch { path_id: 1 },
            expr.span,
            ProbeOutcome::BranchFalse,
        );
        let rewritten = self.rewrite_expression_tree(condition, true);
        if let (Some(true_probe), Some(false_probe)) = (true_probe, false_probe) {
            self.wrap_boolean_condition_value(condition.span, true_probe, false_probe, rewritten);
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solar::{interface::source_map::FileName, parse::Parser};

    #[test]
    fn test_instrumentation() {
        let src = "contract C {
    modifier m() {
        uint a = 1;
        _;
    }
    function foo(uint x) public m {
        uint y = x + 1;
        if (y > 10) { y = 0; } else if (y > 5) { y = 1; } else { y = 2; }
        if (y == 20) { y = 0; } else { y = 1; }
        if (y == 30) { y = 0; } if (y == 40) { y = 1; } else { y = 2; }
        if (y == 50) { y = 0; } else if (y == 60) { y = 1; }
        if (y == 70) { y = 0; } else if (y == 80) { y = 1; }
        if (y < 0) {
            y = 0;
        } else {
            y = 1;
        }
        if (y > 100)
        {
            y = 100;
        }
        else
        {
            y = y;
        }
        while (y < 5) {
            y++;
        }
        for (uint i = 0; i < 10; i++) {
            y += i;
        }
    }
    function add(uint a, uint b) public pure returns (uint) {
        return a + b;
    }
}";
        let mut content = src.to_string();
        let sess = Session::builder().with_buffer_emitter(Default::default()).build();
        let _: solar::interface::Result<()> = sess.enter_sequential(|| {
            let arena = ast::Arena::new();
            let mut parser = Parser::from_source_code(
                &sess,
                &arena,
                FileName::Custom("test.sol".to_string()),
                src.to_string(),
            )
            .unwrap();
            let ast = match parser.parse_file() {
                Ok(ast) => ast,
                Err(diag) => {
                    panic!("Parse error: {:?}", diag);
                }
            };

            let mut instrumenter = Instrumenter::new(&sess, 0, SourceKey::default(), Vec::new());
            let _ = instrumenter.visit_source_unit(&ast);
            instrumenter.instrument(&mut content).unwrap();

            println!("Instrumented code:\n{}", content);

            // Basic assertions
            assert!(content.contains("pure")); // pure should be preserved

            solar::interface::Result::Ok(())
        });
    }

    #[test]
    fn test_override_view_instrumentation() {
        let src = "contract C {
    function foo() public view virtual returns (uint) { return 1; }
}
contract D is C {
    function foo() public view override returns (uint) { return 2; }
}";
        let mut content = src.to_string();
        let sess = Session::builder().with_buffer_emitter(Default::default()).build();
        let _: solar::interface::Result<()> = sess.enter_sequential(|| {
            let arena = ast::Arena::new();
            let mut parser = Parser::from_source_code(
                &sess,
                &arena,
                FileName::Custom("test.sol".to_string()),
                src.to_string(),
            )
            .unwrap();
            let ast = match parser.parse_file() {
                Ok(ast) => ast,
                Err(diag) => {
                    panic!("Parse error: {:?}", diag);
                }
            };

            let mut instrumenter = Instrumenter::new(&sess, 0, SourceKey::default(), Vec::new());
            let _ = instrumenter.visit_source_unit(&ast);
            instrumenter.instrument(&mut content).unwrap();

            println!("Instrumented code:\n{}", content);

            // Assertions
            // The base contract function 'foo' (virtual, not override) SHOULD be instrumented (view
            // removed) The derived contract function 'foo' (override) SHOULD NOT be
            // instrumented (view preserved)

            let view_count = content.matches("view").count();
            assert_eq!(view_count, 2, "Expected 'view' to remain in both C.foo and D.foo");

            let parts: Vec<&str> = content.split("contract D").collect();
            let c_part = parts[0];
            let d_part = parts[1];

            assert!(c_part.contains("view"), "Base contract function should keep view");
            assert!(d_part.contains("view"), "Derived contract function should keep view");

            solar::interface::Result::Ok(())
        });
    }

    #[test]
    fn transformed_control_flow_reparses() {
        let src = r#"
contract C {
    modifier twice() { _; _; }
    function target() external returns (uint256) { return 1; }
    function run(uint256 x) public twice returns (uint256) {
        while (x > 3) if (x == 8) x--; else x -= 2;
        do x++; while (x < 3);
        for (uint256 i; i < 2; i++) if (i == 1) x++;
        require(x > 0 && target() > 0, "zero");
        try this.target() returns (uint256 value) { x += value; } catch { x = 1; }
        return x;
    }
}
"#;
        let mut transformed = src.to_string();
        let sess = Session::builder().with_buffer_emitter(Default::default()).build();
        sess.enter_sequential(|| {
            let arena = ast::Arena::new();
            let mut parser = Parser::from_source_code(
                &sess,
                &arena,
                FileName::Custom("test.sol".to_string()),
                src.to_string(),
            )
            .unwrap();
            let ast = parser.parse_file().unwrap();
            let mut instrumenter = Instrumenter::new(&sess, 0, SourceKey::default(), Vec::new());
            let _ = instrumenter.visit_source_unit(&ast);
            instrumenter.instrument(&mut transformed).unwrap();
            transformed.push_str(&instrumenter.interface_definition());
        });

        let verify = Session::builder().with_buffer_emitter(Default::default()).build();
        verify.enter_sequential(|| {
            let arena = ast::Arena::new();
            let mut parser = Parser::from_source_code(
                &verify,
                &arena,
                FileName::Custom("transformed.sol".to_string()),
                transformed,
            )
            .unwrap();
            parser.parse_file().unwrap();
        });
    }
}
