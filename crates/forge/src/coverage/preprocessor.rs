//! Source coverage preprocessing over fully resolved compiler jobs.

use super::instrument::Instrumenter;
use alloy_primitives::{B256, keccak256};
use foundry_compilers::{
    Compiler, ProjectPathsConfig, SourceParser,
    artifacts::SolcLanguage,
    error::Result,
    multi::{MultiCompiler, MultiCompilerInput, MultiCompilerLanguage},
    project::Preprocessor,
};
use foundry_evm::coverage::{
    CoverageCompleteness, CoverageItem, CoverageItemKind, IncompleteReason, IncompleteReasonKind,
    ProbeId, SourceKey,
    analysis::{ProbeSite, ProbeSiteKind, SourceAnalysis, SourceFiles},
    probe::MIN_SOLIDITY_VERSION,
};
use semver::Version;
use solar::{ast::visit::Visit, interface::source_map::FileName};
use std::{
    collections::{HashMap, HashSet},
    ops::ControlFlow,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug)]
pub struct SourceCoverageOptions {
    pub include_libs: bool,
    pub exclude_tests: bool,
    pub coverage_pattern_inverse: Option<regex::Regex>,
}

#[derive(Clone, Debug)]
pub struct PreparedSource {
    pub version: Version,
    pub source_id: u32,
    pub path: PathBuf,
    pub items: Vec<CoverageItem>,
    pub probes: Vec<(ProbeId, u32)>,
}

#[derive(Clone, Debug, Default)]
pub struct SourceCoverageState {
    pub sources: Vec<PreparedSource>,
    pub completeness: CoverageCompleteness,
    pub fatal_error: Option<String>,
    next_source_id: u32,
}

impl SourceCoverageState {
    fn fail(&mut self, detail: impl Into<String>) {
        self.completeness = CoverageCompleteness::Failed;
        self.fatal_error = Some(detail.into());
    }
}

/// A cloneable handle used to extract the inventory and registry after compilation.
pub type SharedSourceCoverageState = Arc<Mutex<SourceCoverageState>>;

#[derive(Clone, Debug)]
pub struct SourceCoveragePreprocessor {
    options: SourceCoverageOptions,
    state: SharedSourceCoverageState,
}

impl SourceCoveragePreprocessor {
    pub fn new(options: SourceCoverageOptions) -> (Self, SharedSourceCoverageState) {
        let state = Arc::new(Mutex::new(SourceCoverageState::default()));
        (Self { options, state: state.clone() }, state)
    }

    fn selected(&self, path: &Path, paths: &ProjectPathsConfig<MultiCompilerLanguage>) -> bool {
        if (!self.options.include_libs && paths.has_library_ancestor(path))
            || (self.options.exclude_tests && paths.is_test(path))
        {
            return false;
        }

        let normalized = path.strip_prefix(&paths.root).unwrap_or(path);
        !self
            .options
            .coverage_pattern_inverse
            .as_ref()
            .is_some_and(|re| re.is_match(&normalized.to_string_lossy()))
    }

    fn record_unsupported_input(
        &self,
        input: &MultiCompilerInput,
        paths: &ProjectPathsConfig<MultiCompilerLanguage>,
    ) {
        let (sources, language) = match input {
            MultiCompilerInput::Vyper(input) => (&input.input.sources, "Vyper"),
            MultiCompilerInput::Solc(input) => (&input.input.sources, "Yul"),
        };
        let mut state = self.state.lock().unwrap();
        for path in sources.keys().filter(|path| self.selected(path, paths)) {
            state.completeness.push(IncompleteReason::new(
                Some(path.clone()),
                IncompleteReasonKind::UnsupportedLanguage,
                format!("{language} source instrumentation is not supported"),
            ));
        }
    }
}

impl Preprocessor<MultiCompiler> for SourceCoveragePreprocessor {
    #[instrument(name = "SourceCoveragePreprocessor::preprocess", skip_all)]
    fn preprocess(
        &self,
        _compiler: &MultiCompiler,
        input: &mut <MultiCompiler as Compiler>::Input,
        paths: &ProjectPathsConfig<MultiCompilerLanguage>,
        _mocks: &mut HashSet<PathBuf>,
    ) -> Result<()> {
        let MultiCompilerInput::Solc(solc_input) = input else {
            self.record_unsupported_input(input, paths);
            return Ok(());
        };

        if solc_input.input.language != SolcLanguage::Solidity {
            self.record_unsupported_input(input, paths);
            return Ok(());
        }

        let version = solc_input.version.clone();
        let supported = (version.major, version.minor, version.patch) >= MIN_SOLIDITY_VERSION;
        let fingerprint = compilation_fingerprint(solc_input);

        let selected_paths = solc_input
            .input
            .sources
            .keys()
            .filter(|path| self.selected(path, paths))
            .cloned()
            .collect::<Vec<_>>();

        if !supported {
            let mut state = self.state.lock().unwrap();
            for path in selected_paths {
                state.completeness.push(IncompleteReason::new(
                    Some(path),
                    IncompleteReasonKind::UnsupportedCompiler,
                    format!("Solidity {version}; minimum supported version is 0.8.0"),
                ));
            }
            return Ok(());
        }

        let selected_sources = {
            let mut state = self.state.lock().unwrap();
            selected_paths
                .into_iter()
                .map(|path| {
                    let source_id = state.next_source_id;
                    state.next_source_id = state.next_source_id.saturating_add(1);
                    (path, source_id)
                })
                .collect::<Vec<_>>()
        };

        let canonical = match canonical_analysis(solc_input, paths, &selected_sources) {
            Ok(analysis) => analysis,
            Err(error) => {
                self.state.lock().unwrap().fail(error);
                return Ok(());
            }
        };

        for (path, source_id) in selected_sources {
            let Some(source) = solc_input.input.sources.get_mut(&path) else { continue };
            let original = source.content.as_str();
            let normalized_path = path.strip_prefix(&paths.root).unwrap_or(&path);
            let source_key = SourceKey::new(fingerprint, normalized_path);
            let helper_name = format!("VmCoverage_{}", source_key.helper_suffix());

            if original.contains(&helper_name) {
                let mut state = self.state.lock().unwrap();
                state.fail(format!(
                    "generated source-coverage helper `{helper_name}` collides in {}",
                    path.display()
                ));
                continue;
            }

            let canonical_items_with_ids = canonical
                .items_for_source_enumerated(source_id)
                .filter(|(_, item)| !matches!(item.kind, CoverageItemKind::Line))
                .collect::<Vec<_>>();
            let canonical_items = canonical_items_with_ids
                .iter()
                .map(|(_, item)| (*item).clone())
                .collect::<Vec<_>>();
            let local_ids = canonical_items_with_ids
                .iter()
                .enumerate()
                .map(|(local_id, (canonical_id, _))| (*canonical_id, local_id as u32))
                .collect::<HashMap<_, _>>();
            let probe_sites = canonical
                .probe_sites_for_source(source_id)
                .into_iter()
                .filter_map(|mut site| {
                    site.item_id = *local_ids.get(&site.item_id)?;
                    Some(site)
                })
                .collect::<Vec<_>>();

            let session = solar::interface::Session::builder().with_stderr_emitter().build();
            let result: std::result::Result<_, String> = session.enter_sequential(|| {
                let arena = solar::ast::Arena::new();
                let mut parser = solar::parse::Parser::from_source_code(
                    &session,
                    &arena,
                    FileName::Real(path.clone()),
                    original.to_owned(),
                )
                .map_err(|error| format!("failed to create parser: {error:?}"))?;
                let ast = parser
                    .parse_file()
                    .map_err(|error| format!("failed to parse source: {error:?}"))?;
                let mut instrumenter =
                    Instrumenter::new(&session, source_id, source_key, probe_sites);
                let _ = instrumenter.visit_source_unit(&ast);
                let mut transformed = original.to_owned();
                instrumenter.instrument(&mut transformed)?;
                if !instrumenter.probes().is_empty() {
                    transformed.push_str(&instrumenter.interface_definition());
                }
                Ok((
                    transformed,
                    instrumenter.probes().to_vec(),
                    instrumenter.unclaimed_sites(),
                    instrumenter.unsupported_constructs,
                ))
            });

            match result {
                Ok((transformed, probes, unmatched, unsupported_constructs)) => {
                    let unmatched_detail = (!unmatched.is_empty())
                        .then(|| describe_unclaimed_sites(&unmatched, original));
                    source.content = Arc::new(transformed);
                    let mut state = self.state.lock().unwrap();
                    for detail in unsupported_constructs {
                        state.completeness.push(IncompleteReason::new(
                            Some(path.clone()),
                            IncompleteReasonKind::UnsupportedConstruct,
                            detail,
                        ));
                    }
                    if let Some(detail) = unmatched_detail {
                        state.completeness.push(IncompleteReason::new(
                            Some(path.clone()),
                            IncompleteReasonKind::InstrumentationBoundary,
                            detail,
                        ));
                    }
                    state.sources.push(PreparedSource {
                        version: version.clone(),
                        source_id,
                        path,
                        items: canonical_items,
                        probes,
                    });
                }
                Err(err) => self
                    .state
                    .lock()
                    .unwrap()
                    .fail(format!("failed to instrument {}: {err:?}", path.display())),
            }
        }

        Ok(())
    }
}

fn describe_unclaimed_sites(sites: &[ProbeSite], source: &str) -> String {
    let mut functions = 0;
    let mut statements = 0;
    let mut expressions = 0;
    let mut branches = 0;
    for site in sites {
        match site.kind {
            ProbeSiteKind::FunctionEntry => functions += 1,
            ProbeSiteKind::StatementEntry => statements += 1,
            ProbeSiteKind::Expression => expressions += 1,
            ProbeSiteKind::Branch { .. } => branches += 1,
        }
    }
    let mut kinds = Vec::new();
    if functions != 0 {
        kinds.push(format!("{functions} function"));
    }
    if statements != 0 {
        kinds.push(format!("{statements} statement"));
    }
    if expressions != 0 {
        kinds.push(format!("{expressions} expression"));
    }
    if branches != 0 {
        kinds.push(format!("{branches} branch"));
    }
    let examples = sites
        .iter()
        .take(12)
        .map(|site| {
            let kind = match site.kind {
                ProbeSiteKind::FunctionEntry => "function",
                ProbeSiteKind::StatementEntry => "statement",
                ProbeSiteKind::Expression => "expression",
                ProbeSiteKind::Branch { .. } => "branch",
            };
            let snippet = source
                .get(site.loc.bytes.start as usize..site.loc.bytes.end as usize)
                .unwrap_or("<invalid span>")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            let snippet = if snippet.chars().count() > 120 {
                format!("{}...", snippet.chars().take(120).collect::<String>())
            } else {
                snippet
            };
            format!("{}:{} {kind} `{snippet}`", site.loc.contract_name, site.loc.lines.start)
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "{} canonical coverage item(s) have no safe probe ({}; examples: {examples})",
        sites.len(),
        kinds.join(", ")
    )
}

fn compilation_fingerprint(input: &foundry_compilers::solc::SolcVersionedInput) -> B256 {
    // The resolved compiler input includes version, language, paths, contents, remappings, and
    // compiler settings. Serializing it gives distinct identities to overlapping source IDs in
    // separate compiler jobs.
    keccak256(serde_json::to_vec(input).expect("solc input is serializable"))
}

fn canonical_analysis(
    input: &foundry_compilers::solc::SolcVersionedInput,
    paths: &ProjectPathsConfig<MultiCompilerLanguage>,
    selected_sources: &[(PathBuf, u32)],
) -> std::result::Result<SourceAnalysis, String> {
    let mut compiler = foundry_compilers::resolver::parse::SolParser::new(paths).into_compiler();
    compiler.enter_mut(|compiler| -> std::result::Result<_, String> {
        let mut pcx = compiler.parse();
        for (path, source) in input.input.sources.iter() {
            let source_file = compiler
                .sess()
                .source_map()
                .new_source_file(path.clone(), source.content.as_str())
                .map_err(|error| format!("failed to load {}: {error}", path.display()))?;
            pcx.add_file(source_file);
        }
        pcx.parse();
        let ControlFlow::Continue(()) = compiler
            .lower_asts()
            .map_err(|_| "failed to lower original Solidity input".to_string())?
        else {
            return Ok(SourceAnalysis::default());
        };
        let data = SourceFiles {
            sources: selected_sources.iter().map(|(path, id)| (*id, path.clone())).collect(),
        };
        Ok(SourceAnalysis::from_gcx(&data, compiler.gcx()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use foundry_compilers::artifacts::{Settings, SolcInput, Source, Sources};

    #[test]
    fn fingerprint_changes_with_compiler_version() {
        let sources = Sources::from([(PathBuf::from("src/C.sol"), Source::new("contract C {}"))]);
        let mut a = foundry_compilers::solc::SolcVersionedInput {
            version: Version::new(0, 8, 20),
            input: SolcInput::new(SolcLanguage::Solidity, sources, Settings::default()),
            cli_settings: Default::default(),
        };
        let first = compilation_fingerprint(&a);
        a.version = Version::new(0, 8, 21);
        assert_ne!(first, compilation_fingerprint(&a));
    }
}
