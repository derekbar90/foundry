use std::path::PathBuf;

/// Whether a coverage report represents every selected input and item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum CoverageCompleteness {
    #[default]
    Complete,
    Partial(Vec<IncompleteReason>),
    Failed,
}

impl CoverageCompleteness {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }

    pub fn reasons(&self) -> &[IncompleteReason] {
        match self {
            Self::Partial(reasons) => reasons,
            Self::Complete | Self::Failed => &[],
        }
    }

    pub fn push(&mut self, reason: IncompleteReason) {
        match self {
            Self::Complete => *self = Self::Partial(vec![reason]),
            Self::Partial(reasons) => reasons.push(reason),
            Self::Failed => {}
        }
    }
}

/// Why a selected source or item could not be collected completely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncompleteReason {
    pub path: Option<PathBuf>,
    pub kind: IncompleteReasonKind,
    pub detail: String,
}

impl IncompleteReason {
    pub fn new(
        path: impl Into<Option<PathBuf>>,
        kind: IncompleteReasonKind,
        detail: impl Into<String>,
    ) -> Self {
        Self { path: path.into(), kind, detail: detail.into() }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteReasonKind {
    UnsupportedLanguage,
    UnsupportedCompiler,
    UnsupportedConstruct,
    InstrumentationBoundary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_becomes_partial_without_losing_reasons() {
        let mut completeness = CoverageCompleteness::Complete;
        completeness.push(IncompleteReason::new(
            Some(PathBuf::from("src/Legacy.sol")),
            IncompleteReasonKind::UnsupportedCompiler,
            "Solidity 0.7.6",
        ));
        completeness.push(IncompleteReason::new(
            Some(PathBuf::from("src/Module.vy")),
            IncompleteReasonKind::UnsupportedLanguage,
            "Vyper",
        ));

        assert!(!completeness.is_complete());
        assert_eq!(completeness.reasons().len(), 2);
    }
}
