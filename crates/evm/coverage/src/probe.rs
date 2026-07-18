use alloy_primitives::{B256, keccak256};
use std::{fmt, path::Path, sync::LazyLock};

/// The first Solidity release supported by source instrumentation.
///
/// The source backend relies on Solar lowering, whose supported Solidity floor is 0.8.0. Older
/// jobs remain valid compiler inputs, but make a source-instrumented report incomplete.
pub const MIN_SOLIDITY_VERSION: (u64, u64, u64) = (0, 8, 0);

/// Signature of the statement/function probe primitive.
pub const HIT_SIGNATURE: &str = "coverageHit(bytes32)";

/// Signature of the value-preserving branch probe primitive.
pub const BRANCH_SIGNATURE: &str = "coverageBranch(bytes32,bytes32,bool)";

/// Selector of [`HIT_SIGNATURE`].
pub static HIT_SELECTOR: LazyLock<[u8; 4]> = LazyLock::new(|| selector(HIT_SIGNATURE));

/// Selector of [`BRANCH_SIGNATURE`].
pub static BRANCH_SELECTOR: LazyLock<[u8; 4]> = LazyLock::new(|| selector(BRANCH_SIGNATURE));

/// Stable identity of a source within a resolved compiler job.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceKey(B256);

impl SourceKey {
    /// Creates a key from a resolved compiler-job fingerprint and normalized virtual path.
    pub fn new(job_fingerprint: B256, path: &Path) -> Self {
        let normalized = path.to_string_lossy().replace('\\', "/");
        let mut input = Vec::with_capacity(32 + normalized.len());
        input.extend_from_slice(job_fingerprint.as_slice());
        input.extend_from_slice(normalized.as_bytes());
        Self(keccak256(input))
    }

    /// Returns the underlying digest.
    pub const fn digest(self) -> B256 {
        self.0
    }

    /// Returns a collision-resistant Solidity helper suffix.
    pub fn helper_suffix(self) -> String {
        hex::encode(&self.0[..8])
    }
}

/// Stable item identity within one [`SourceKey`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId(pub u32);

/// The event represented by a runtime probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProbeOutcome {
    Hit = 0,
    BranchTrue = 1,
    BranchFalse = 2,
}

/// Opaque runtime probe identity.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProbeId(B256);

impl ProbeId {
    /// Derives a probe ID from stable source/item identities and an outcome.
    pub fn new(source: SourceKey, item: ItemId, outcome: ProbeOutcome) -> Self {
        let mut input = [0u8; 37];
        input[..32].copy_from_slice(source.digest().as_slice());
        input[32..36].copy_from_slice(&item.0.to_be_bytes());
        input[36] = outcome as u8;
        Self(keccak256(input))
    }

    /// Creates an ID from calldata.
    pub const fn from_digest(digest: B256) -> Self {
        Self(digest)
    }

    /// Returns the underlying digest.
    pub const fn digest(self) -> B256 {
        self.0
    }

    /// Returns a Solidity `bytes32` literal.
    pub fn solidity_literal(self) -> String {
        format!("{:#x}", self.0)
    }
}

impl fmt::Debug for ProbeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().expect("four-byte selector")
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_are_stable_and_namespaced() {
        let job_a = keccak256(b"solc-0.8.30-profile-a");
        let job_b = keccak256(b"solc-0.8.30-profile-b");
        let source_a = SourceKey::new(job_a, Path::new("src/Counter.sol"));
        let source_a_again = SourceKey::new(job_a, Path::new("src/Counter.sol"));
        let source_b = SourceKey::new(job_b, Path::new("src/Counter.sol"));

        assert_eq!(source_a, source_a_again);
        assert_ne!(source_a, source_b);
        assert_ne!(
            ProbeId::new(source_a, ItemId(1), ProbeOutcome::Hit),
            ProbeId::new(source_a, ItemId(1), ProbeOutcome::BranchTrue)
        );
        assert_ne!(
            ProbeId::new(source_a, ItemId(1), ProbeOutcome::Hit),
            ProbeId::new(source_a, ItemId(2), ProbeOutcome::Hit)
        );
    }

    #[test]
    fn selectors_match_the_frozen_protocol() {
        assert_eq!(*HIT_SELECTOR, selector(HIT_SIGNATURE));
        assert_eq!(*BRANCH_SELECTOR, selector(BRANCH_SIGNATURE));
        assert_ne!(*HIT_SELECTOR, *BRANCH_SELECTOR);
    }

    #[test]
    fn generated_identifiers_and_literals_are_valid_solidity_tokens() {
        let source = SourceKey::new(B256::ZERO, Path::new("src/Counter.sol"));
        let probe = ProbeId::new(source, ItemId(7), ProbeOutcome::Hit);

        assert_eq!(source.helper_suffix().len(), 16);
        assert!(source.helper_suffix().bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(probe.solidity_literal().len(), 66);
        assert!(probe.solidity_literal().starts_with("0x"));
    }
}
