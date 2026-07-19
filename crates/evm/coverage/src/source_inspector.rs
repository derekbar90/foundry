use crate::{
    ProbeId, SourceHitMaps,
    probe::{BOOL_SELECTOR, BRANCH_SELECTOR, HIT_SELECTOR},
};
use alloy_primitives::{Address, B256, Bytes};
use revm::{
    Inspector,
    context::ContextTr,
    inspector::JournalExt,
    interpreter::{CallInputs, CallOutcome, InstructionResult, InterpreterResult},
};

/// Address of the specialized cheatcode contract for coverage.
/// address(uint160(uint256(keccak256("hevm cheat code"))))
pub const CHEATCODE_ADDRESS: Address = Address::new([
    0x71, 0x09, 0x70, 0x9E, 0xCF, 0xa9, 0x1a, 0x80, 0x62, 0x6f, 0xF3, 0x98, 0x9D, 0x68, 0xf6, 0x7F,
    0x5b, 0x1D, 0xD1, 0x2D,
]);

#[derive(Debug, Clone, Default)]
pub struct SourceCoverageCollector {
    pub maps: SourceHitMaps,
}

impl<CTX> Inspector<CTX> for SourceCoverageCollector
where
    CTX: ContextTr<Journal: JournalExt>,
{
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        if inputs.target_address != CHEATCODE_ADDRESS {
            return None;
        }

        let decoded = decode_probe_call(&inputs.input.bytes(context))?;
        let output = match decoded {
            DecodedProbeCall::Hit(probe) => {
                self.maps.hit(probe);
                Bytes::new()
            }
            DecodedProbeCall::Bool { probe, value } => {
                self.maps.hit(probe);
                encoded_bool(value)
            }
            DecodedProbeCall::Branch { if_true, if_false, value } => {
                self.maps.hit(if value { if_true } else { if_false });
                encoded_bool(value)
            }
        };

        Some(CallOutcome {
            result: InterpreterResult {
                result: InstructionResult::Return,
                output,
                gas: revm::interpreter::Gas::new(inputs.gas_limit),
            },
            memory_offset: inputs.return_memory_offset.clone(),
            was_precompile_called: false,
            precompile_call_logs: vec![],
            charged_new_account_state_gas: false,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodedProbeCall {
    Hit(ProbeId),
    Bool { probe: ProbeId, value: bool },
    Branch { if_true: ProbeId, if_false: ProbeId, value: bool },
}

fn decode_probe_call(input: &[u8]) -> Option<DecodedProbeCall> {
    let selector: [u8; 4] = input.get(..4)?.try_into().ok()?;
    if selector == *HIT_SELECTOR {
        if input.len() != 36 {
            return None;
        }
        return Some(DecodedProbeCall::Hit(ProbeId::from_digest(B256::from_slice(&input[4..36]))));
    }

    if selector == *BOOL_SELECTOR {
        if input.len() != 68 {
            return None;
        }
        return Some(DecodedProbeCall::Bool {
            probe: ProbeId::from_digest(B256::from_slice(&input[4..36])),
            value: decode_bool_word(&input[36..68])?,
        });
    }

    if selector != *BRANCH_SELECTOR || input.len() != 100 {
        return None;
    }
    Some(DecodedProbeCall::Branch {
        if_true: ProbeId::from_digest(B256::from_slice(&input[4..36])),
        if_false: ProbeId::from_digest(B256::from_slice(&input[36..68])),
        value: decode_bool_word(&input[68..100])?,
    })
}

fn decode_bool_word(word: &[u8]) -> Option<bool> {
    (word.len() == 32 && word[..31].iter().all(|&byte| byte == 0) && word[31] <= 1)
        .then(|| word[31] == 1)
}

fn encoded_bool(value: bool) -> Bytes {
    let mut encoded = [0u8; 32];
    encoded[31] = u8::from(value);
    Bytes::copy_from_slice(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_exact_hit_bool_and_branch_calls() {
        let true_id = B256::repeat_byte(0x11);
        let false_id = B256::repeat_byte(0x22);
        let mut hit = Vec::from(*HIT_SELECTOR);
        hit.extend_from_slice(true_id.as_slice());
        assert_eq!(
            decode_probe_call(&hit),
            Some(DecodedProbeCall::Hit(ProbeId::from_digest(true_id)))
        );

        let mut bool_call = Vec::from(*BOOL_SELECTOR);
        bool_call.extend_from_slice(true_id.as_slice());
        bool_call.extend_from_slice(&[0u8; 31]);
        bool_call.push(1);
        assert_eq!(
            decode_probe_call(&bool_call),
            Some(DecodedProbeCall::Bool { probe: ProbeId::from_digest(true_id), value: true })
        );

        let mut branch = Vec::from(*BRANCH_SELECTOR);
        branch.extend_from_slice(true_id.as_slice());
        branch.extend_from_slice(false_id.as_slice());
        branch.extend_from_slice(&[0u8; 31]);
        branch.push(1);
        assert_eq!(
            decode_probe_call(&branch),
            Some(DecodedProbeCall::Branch {
                if_true: ProbeId::from_digest(true_id),
                if_false: ProbeId::from_digest(false_id),
                value: true,
            })
        );
    }

    #[test]
    fn rejects_non_canonical_or_truncated_calldata() {
        let mut invalid_bool = Vec::from(*BRANCH_SELECTOR);
        invalid_bool.extend_from_slice(B256::ZERO.as_slice());
        invalid_bool.extend_from_slice(B256::ZERO.as_slice());
        invalid_bool.extend_from_slice(&[0u8; 31]);
        invalid_bool.push(2);
        assert_eq!(decode_probe_call(&invalid_bool), None);
        assert_eq!(decode_probe_call(&invalid_bool[..99]), None);

        let mut invalid_single_bool = Vec::from(*BOOL_SELECTOR);
        invalid_single_bool.extend_from_slice(B256::ZERO.as_slice());
        invalid_single_bool.extend_from_slice(&[0u8; 31]);
        invalid_single_bool.push(2);
        assert_eq!(decode_probe_call(&invalid_single_bool), None);
        assert_eq!(decode_probe_call(&[]), None);
    }
}

impl SourceCoverageCollector {
    /// Finish collecting coverage information and return the [`SourceHitMaps`].
    pub fn finish(self) -> SourceHitMaps {
        self.maps
    }
}
