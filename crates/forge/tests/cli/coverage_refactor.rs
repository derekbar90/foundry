use foundry_config::fs_permissions::PathPermission;
use foundry_test_utils::{forgetest, util::OutputExt};

forgetest!(instrumented_complex_control_flow, |prj, cmd| {
    prj.insert_ds_test();
    prj.create_file("runtime-marker.txt", "original-project-root");
    prj.update_config(|config| config.fs_permissions.add(PathPermission::read(".")));
    prj.add_source(
        "Complex.sol",
        r#"
contract Complex {
    function nested(uint256 x) public pure returns (uint256) {
        if (x > 10) {
            if (x > 20) {
                return 1;
            } else {
                return 2;
            }
        } else {
            for (uint256 i = 0; i < x; i++) {
                if (i == 5) {
                    return 3;
                }
            }
        }
        return 4;
    }

    function loops(uint256 x) public pure returns (uint256) {
        uint256 y = 0;
        while (x > 0) {
            y++;
            x--;
            if (y > 100) break;
        }
        do {
            y++;
        } while (y < 10);
        return y;
    }
}
    "#,
    );

    prj.add_source(
        "ComplexTest.sol",
        r#"
import "./test.sol";
import {Complex} from "./Complex.sol";

interface Vm {
    function projectRoot() external view returns (string memory);
    function readFile(string calldata) external view returns (string memory);
}

contract ComplexTest is DSTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Complex public complex;

    function setUp() public {
        complex = new Complex();
    }

    function test_Nested() public {
        complex.nested(5);
        complex.nested(15);
        complex.nested(25);
    }

    function test_Loops() public {
        complex.loops(5);
    }

    function test_OriginalProjectRoot() public {
        string memory marker = vm.readFile(string.concat(vm.projectRoot(), "/runtime-marker.txt"));
        require(keccak256(bytes(marker)) == keccak256(bytes("original-project-root")));
    }
}
    "#,
    );

    let output = cmd.arg("coverage").arg("--instrument-source").assert_success();

    let stdout = output.get_output().stdout_lossy();
    assert!(stdout.contains("src/Complex.sol"));
});

forgetest!(instrumented_table_tests_merge_source_hits, |prj, cmd| {
    prj.insert_ds_test();
    prj.add_source(
        "TableTarget.sol",
        r#"
contract TableTarget {
    uint256 public value;
    function set(uint256 next) external { value = next; }
}
"#,
    );
    prj.add_source(
        "TableTargetTest.sol",
        r#"
import "./test.sol";
import {TableTarget} from "./TableTarget.sol";

contract TableTargetTest is DSTest {
    TableTarget target = new TableTarget();
    uint256[] public fixtureAmount = [1, 2, 3];
    function tableSet(uint256 amount) public { target.set(amount); }
}
"#,
    );

    let output = cmd.arg("coverage").arg("--instrument-source").assert_success();
    let stdout = output.get_output().stdout_lossy();
    assert!(stdout.contains("src/TableTarget.sol") && stdout.contains("100.00% (1/1)"), "{stdout}");
});

forgetest!(instrumented_short_circuit_keeps_skipped_call_uncovered, |prj, cmd| {
    prj.insert_ds_test();
    prj.add_source(
        "ShortCircuit.sol",
        r#"
contract ShortCircuit {
    uint256 public calls;

    function side() internal returns (bool) {
        calls++;
        return true;
    }

    function run(bool enabled) external returns (bool) {
        return enabled && side();
    }
}
"#,
    );
    prj.add_source(
        "ShortCircuitTest.sol",
        r#"
import "./test.sol";
import {ShortCircuit} from "./ShortCircuit.sol";
contract ShortCircuitTest is DSTest {
    function testSkippedCall() public {
        ShortCircuit target = new ShortCircuit();
        require(!target.run(false));
        require(target.calls() == 0);
    }
}
"#,
    );

    let output =
        cmd.args(["coverage", "--instrument-source", "--report", "debug"]).assert_success();
    let stdout = output.get_output().stdout_lossy();
    let side = stdout
        .lines()
        .find(|line| line.ends_with("-> \"side()\""))
        .unwrap_or_else(|| panic!("missing canonical side() item:\n{stdout}"));
    assert!(side.contains("hits: 0"), "skipped side() was reported covered: {side}");
});

forgetest!(instrumented_long_short_circuit_chain_avoids_stack_pressure, |prj, cmd| {
    prj.insert_ds_test();
    prj.update_config(|config| {
        config.optimizer = Some(false);
        config.via_ir = false;
    });
    prj.add_source(
        "ShortCircuitChain.sol",
        r#"
contract ShortCircuitChain {
    uint16 constant DIVISOR = 10_000;
    uint16 constant MAX_LOSS = 500;
    uint24 constant MAX_MOVE = 1_000;

    function validate(uint16 input, uint16 loss, uint24 move, address helper) external view {
        address currentHelper = address(this);
        if (currentHelper != address(0) && currentHelper != helper) revert();
        if (currentHelper == address(0) && helper.code.length == 0) revert();
        if (
            input == 0 || input > DIVISOR || loss == 0 || loss > MAX_LOSS
                || move == 0 || move > MAX_MOVE
        ) revert();
    }
}
"#,
    );
    prj.add_source(
        "ShortCircuitChainTest.sol",
        r#"
import "./test.sol";
import {ShortCircuitChain} from "./ShortCircuitChain.sol";
contract ShortCircuitChainTest is DSTest {
    function testValidate() public {
        ShortCircuitChain target = new ShortCircuitChain();
        target.validate(1, 1, 1, address(target));
    }
}
"#,
    );

    cmd.args(["coverage", "--instrument-source"]).assert_success();
});

forgetest!(instrumented_calls_use_owning_contract_and_entry_probe, |prj, cmd| {
    prj.insert_ds_test();
    prj.add_source(
        "Calls.sol",
        r#"
contract Calls {
    uint256 public calls;

    function value() internal returns (uint256) {
        calls++;
        return calls;
    }

    function pair() internal returns (uint256, uint256) {
        calls++;
        return (calls, calls + 1);
    }

    function run() external returns (uint256) {
        require(value() > 0);
        (uint256 left, uint256 right) = pair();
        value();
        return value() + left + right;
    }
}

// Keeping a second contract after `Calls` regresses call items accidentally inheriting the last
// contract name encountered in a source file.
contract LaterContract {}
"#,
    );
    prj.add_source(
        "CallsTest.sol",
        r#"
import "./test.sol";
import {Calls} from "./Calls.sol";
contract CallsTest is DSTest {
    function testCalls() public {
        Calls target = new Calls();
        require(target.run() == 9);
        require(target.calls() == 4);
    }
}
"#,
    );

    cmd.args(["coverage", "--instrument-source"]).assert_success();
});

forgetest!(instrumented_void_and_tuple_for_updates_preserve_control_flow, |prj, cmd| {
    prj.insert_ds_test();
    prj.add_source(
        "LoopUpdates.sol",
        r#"
contract LoopUpdates {
    uint256 public ticks;

    function tick() internal { ticks++; }
    function pair() internal returns (uint256, uint256) {
        ticks++;
        return (1, 2);
    }

    function run() external {
        uint256 i;
        for (i = 0; i < 4; tick()) {
            i++;
            if (i == 1) continue;
            if (i == 3) break;
        }
        for (uint256 j; j < 2; pair()) {
            j++;
        }
    }
}
"#,
    );
    prj.add_source(
        "LoopUpdatesTest.sol",
        r#"
import "./test.sol";
import {LoopUpdates} from "./LoopUpdates.sol";
contract LoopUpdatesTest is DSTest {
    function testUpdates() public {
        LoopUpdates target = new LoopUpdates();
        target.run();
        require(target.ticks() == 4);
    }
}
"#,
    );

    cmd.args(["coverage", "--instrument-source"]).assert_success();
});

forgetest!(instrumented_typed_empty_catch_is_complete, |prj, cmd| {
    prj.insert_ds_test();
    prj.add_source(
        "TypedCatch.sol",
        r#"
contract TypedCatch {
    error Failed();
    function fail() external pure { revert Failed(); }
    function run() external {
        try this.fail() {} catch (bytes memory reason) {}
    }
}
"#,
    );
    prj.add_source(
        "TypedCatchTest.sol",
        r#"
import "./test.sol";
import {TypedCatch} from "./TypedCatch.sol";
contract TypedCatchTest is DSTest {
    function testCatch() public { new TypedCatch().run(); }
}
"#,
    );

    cmd.args(["coverage", "--instrument-source"]).assert_success();
});

forgetest!(instrumented_assembly_requires_partial_opt_in, |prj, cmd| {
    prj.insert_ds_test();
    prj.add_source(
        "AssemblyTarget.sol",
        r#"
contract AssemblyTarget {
    function value() external pure returns (uint256 result) {
        assembly { result := 1 }
    }
}
"#,
    );
    prj.add_source(
        "AssemblyTargetTest.sol",
        r#"
import "./test.sol";
import {AssemblyTarget} from "./AssemblyTarget.sol";
contract AssemblyTargetTest is DSTest {
    function testValue() public { require(new AssemblyTarget().value() == 1); }
}
"#,
    );

    let output = cmd.args(["coverage", "--instrument-source"]).assert_failure();
    let stderr = output.get_output().stderr_lossy();
    assert!(
        stderr.contains("source coverage is incomplete") && stderr.contains("--allow-partial"),
        "{stderr}"
    );
    let output = cmd
        .forge_fuse()
        .args(["coverage", "--instrument-source", "--allow-partial", "--report", "lcov"])
        .assert_failure();
    let stderr = output.get_output().stderr_lossy();
    assert!(stderr.contains("cannot represent partial source coverage"), "{stderr}");
    assert!(!prj.root().join("lcov.info").exists());

    let output = cmd
        .forge_fuse()
        .args(["coverage", "--instrument-source", "--allow-partial", "--report", "bytecode"])
        .assert_failure();
    let stderr = output.get_output().stderr_lossy();
    assert!(stderr.contains("cannot represent partial source coverage"), "{stderr}");
    assert!(!prj.root().join("bytecode-coverage").exists());

    cmd.forge_fuse().args(["coverage", "--instrument-source", "--allow-partial"]).assert_success();
});
