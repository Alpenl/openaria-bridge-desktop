//! Issue #1 commits 37–38, from the outside: the transfer job state
//! machine and its reducer are usable — and provable — without a database,
//! a network, a thread or a clock.
//!
//! The in-crate unit tests pin the full state x command table. This file
//! is the *external* contract: everything a consumer needs to reason about
//! a job is reachable through the public API, the reducer is pure, and the
//! four invariants the refactor plan names hold for every state and every
//! command.

use ylx_transfer_core::transfer::aggregate::{all_states, state_name};
use ylx_transfer_core::transfer::{
    is_legal_transition, CommandOutcome, DesiredRunState, Effect, FailureCode, JobAggregate,
    JobCommand, RejectReason, TransferJobState,
};

fn commands() -> Vec<JobCommand> {
    let mut commands = vec![
        JobCommand::Pause,
        JobCommand::Resume,
        JobCommand::Cancel,
        JobCommand::FinalizeCancel,
        JobCommand::Retry,
        JobCommand::Dismiss,
    ];
    // Every possible target state, so the table covers all 13 x 13
    // transition commands too, not just one representative.
    commands.extend(all_states().into_iter().map(JobCommand::Transition));
    commands
}

fn commits(decision: &ylx_transfer_core::transfer::Decision) -> Vec<(u64, TransferJobState)> {
    decision
        .effects
        .iter()
        .filter_map(|e| match e {
            Effect::Commit {
                expected_version,
                to,
                ..
            } => Some((*expected_version, to.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn every_state_and_command_pair_is_decided_without_touching_the_outside_world() {
    // The reducer is a plain value: constructing it needs no store, no
    // port, no runtime. That is the whole claim of commit 38, and this
    // test would not compile if it stopped being true.
    for state in all_states() {
        for command in commands() {
            let decision = JobAggregate::new(state.clone()).decide(command);
            match &decision.outcome {
                CommandOutcome::Accepted => assert!(
                    !decision.effects.is_empty(),
                    "{}: accepted with nothing to do",
                    state_name(&state)
                ),
                CommandOutcome::NoOp | CommandOutcome::Rejected(_) => assert!(
                    decision.effects.is_empty(),
                    "{}: refused/no-op commands must produce no effects",
                    state_name(&state)
                ),
            }
        }
    }
}

#[test]
fn a_terminal_state_is_never_left() {
    for state in all_states()
        .into_iter()
        .filter(TransferJobState::is_terminal)
    {
        for command in commands() {
            let decision = JobAggregate::new(state.clone()).decide(command.clone());
            assert!(
                commits(&decision).is_empty(),
                "{} + {} proposed leaving a terminal state",
                state_name(&state),
                command.name()
            );
        }
    }
}

#[test]
fn versions_increase_monotonically_and_never_repeat_within_a_decision() {
    for version in [1_u64, 2, 99] {
        for state in all_states() {
            for command in commands() {
                let decision = JobAggregate::new(state.clone())
                    .with_version(version)
                    .decide(command);
                let versions: Vec<u64> = commits(&decision).into_iter().map(|(v, _)| v).collect();
                let expected: Vec<u64> = (0..versions.len() as u64).map(|i| version + i).collect();
                assert_eq!(versions, expected, "{}", state_name(&state));
            }
        }
    }
}

#[test]
fn an_illegal_command_produces_no_effects() {
    let terminal = TransferJobState::Succeeded;
    for command in commands() {
        let decision = JobAggregate::new(terminal.clone()).decide(command);
        if let CommandOutcome::Rejected(reason) = &decision.outcome {
            assert!(matches!(
                reason,
                RejectReason::AlreadyTerminal | RejectReason::NotFailed
            ));
            assert!(decision.effects.is_empty());
        }
    }

    // A specific illegal edge: canonical publication cannot jump back to a
    // capture-active pause state.
    let decision = JobAggregate::new(TransferJobState::Committing).decide(JobCommand::Transition(
        TransferJobState::PausedCaptureActive,
    ));
    assert_eq!(
        decision.outcome,
        CommandOutcome::Rejected(RejectReason::IllegalTransition {
            from: TransferJobState::Committing,
            to: TransferJobState::PausedCaptureActive,
        })
    );
    assert!(decision.effects.is_empty());
}

#[test]
fn a_cancel_that_arrives_twice_transitions_once() {
    let aggregate = JobAggregate::new(TransferJobState::Transferring);
    let first = aggregate.decide(JobCommand::Cancel);
    assert_eq!(
        commits(&first),
        vec![(1, TransferJobState::Cancelling)],
        "the first cancel enters cancelling"
    );

    // The second caller decides against the state the first one committed
    // — which is exactly what the per-job serialized owner guarantees it
    // sees — and proposes no second transition.
    let after =
        JobAggregate::new(first.final_state(&TransferJobState::Transferring)).with_version(2);
    let second = after.decide(JobCommand::Cancel);
    assert_eq!(second.outcome, CommandOutcome::Accepted);
    assert!(
        commits(&second).is_empty(),
        "a second cancel must not attempt cancelling -> cancelling"
    );

    // Finalizing is idempotent for the same reason.
    let finalized = after.decide(JobCommand::FinalizeCancel);
    assert_eq!(commits(&finalized), vec![(2, TransferJobState::Cancelled)]);
    let again = JobAggregate::new(TransferJobState::Cancelled)
        .with_version(3)
        .decide(JobCommand::FinalizeCancel);
    assert_eq!(again.outcome, CommandOutcome::NoOp);
    assert!(again.effects.is_empty());
}

#[test]
fn pausing_is_a_desired_run_state_not_a_job_state() {
    let decision = JobAggregate::new(TransferJobState::Transferring).decide(JobCommand::Pause);
    assert!(
        commits(&decision).is_empty(),
        "pause must not invent a durable state; plan 5.4 has none"
    );
    assert!(decision
        .effects
        .contains(&Effect::SetDesiredRunState(DesiredRunState::Paused)));

    // Resuming a job resting in `retry_wait` is the one pause-shaped
    // command that *does* move the state machine.
    let resumed = JobAggregate::new(TransferJobState::RetryWait)
        .with_desired_run_state(DesiredRunState::Paused)
        .decide(JobCommand::Resume);
    assert_eq!(commits(&resumed), vec![(1, TransferJobState::Queued)]);
    assert!(resumed
        .effects
        .contains(&Effect::SetDesiredRunState(DesiredRunState::Run)));
}

#[test]
fn only_a_failed_job_can_be_retried_and_a_retry_is_a_new_job() {
    for state in all_states() {
        let decision = JobAggregate::new(state.clone()).decide(JobCommand::Retry);
        if matches!(state, TransferJobState::Failed { .. }) {
            assert_eq!(decision.effects, vec![Effect::SpawnRetryJob]);
            assert!(
                commits(&decision).is_empty(),
                "a retry never resurrects the failed row"
            );
        } else {
            assert_eq!(
                decision.outcome,
                CommandOutcome::Rejected(RejectReason::NotFailed),
                "{}",
                state_name(&state)
            );
        }
    }
}

#[test]
fn the_legal_transition_graph_is_reachable_and_closed() {
    // Every non-terminal state can reach a terminal one, and every
    // terminal one is a sink. A state that could neither finish nor be
    // cancelled would be a job the user can never get rid of.
    for state in all_states() {
        let mut seen = vec![state.clone()];
        let mut frontier = vec![state.clone()];
        while let Some(current) = frontier.pop() {
            for next in all_states() {
                if is_legal_transition(&current, &next) && !seen.contains(&next) {
                    seen.push(next.clone());
                    frontier.push(next);
                }
            }
        }
        assert!(
            seen.iter().any(TransferJobState::is_terminal),
            "{} can never reach a terminal state",
            state_name(&state)
        );
    }

    assert!(!is_legal_transition(
        &TransferJobState::Succeeded,
        &TransferJobState::Queued
    ));
    assert!(!is_legal_transition(
        &TransferJobState::Failed {
            code: FailureCode::Network,
            retryable: true
        },
        &TransferJobState::Queued
    ));
}
