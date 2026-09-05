use super::*;

use std::sync::Mutex;

use acp_proto::{ControlAckStatus, ControlCommand, ControlCommandType};
use tokio::sync::{Notify, Semaphore, oneshot};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

use crate::control::{CommandExecutor, MAX_QUEUED_CONTROL_ACKS, TerminalResult};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct GatedExecutor {
    regular_started: Notify,
    refresh_started: Notify,
    regular_gate: Semaphore,
    refresh_gate: Semaphore,
    calls: Mutex<Vec<String>>,
    completed: Mutex<Vec<String>>,
}

impl GatedExecutor {
    fn new() -> Self {
        Self {
            regular_started: Notify::new(),
            refresh_started: Notify::new(),
            regular_gate: Semaphore::new(0),
            refresh_gate: Semaphore::new(0),
            calls: Mutex::new(Vec::new()),
            completed: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl CommandExecutor for GatedExecutor {
    async fn execute(&self, command: ControlCommand) -> TerminalResult {
        self.calls.lock().unwrap().push(command.command_id.clone());
        match command.command_id.as_str() {
            "regular-active" => {
                self.regular_started.notify_one();
                self.regular_gate.acquire().await.unwrap().forget();
            }
            "refresh-active" => {
                self.refresh_started.notify_one();
                self.refresh_gate.acquire().await.unwrap().forget();
            }
            _ => {}
        }
        self.completed.lock().unwrap().push(command.command_id);
        TerminalResult::applied("completed")
    }
}

fn command(id: &str, kind: ControlCommandType) -> ControlCommand {
    ControlCommand {
        command_id: id.into(),
        r#type: kind as i32,
        ..Default::default()
    }
}

async fn submit_and_take_accepted(
    worker: &ControlCommandWorker,
    acknowledgements: &mut mpsc::Receiver<ControlAck>,
    id: &str,
    kind: ControlCommandType,
) {
    worker.submit(command(id, kind)).await.unwrap();
    let acknowledgement = acknowledgements.recv().await.unwrap();
    assert_eq!(acknowledgement.command_id, id);
    assert_eq!(acknowledgement.status, ControlAckStatus::Accepted as i32);
}

async fn wait_for_worker_exit(executor: &Arc<GatedExecutor>) {
    // Each command lane owns the executor until it exits. Waiting for both
    // owners to disappear also proves that no queued successor can run later.
    while Arc::strong_count(executor) != 1 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn refresh_acks_are_forwarded_while_regular_submission_waits_for_capacity() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let cancel = CancellationToken::new();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let executor = Arc::new(GatedExecutor::new());
        let (worker, mut acknowledgements) = ControlCommandWorker::spawn_with_capacity_and_cancel(
            executor.clone(),
            Arc::new(AckStore::new()),
            1,
            MAX_QUEUED_CONTROL_ACKS,
            cancel.clone(),
        );

        submit_and_take_accepted(
            &worker,
            &mut acknowledgements,
            "regular-active",
            ControlCommandType::UserMutation,
        )
        .await;
        executor.regular_started.notified().await;
        submit_and_take_accepted(
            &worker,
            &mut acknowledgements,
            "regular-queued",
            ControlCommandType::UserMutation,
        )
        .await;
        submit_and_take_accepted(
            &worker,
            &mut acknowledgements,
            "refresh-active",
            ControlCommandType::UserRefresh,
        )
        .await;
        executor.refresh_started.notified().await;
        for index in 0..MAX_QUEUED_CONTROL_ACKS {
            submit_and_take_accepted(
                &worker,
                &mut acknowledgements,
                &format!("refresh-{index}"),
                ControlCommandType::UserRefresh,
            )
            .await;
        }

        let (commands_tx, commands_rx) = mpsc::channel(1);
        commands_tx
            .send(Ok(command(
                "regular-waiting",
                ControlCommandType::UserMutation,
            )))
            .await
            .unwrap();
        let (read_command, command_read) = oneshot::channel();
        let mut read_command = Some(read_command);
        let commands = ReceiverStream::new(commands_rx).map(move |command| {
            read_command.take().unwrap().send(()).unwrap();
            command
        });
        let (ack_sender, mut panel_acks) = mpsc::channel(1);
        let runner = tokio::spawn(run_control_stream_parts(
            cancel.clone(),
            commands,
            ack_sender,
            worker,
            acknowledgements,
        ));
        command_read.await.unwrap();
        // On the current-thread test runtime the runner has now yielded inside
        // submit: the regular lane is gated and its only queue slot is occupied.
        executor.refresh_gate.add_permits(1);
        for index in 0..=MAX_QUEUED_CONTROL_ACKS {
            let acknowledgement = panel_acks.recv().await.unwrap();
            let expected = if index == 0 {
                "refresh-active".to_string()
            } else {
                format!("refresh-{}", index - 1)
            };
            assert_eq!(acknowledgement.command_id, expected);
            assert_eq!(acknowledgement.status, ControlAckStatus::Applied as i32);
        }
        // More than the entire ACK capacity has crossed the real stream runner
        // while it still cannot accept the pending regular command.
        assert!(
            !executor
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|id| id == "regular-waiting")
        );
        executor.regular_gate.add_permits(1);
        let mut waiting_statuses = Vec::new();
        for _ in 0..4 {
            let acknowledgement = panel_acks.recv().await.unwrap();
            if acknowledgement.command_id == "regular-waiting" {
                waiting_statuses.push(acknowledgement.status);
            } else {
                assert!(matches!(
                    acknowledgement.command_id.as_str(),
                    "regular-active" | "regular-queued"
                ));
                assert_eq!(acknowledgement.status, ControlAckStatus::Applied as i32);
            }
        }
        assert_eq!(
            waiting_statuses,
            [
                ControlAckStatus::Accepted as i32,
                ControlAckStatus::Applied as i32,
            ]
        );
        cancel.cancel();
        runner.await.unwrap().unwrap();
        wait_for_worker_exit(&executor).await;
        drop(commands_tx);
    })
    .await
    .expect("ACK forwarding must remain live while a command queue is full");
}

#[tokio::test]
async fn cancellation_interrupts_a_backpressured_panel_ack_send() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let cancel = CancellationToken::new();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let executor = Arc::new(GatedExecutor::new());
        let (worker, acknowledgements) = ControlCommandWorker::spawn_with_capacity_and_cancel(
            executor.clone(),
            Arc::new(AckStore::new()),
            1,
            1,
            cancel.clone(),
        );
        worker
            .submit(command("regular-active", ControlCommandType::UserMutation))
            .await
            .unwrap();
        executor.regular_started.notified().await;
        assert_eq!(acknowledgements.len(), 1);

        let (ack_sender, mut panel_acks) = mpsc::channel(1);
        ack_sender
            .send(ControlAck {
                command_id: "already-buffered".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        let (commands_tx, commands_rx) = mpsc::channel(1);
        let mut runner = Box::pin(tokio::task::unconstrained(run_control_stream_parts(
            cancel.clone(),
            ReceiverStream::new(commands_rx),
            ack_sender,
            worker,
            acknowledgements,
        )));
        // Exhaust the immediately ready work without a cooperative-budget yield:
        // an ACCEPTED ACK is ready, but its one-slot panel channel is already full.
        std::future::poll_fn(|cx| {
            assert!(runner.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        cancel.cancel();
        runner.await.unwrap();
        assert_eq!(
            panel_acks.recv().await.unwrap().command_id,
            "already-buffered"
        );
        assert!(panel_acks.recv().await.is_none());
        executor.regular_gate.add_permits(1);
        wait_for_worker_exit(&executor).await;
        drop(commands_tx);
    })
    .await
    .expect("cancellation must not wait for the panel to resume reading ACKs");
}

#[tokio::test]
async fn command_eof_cancels_queue_without_aborting_started_execution() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let cancel = CancellationToken::new();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let executor = Arc::new(GatedExecutor::new());
        let (worker, mut acknowledgements) = ControlCommandWorker::spawn_with_capacity_and_cancel(
            executor.clone(),
            Arc::new(AckStore::new()),
            1,
            1,
            cancel.clone(),
        );
        submit_and_take_accepted(
            &worker,
            &mut acknowledgements,
            "regular-active",
            ControlCommandType::UserMutation,
        )
        .await;
        executor.regular_started.notified().await;
        submit_and_take_accepted(
            &worker,
            &mut acknowledgements,
            "regular-queued",
            ControlCommandType::UserMutation,
        )
        .await;
        let (ack_sender, mut panel_acks) = mpsc::channel(1);
        let result = run_control_stream_parts(
            cancel,
            tokio_stream::empty(),
            ack_sender,
            worker,
            acknowledgements,
        )
        .await;
        assert!(matches!(result, Err(SessionError::CriticalStreamEnded(_))));
        assert!(executor.completed.lock().unwrap().is_empty());
        executor.regular_gate.add_permits(1);
        wait_for_worker_exit(&executor).await;
        assert_eq!(*executor.calls.lock().unwrap(), ["regular-active"]);
        assert_eq!(*executor.completed.lock().unwrap(), ["regular-active"]);
        assert!(panel_acks.recv().await.is_none());
    })
    .await
    .expect("EOF must end the session while an accepted transaction finishes safely");
}
