mod helpers;
mod tor_service;
mod web_server;

use anyhow::Result;
use futures_util::{pin_mut, StreamExt};
use std::{sync::Arc, thread};
use tokio::{
    runtime::Builder,
    sync::{mpsc, Semaphore},
    task::JoinSet,
    time::{timeout, Duration},
};

use crate::helpers::hsid_from_user_mnemonic;
use crate::tor_service::init_tor_service;
use crate::web_server::{app_service, handle_client};

const CLIENT_TIMEOUT: Duration = Duration::from_secs(70);

struct AppTuning {
    queue_capacity: usize,
    max_inflight: usize,
    worker_threads: usize,
}

fn compute_tuning() -> AppTuning {
    let cpus = thread::available_parallelism().map(|v| v.get()).unwrap_or(4);
    let worker_threads = cpus.clamp(2, 32);
    let max_inflight = (worker_threads * 16).max(64);
    let queue_capacity = max_inflight * 2;
    AppTuning {
        queue_capacity,
        max_inflight,
        worker_threads,
    }
}

fn main() -> Result<()> {
    let tuning = compute_tuning();

    let rt = Builder::new_multi_thread()
        .worker_threads(tuning.worker_threads)
        .enable_all()
        .thread_name("onion-svc")
        .build()?;

    let res = rt.block_on(async_main(tuning));

    // Immediate teardown; do not wait for graceful shutdown.
    rt.shutdown_background();

    res
}

async fn async_main(tuning: AppTuning) -> Result<()> {
    let hsid = hsid_from_user_mnemonic()?;
    let (tor_client, running_service, stream_requests) = init_tor_service(hsid).await?;

    // Keep the core service handles alive for the lifetime of the process.
    let _tor_client = tor_client;
    let _running_service = running_service;

    let app = Arc::new(app_service());
    let sem = Arc::new(Semaphore::new(tuning.max_inflight));

    let (tx, mut rx) = mpsc::channel(tuning.queue_capacity);

    // Track producer separately
    let mut producer_tasks = JoinSet::new();
    // Track all client handlers so they don't outlive runtime shutdown
    let mut client_tasks = JoinSet::new();

    // Producer: read incoming streams and push into bounded channel.
    producer_tasks.spawn({
        let tx = tx.clone();
        async move {
            pin_mut!(stream_requests);
            loop {
                tokio::select! {
                    maybe_req = stream_requests.next() => {
                        let Some(stream_req) = maybe_req else {
                            println!("🛑 producer: stream_requests closed");
                            break;
                        };

                        if tx.send(stream_req).await.is_err() {
                            println!("⚠️  producer: queue closed, dropping connection");
                            break;
                        }
                    }
                }
            }
            println!("🛑 producer exited");
        }
    });

    println!("⌛ waiting for Ctrl+C…");

    // Main loop acts as dispatcher: reads queue and spawns client tasks (tracked).
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("💀 Ctrl+C received, aborting tasks immediately…");
                producer_tasks.abort_all();
                client_tasks.abort_all();
                break;
            }

            maybe_req = rx.recv() => {
                let Some(stream_req) = maybe_req else {
                    break;
                };

                let permit = match sem.clone().acquire_owned().await {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("🛑 semaphore closed");
                        break;
                    }
                };

                let app = app.clone();
                client_tasks.spawn(async move {
                    let _permit = permit;

                    match timeout(CLIENT_TIMEOUT, handle_client(stream_req, app)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            eprintln!("❌ client error: {:?}", err);
                        }
                        Err(_) => {
                            eprintln!("⏱ client timeout after {:?}", CLIENT_TIMEOUT);
                        }
                    }
                });
            }
        }
    }

    println!("🔥 shutdown requested; tasks aborted without grace");
    Ok(())
}
