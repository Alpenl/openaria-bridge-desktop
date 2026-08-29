mod application;
#[path = "application/workflows.rs"]
mod application_workflows;
mod commands;
mod composition;
#[cfg(feature = "demo")]
mod demo;
mod library_delete;
mod media;
mod models;
#[cfg(feature = "demo")]
mod sim;
mod state;

#[cfg(target_os = "linux")]
use std::sync::Arc;

use tauri::Manager;

use application::TransferApplication;
use media::adapters::fail_closed_media_ports;
use media::{ports::MediaProjectionSet, MediaApplication, MediaProjectionBridge};
#[cfg(target_os = "linux")]
use media::{
    ports::{MediaProjectionSink, RecordingIngestorPort},
    trust::{CompositionMediaTrustPort, MediaStoreTrustedProducerRegistry},
    ubuntu::UbuntuMediaRuntime,
    ubuntu_derivation::UbuntuDerivationPort,
    ubuntu_ingestor::{UbuntuIngestConfig, UbuntuRecordingIngestor},
    ubuntu_lifecycle::{
        ubuntu_media_lifecycle, UbuntuImportRecovery, UbuntuImportRecoveryAdapter,
        UbuntuNormalizerRecovery, UbuntuNormalizerRecoveryAdapter, UbuntuProjectionSupplier,
    },
    ubuntu_normalizer::ubuntu_mvp_normalizer_port,
    ubuntu_pipeline::{UbuntuPipelineConfig, UbuntuPipelinePort},
    ubuntu_projector::UbuntuMediaCompletionProjector,
    ubuntu_uploader::{storage_profile_identity_for, UbuntuDerivedUploader},
    ubuntu_workers::{WorkerLane, DEFAULT_QUEUE_CAPACITY, DEFAULT_STOP_TIMEOUT},
    MediaApplicationPorts,
};
use state::{AppState, BootConfig};
#[cfg(target_os = "linux")]
use ylx_transfer_core::media_library::AppStoreMediaLibraryProjectionRepository;

/// The projector lane is level-triggered, so one constant id is enough: a
/// second wake-up while a drain is running would only repeat work the running
/// drain is already doing.
#[cfg(target_os = "linux")]
const MEDIA_PROJECTOR_WAKEUP: &str = "media-library-projection";

/// Recover the durable Ubuntu media graph in dependency order while every
/// worker lane is still inactive. Returning the import projection preserves
/// the lifecycle adapter's existing recovery contract.
#[cfg(target_os = "linux")]
fn recover_ubuntu_media_graph<T, E>(
    project_completions: impl FnOnce() -> Result<(), E>,
    recover_imports: impl FnOnce() -> Result<T, E>,
    recover_derivations: impl FnOnce() -> Result<(), E>,
    reconcile_pipeline: impl FnOnce() -> Result<(), E>,
    recover_uploads: impl FnOnce() -> Result<(), E>,
) -> Result<T, E> {
    project_completions()?;
    let imports = recover_imports()?;
    recover_derivations()?;
    reconcile_pipeline()?;
    recover_uploads()?;
    Ok(imports)
}

/// Assemble the Ubuntu-only mounted-media graph without starting recovery.
///
/// The scanner runtime, candidate catalog, and artifact resolver are one
/// shared object. Likewise, the ingestor, projection reader, and lifecycle
/// all use the composition's one durable media store, and the completion
/// projector uses the application's one `AppStore` connection rather than a
/// second writer that would bypass its revision compare-and-swap. The facade
/// starts recovery only after it has been registered as managed Tauri state.
#[cfg(target_os = "linux")]
fn ubuntu_media_application_ports(
    composition: &Arc<composition::Composition>,
    app_store: Arc<ylx_transfer_core::persistence::AppStore>,
    projection_bridge: Arc<MediaProjectionBridge>,
) -> Result<MediaApplicationPorts, media::ports::MediaPortError> {
    let media_store = composition.media_store();
    // Trust is read through a narrow registry seam so admission cannot reach
    // SQLite directly, and cannot write trust at all.
    let trusted_producers = MediaStoreTrustedProducerRegistry::new(Arc::clone(&media_store));
    let trust_port = CompositionMediaTrustPort::new(Arc::clone(composition));
    let runtime = UbuntuMediaRuntime::start(Arc::clone(&media_store), trusted_producers)?;
    let ingestor = Arc::new(UbuntuRecordingIngestor::new(
        Arc::clone(&runtime),
        Arc::clone(&media_store),
        Arc::clone(composition),
        UbuntuIngestConfig::new(),
    )?);
    let pipeline_config = app_store
        .load()
        .map_err(|error| {
            media::ports::MediaPortError::new(
                media::ports::MediaErrorCode::StorageNotConfigured,
                format!("cannot read persisted storage coordinates: {error}"),
            )
            .with_retryable(true)
        })?
        .storage
        .and_then(|bytes| serde_json::from_slice::<crate::models::StorageConfig>(&bytes).ok())
        .and_then(|storage| storage_profile_identity_for(&storage).ok())
        .map(UbuntuPipelineConfig::with_storage_profile_identity)
        .unwrap_or_else(UbuntuPipelineConfig::new);
    let pipeline = Arc::new(UbuntuPipelinePort::new(
        Arc::clone(&ingestor),
        Arc::clone(&media_store),
        pipeline_config,
    ));

    // The completion projector consumes the media-store outboxes into the
    // shared AppStore. It gets its own single-threaded lane so outbox sequence
    // order and AppStore CAS convergence are both preserved, and so projection
    // work never runs while the application-state lock is held.
    let projector = UbuntuMediaCompletionProjector::new(
        Arc::clone(&media_store),
        composition.transfer_store(),
        AppStoreMediaLibraryProjectionRepository::new(
            Arc::clone(&app_store),
            Arc::new(|| chrono::Utc::now().to_rfc3339()),
        ),
        Arc::new(|| chrono::Utc::now().to_rfc3339()),
    );
    // The lane is level-triggered: any wake-up drains everything pending, so
    // the queued id is only a signal and never identifies specific work.
    let projector_lane = WorkerLane::spawn_inactive("library-projector", DEFAULT_QUEUE_CAPACITY, {
        let projector = Arc::clone(&projector);
        let projection_bridge = Arc::clone(&projection_bridge);
        move |_wakeup| match projector.drain() {
            Ok(_) => match projector.projection_snapshot() {
                Ok((source_version, projections)) => {
                    match media::ubuntu_projection::map_media_library_collection(
                        source_version,
                        &projections,
                    ) {
                        Ok(library) => {
                            let delta = media::ports::MediaProjectionDelta {
                                library: Some(library),
                                ..media::ports::MediaProjectionDelta::default()
                            };
                            if let Err(error) = projection_bridge.publish(delta) {
                                let code = error.into_rpc().code;
                                eprintln!(
                                    "[media] library projection publication skipped ({code})"
                                );
                            }
                        }
                        Err(error) => {
                            let code = error.into_rpc().code;
                            eprintln!("[media] library projection mapping failed ({code})");
                        }
                    }
                }
                Err(error) => {
                    let code = error.into_rpc().code;
                    eprintln!("[media] library projection read failed ({code})");
                }
            },
            Err(error) => {
                let code = error.into_rpc().code;
                eprintln!("[media] library projection drain failed ({code})");
            }
        }
    });

    // The upload lane owns only durable derived-bundle jobs. It uses the
    // composition factory for every S3 client, so credentials never cross
    // into this module and the lane cannot grow a second object-store setup.
    let uploader = UbuntuDerivedUploader::new(
        Arc::clone(&media_store),
        composition.transfer_store(),
        Arc::clone(&app_store),
        Arc::clone(composition),
    );
    let upload_lane = WorkerLane::spawn_over_inactive("upload", uploader.wake_queue(), {
        let uploader = Arc::clone(&uploader);
        let projector_lane = Arc::clone(&projector_lane);
        let pipeline = Arc::clone(&pipeline);
        move |job_id| {
            if let Err(error) = uploader.run_upload_once(job_id) {
                let code = error.into_rpc().code;
                eprintln!("[media] derived upload worker turn failed ({code})");
            }
            if let Err(error) = pipeline.reconcile_all() {
                let code = error.into_rpc().code;
                eprintln!("[media] upload pipeline reconciliation failed ({code})");
            }
            let _ = projector_lane.enqueue(MEDIA_PROJECTOR_WAKEUP);
        }
    });

    // One import lane, spawned over the ingestor's own wake queue. Commands
    // only ever push job ids onto that queue; this thread is the single place
    // where copy I/O happens, so a large session import cannot hold a Tauri
    // command — or a pause — open behind it.
    let import_lane = WorkerLane::spawn_over_inactive("import", ingestor.wake_queue(), {
        let ingestor = Arc::clone(&ingestor);
        let projector_lane = Arc::clone(&projector_lane);
        let pipeline = Arc::clone(&pipeline);
        move |job_id| {
            if let Err(error) = ingestor.run_import_once(job_id) {
                // The authoritative outcome is the durable job row, which the
                // executor already updated. Only the bounded stable code is
                // logged; worker diagnostics must not become a data channel.
                let code = error.into_rpc().code;
                eprintln!("[media] import worker turn failed ({code})");
            }
            if let Err(error) = pipeline.reconcile_all() {
                let code = error.into_rpc().code;
                eprintln!("[media] import pipeline reconciliation failed ({code})");
            }
            // Wake the projector rather than projecting inline: the outbox row
            // is already durable, so this is a latency hint, and keeping it off
            // this thread leaves the import lane free for the next copy.
            let _ = projector_lane.enqueue(MEDIA_PROJECTOR_WAKEUP);
        }
    });

    // The derivation lane is wired to the real core executor, but the release
    // gate is untouched: `UbuntuDerivationPort` can only start work against a
    // profile the shipped approval manifest resolves, and that manifest is
    // empty until each profile carries its five review reports. A machine
    // without a usable FFmpeg has no port at all, which is a different fact
    // from "nothing approved" and stays a different error.
    let library_root = composition.library_root();
    // `DerivedStaging` owns its hidden `.ylx-derived-staging` child below the
    // library root. Pass that exact child to the quality reporter for
    // containment checks; the filesystem transaction itself still receives
    // the library root so its atomic rename lands in `derivatives/`.
    let staging_root = library_root.join(".ylx-derived-staging");
    let derivation =
        UbuntuDerivationPort::start(Arc::clone(&media_store), library_root, staging_root);
    let (normalizer, derivation_lane, derivation_shutdown) = match derivation {
        Ok(port) => {
            let lane = WorkerLane::spawn_over_inactive("derive", port.wake_queue(), {
                let port = Arc::clone(&port);
                let projector_lane = Arc::clone(&projector_lane);
                let pipeline = Arc::clone(&pipeline);
                move |job_id| {
                    if let Err(error) = port.run_derivation_once(job_id) {
                        let code = error.into_rpc().code;
                        eprintln!("[media] derivation worker turn failed ({code})");
                    }
                    if let Err(error) = pipeline.reconcile_all() {
                        let code = error.into_rpc().code;
                        eprintln!("[media] derivation pipeline reconciliation failed ({code})");
                    }
                    let _ = projector_lane.enqueue(MEDIA_PROJECTOR_WAKEUP);
                }
            });
            (
                Arc::clone(&port) as Arc<dyn media::ports::MediaNormalizerPort>,
                Some(lane),
                Some(port),
            )
        }
        Err(error) => {
            // Not fatal: import stays fully usable on a machine that cannot
            // encode, and the typed capability error is what the UI renders.
            let code = error.into_rpc().code;
            eprintln!("[media] normalization backend unavailable ({code})");
            (ubuntu_mvp_normalizer_port(), None, None)
        }
    };

    pipeline.set_downstream_owners(
        Arc::clone(&normalizer),
        Arc::clone(&uploader),
        composition.transfer_store(),
    );

    let imports: Arc<dyn UbuntuImportRecovery> =
        Arc::new(UbuntuImportRecoveryAdapter::with_start_shutdown(
            {
                let ingestor = Arc::clone(&ingestor);
                let projector = Arc::clone(&projector);
                let uploader = Arc::clone(&uploader);
                let derivation = derivation_shutdown.clone();
                let pipeline = Arc::clone(&pipeline);
                move || {
                    // Replay every durable owner while all worker lanes remain
                    // inactive. Any failure aborts lifecycle recovery; starting
                    // consumers from a partially recovered graph would make the
                    // resulting projection and dependency order untrustworthy.
                    recover_ubuntu_media_graph(
                        || projector.drain().map(|_| ()),
                        || ingestor.recover_pending_imports(),
                        || {
                            if let Some(derivation) = &derivation {
                                derivation.recover_pending_derivations()?;
                            }
                            Ok(())
                        },
                        || pipeline.reconcile_all().map(|_| ()),
                        || uploader.recover_pending_uploads().map(|_| ()),
                    )
                }
            },
            {
                let projector_lane = Arc::clone(&projector_lane);
                let import_lane = Arc::clone(&import_lane);
                let derivation_lane = derivation_lane.clone();
                let upload_lane = Arc::clone(&upload_lane);
                move || {
                    // The projector is released first so every producer can
                    // publish a durable completion without waiting for a
                    // later startup phase to create its consumer.
                    projector_lane.start();
                    import_lane.start();
                    if let Some(derivation_lane) = &derivation_lane {
                        derivation_lane.start();
                    }
                    upload_lane.start();
                    Ok(())
                }
            },
            {
                let import_lane = Arc::clone(&import_lane);
                let upload_lane = Arc::clone(&upload_lane);
                let projector_lane = Arc::clone(&projector_lane);
                let derivation_lane = derivation_lane.clone();
                let derivation_shutdown = derivation_shutdown.clone();
                move || {
                    // Stop the producer first: a projector that stops while the
                    // import lane is still committing would leave the outbox
                    // pending with no consumer for the rest of the session.
                    let import_stopped = import_lane.stop(DEFAULT_STOP_TIMEOUT);
                    // The derivation lane owns FFmpeg child processes, so its
                    // executor is asked to stop before the lane is joined:
                    // a thread blocked in a six-hour encode would otherwise
                    // hold the deadline open for nothing.
                    let derivation_stopped = match (&derivation_shutdown, &derivation_lane) {
                        (Some(port), Some(lane)) => {
                            let executor_stopped = port.shutdown();
                            executor_stopped.and(lane.stop(DEFAULT_STOP_TIMEOUT))
                        }
                        _ => Ok(()),
                    };
                    let upload_stopped = upload_lane.stop(DEFAULT_STOP_TIMEOUT);
                    let projector_stopped = projector_lane.stop(DEFAULT_STOP_TIMEOUT);
                    import_stopped
                        .and(derivation_stopped)
                        .and(upload_stopped)
                        .and(projector_stopped)
                }
            },
        ));
    let normalizer_recovery: Option<Arc<dyn UbuntuNormalizerRecovery>> =
        derivation_shutdown.as_ref().map(|port| {
            let recover = Arc::clone(port);
            let shutdown = Arc::clone(port);
            let runtime = Arc::clone(&runtime);
            let pipeline = Arc::clone(&pipeline);
            Arc::new(UbuntuNormalizerRecoveryAdapter::with_shutdown(
                move || {
                    recover.recover_pending_derivations()?;
                    Ok(pipeline
                        .durable_projections(runtime.scan_snapshot())?
                        .derivations)
                },
                move || shutdown.shutdown(),
            )) as Arc<dyn UbuntuNormalizerRecovery>
        });
    let projections: Arc<dyn UbuntuProjectionSupplier> = Arc::new({
        let runtime = Arc::clone(&runtime);
        let pipeline = Arc::clone(&pipeline);
        let projector = Arc::clone(&projector);
        move || {
            let mut projections = pipeline.durable_projections(runtime.scan_snapshot())?;
            let (source_version, library) = projector.projection_snapshot()?;
            projections.library =
                media::ubuntu_projection::map_media_library_collection(source_version, &library)?;
            Ok(projections)
        }
    });

    let scanner = runtime.scanner_port();
    let ingestor_port: Arc<dyn RecordingIngestorPort> = ingestor;
    let pipeline_port = pipeline.as_port();

    let lifecycle = ubuntu_media_lifecycle(runtime, imports, normalizer_recovery, projections);

    Ok(MediaApplicationPorts::new(
        scanner,
        ingestor_port,
        normalizer,
        pipeline_port,
        trust_port,
        lifecycle,
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod recovery_order_tests {
    use std::{cell::RefCell, rc::Rc};

    use super::recover_ubuntu_media_graph;

    const RECOVERY_STAGES: [&str; 5] =
        ["projector", "imports", "derivations", "pipeline", "uploads"];

    #[test]
    fn ubuntu_media_graph_recovery_runs_in_dependency_order() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let projector_calls = Rc::clone(&calls);
        let import_calls = Rc::clone(&calls);
        let derivation_calls = Rc::clone(&calls);
        let pipeline_calls = Rc::clone(&calls);
        let upload_calls = Rc::clone(&calls);

        let imports = recover_ubuntu_media_graph(
            move || {
                projector_calls.borrow_mut().push("projector");
                Ok::<_, &'static str>(())
            },
            move || {
                import_calls.borrow_mut().push("imports");
                Ok::<_, &'static str>("recovered imports")
            },
            move || {
                derivation_calls.borrow_mut().push("derivations");
                Ok::<_, &'static str>(())
            },
            move || {
                pipeline_calls.borrow_mut().push("pipeline");
                Ok::<_, &'static str>(())
            },
            move || {
                upload_calls.borrow_mut().push("uploads");
                Ok::<_, &'static str>(())
            },
        );

        assert_eq!(imports, Ok("recovered imports"));
        assert_eq!(*calls.borrow(), RECOVERY_STAGES);
    }

    #[test]
    fn ubuntu_media_graph_recovery_failure_stops_later_stages_and_activation() {
        for failed_stage in 0..RECOVERY_STAGES.len() {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let projector_calls = Rc::clone(&calls);
            let import_calls = Rc::clone(&calls);
            let derivation_calls = Rc::clone(&calls);
            let pipeline_calls = Rc::clone(&calls);
            let upload_calls = Rc::clone(&calls);

            let recovered = recover_ubuntu_media_graph(
                move || {
                    projector_calls.borrow_mut().push("projector");
                    (failed_stage != 0).then_some(()).ok_or("recovery failed")
                },
                move || {
                    import_calls.borrow_mut().push("imports");
                    (failed_stage != 1)
                        .then_some("recovered imports")
                        .ok_or("recovery failed")
                },
                move || {
                    derivation_calls.borrow_mut().push("derivations");
                    (failed_stage != 2).then_some(()).ok_or("recovery failed")
                },
                move || {
                    pipeline_calls.borrow_mut().push("pipeline");
                    (failed_stage != 3).then_some(()).ok_or("recovery failed")
                },
                move || {
                    upload_calls.borrow_mut().push("uploads");
                    (failed_stage != 4).then_some(()).ok_or("recovery failed")
                },
            );

            if recovered.is_ok() {
                calls.borrow_mut().push("activation");
            }

            assert_eq!(recovered, Err("recovery failed"));
            assert_eq!(
                calls.borrow().as_slice(),
                &RECOVERY_STAGES[..=failed_stage],
                "failure at {} did not short-circuit",
                RECOVERY_STAGES[failed_stage]
            );
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // NEW-13 cleanup (PC-08): `tauri-plugin-opener` was registered but
        // never called from any command or from the frontend -- removed
        // along with its dependency in Cargo.toml and its
        // `opener:default` capability permission.
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        // Startup runs in four ordered stages, and the order is the point:
        //   1. load and migrate the persisted configuration (once),
        //   2. build the runtime, inert -- no threads, no timers,
        //   3. fail downloads interrupted by a previous process, publish the
        //      initial state, and register the runtime as managed state,
        //   4. only now start the background loops.
        // Stage 4 used to happen inside stage 2, so a loop could tick
        // before `app.manage` and observe or emit against application
        // state that did not exist yet.
        .setup(|app| {
            let app_data_dir = app.path().app_data_dir()?;
            let store_path = app_data_dir.join("app-state.sqlite3");
            let handle = app.handle().clone();

            // Stage 1.
            let boot = BootConfig::load(store_path)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            // Stage 2. The library root comes from the configuration just
            // loaded; the running composition may switch it later when no
            // local entries or pending downloads would be split. A missing
            // or relative setting falls back to app data, and so does a
            // configured root that can't be used (renamed, unplugged drive,
            // read-only) -- a bad setting must not brick the launch, since
            // fixing it means getting into the app.
            let default_root = app_data_dir.join("library");
            let library_root = match boot.download_root() {
                Some(configured) => composition::prepare_library_root(configured.clone())
                    .unwrap_or_else(|e| {
                        eprintln!(
                            "[startup] configured download directory {configured:?} is unusable \
                             ({e}); falling back to {default_root:?}"
                        );
                        default_root.clone()
                    }),
                None => default_root.clone(),
            };
            let composition = composition::Composition::new(app_data_dir.clone(), library_root)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

            // Stage 3.
            let state = AppState::from_boot_config(boot, composition.clone())
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            let application = TransferApplication::new_with_app_data_dir(
                state.0.clone(),
                composition.clone(),
                app_data_dir.clone(),
            )
            .map_err(std::io::Error::other)?;
            // Share the one open AppStore connection with the media
            // composition before the state is handed to Tauri, so nothing
            // opens a second writer behind its revision CAS.
            #[cfg(target_os = "linux")]
            let app_store = state.0.lock().unwrap().app_store_handle();
            app.manage(state);
            app.manage(application.clone());

            let media_initial = MediaProjectionSet::empty();
            let projection_bridge = MediaProjectionBridge::new();
            #[cfg(target_os = "linux")]
            let media_ports = match ubuntu_media_application_ports(
                &composition,
                app_store,
                Arc::clone(&projection_bridge),
            ) {
                Ok(ports) => ports,
                Err(error) => {
                    // Only the bounded stable code reaches stderr. Backend
                    // diagnostics can contain device paths or native text and
                    // must not make startup logs an unbounded data channel.
                    let code = error.into_rpc().code;
                    eprintln!(
                        "[startup] Ubuntu media initialization failed ({code}); \
                         continuing with fail-closed media ports"
                    );
                    fail_closed_media_ports(media_initial.clone())
                }
            };
            #[cfg(not(target_os = "linux"))]
            let media_ports = fail_closed_media_ports(media_initial.clone());
            let media_application = MediaApplication::new(media_initial, media_ports);
            projection_bridge.attach(&media_application);
            app.manage(media_application.clone());

            // Stage 4: the application facade binds the event sink and starts
            // background loops only after both managed states are available.
            // No previous-process transfer is replayed here.
            application.start(handle.clone());
            media_application.start(handle);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::read_snapshot,
            commands::list_devices,
            commands::connect_device,
            commands::cancel_pairing,
            commands::add_manual_device,
            commands::disconnect_device,
            commands::list_sessions,
            commands::get_session_detail,
            commands::delete_sessions,
            commands::cleanup_backed_up,
            commands::preview_downloaded_cleanup,
            commands::cleanup_downloaded,
            commands::list_library,
            commands::remove_library_entries,
            commands::list_transfers,
            commands::download_session,
            commands::download_sessions,
            commands::upload_entry,
            commands::upload_entries,
            commands::retry_transfer,
            commands::pause_transfer_job,
            commands::resume_transfer_job,
            commands::cancel_transfer_job,
            commands::dismiss_transfer_job,
            commands::dismiss_upload_transfer,
            commands::cancel_upload,
            commands::reveal_library_file,
            commands::get_storage_config,
            commands::select_download_root,
            commands::save_download_root,
            commands::save_storage_config,
            commands::test_storage_connection,
            commands::set_notifications_enabled,
            media::commands::media_read_snapshot,
            media::commands::media_read_scan_candidates,
            media::commands::media_read_import_jobs,
            media::commands::media_read_derivation_jobs,
            media::commands::media_read_pipeline_sessions,
            media::commands::media_read_library_projections,
            media::commands::media_revoke_trusted_producer,
            media::commands::media_scan,
            media::commands::media_start_import,
            media::commands::media_start_import_batch,
            media::commands::media_start_derivation,
            media::commands::media_start_pipeline,
            media::commands::media_start_pipeline_batch,
            media::commands::media_export_library_entry,
            media::commands::media_command_import,
            media::commands::media_command_derivation,
            media::commands::media_command_pipeline,
            media::commands::media_release_handles,
            media::commands::media_eject,
        ])
        .build(tauri::generate_context!())
        .expect("error while running tauri application")
        // The loop handles kept by stage 4 exist so shutdown can actually
        // stop them: a detached task keeps ticking against state that is
        // being torn down until the process itself dies.
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                if let Some(state) = app.try_state::<AppState>() {
                    if let Some(media_application) = app.try_state::<MediaApplication>() {
                        if let Err(error) = media_application.stop() {
                            eprintln!("[shutdown] media application stop failed: {error}");
                        }
                    }
                    if let Some(application) = app.try_state::<TransferApplication>() {
                        application.stop();
                    } else {
                        let composition = state.0.lock().unwrap().composition.clone();
                        composition.shutdown_background_loops();
                    }
                }
            }
        });
}
