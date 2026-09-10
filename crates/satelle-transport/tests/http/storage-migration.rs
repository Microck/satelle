use super::*;
use satelle_host::SetupRunStatus;
use satelle_transport::StorageMigrationPathsRequest;

#[tokio::test]
async fn storage_migration_completion_checks_admin_paths_and_durable_staging_before_release() {
    let state = TestStateDir::new().expect("create isolated migration state");
    let root = std::fs::canonicalize(state.path()).expect("resolve migration fixture root");
    let mut config = SatelleConfig::defaults()
        .hosts
        .remove(satelle_core::LOCAL_DEMO_HOST)
        .unwrap();
    config.daemon_state_dir = Some(root.join("source"));
    config.daemon_log_dir = Some(root.join("source-logs"));
    config.daemon_config_file = Some(root.join("config.toml"));
    config.daemon_cache_dir = Some(root.join("cache"));
    let source_service = HostService::production_for_host(&config);
    let source_paths = source_service.daemon_resolved_paths().unwrap();
    let source_identity = source_service
        .initialize_daemon()
        .unwrap()
        .host_identity()
        .to_string();
    let operation_id = "http-storage-migration";
    let copied_log = std::path::Path::new(&source_paths.operator_log_root).join("copied.log");
    satelle_core::open_or_create_owner_only_directory(copied_log.parent().unwrap()).unwrap();
    satelle_core::persist_new_owner_only_config_file(&copied_log, b"original log\n").unwrap();
    let retained_controller =
        std::path::Path::new(&source_paths.state_root).join("controller-only.json");
    satelle_core::persist_new_owner_only_config_file(&retained_controller, b"controller state\n")
        .unwrap();
    let source_server = RunningServer::start_with_service(
        ApiScopes::ADMIN,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        TestStateDir::new().unwrap(),
        source_service,
    )
    .await;
    let begin_endpoint = format!("/v1/maintenance/storage-migration/{operation_id}/begin");
    let begin_key = format!("{operation_id}:begin");
    for _ in 0..2 {
        let begin = source_server
            .mutation(&begin_endpoint, &begin_key)
            .json(&StorageMigrationPathsRequest::new(source_paths.clone()))
            .send()
            .await
            .unwrap();
        assert_eq!(begin.status(), StatusCode::OK);
    }
    let mut changed_paths = source_paths.clone();
    changed_paths.operator_log_root.push_str("-changed");
    let conflict = source_server
        .mutation(&begin_endpoint, &begin_key)
        .json(&StorageMigrationPathsRequest::new(changed_paths))
        .send()
        .await
        .unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        conflict.json::<Value>().await.unwrap()["code"],
        "idempotency-key-conflict"
    );

    let second_admin = ApiBearerToken::generate().unwrap();
    source_server
        .service
        .register_api_token(
            &second_admin,
            "migration-other-admin",
            ApiScopes::ADMIN,
            None,
        )
        .unwrap();
    let independent = reqwest::Client::new()
        .post(source_server.url(&begin_endpoint))
        .bearer_auth(second_admin.expose().as_str())
        .header(
            "Satelle-Expected-Host-Identity",
            &source_server.host_identity,
        )
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .header("Satelle-Protocol-Version", "15")
        .header("Idempotency-Key", &begin_key)
        .json(&StorageMigrationPathsRequest::new(source_paths.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(independent.status(), StatusCode::OK);
    let competing = SetupRunPlan::new(
        "competing-maintenance",
        SetupOperationKind::Repair,
        None,
        time::OffsetDateTime::now_utc(),
        vec![SetupActionPlan::new("repair-test", "Repair", true).unwrap()],
    )
    .unwrap();
    assert!(source_server.service.begin_setup_run(&competing).is_err());
    source_server.server.shutdown().await.unwrap();
    drop(source_server.service);

    let stage = HostService::stage_storage_migration(
        &source_paths,
        &root.join("destination"),
        operation_id,
    )
    .expect("stage a real SQLite store");
    config.daemon_state_dir = Some(stage.plan.destination.state_root.clone().into());
    config.daemon_log_dir = Some(stage.plan.destination.operator_log_root.clone().into());
    let destination_service = HostService::production_for_host(&config);
    let server = RunningServer::start_with_service(
        ApiScopes::ADMIN,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        state,
        destination_service,
    )
    .await;
    assert_eq!(server.host_identity, source_identity);
    assert_eq!(
        server
            .service
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .status(),
        SetupRunStatus::OutcomeUnknown,
    );

    let endpoint = format!("/v1/maintenance/storage-migration/{operation_id}/complete");
    let complete_key = format!("{operation_id}:complete");
    let request = StorageMigrationPathsRequest::new(stage.plan.destination.clone());
    let read_token = ApiBearerToken::generate().unwrap();
    server
        .service
        .register_api_token(&read_token, "migration-read-only", ApiScopes::READ, None)
        .unwrap();
    let denied = reqwest::Client::new()
        .post(server.url(&endpoint))
        .bearer_auth(read_token.expose().as_str())
        .header("Satelle-Expected-Host-Identity", &server.host_identity)
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .header("Satelle-Protocol-Version", "15")
        .header("Idempotency-Key", "read-only-completion")
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let wrong_paths = StorageMigrationPathsRequest::new(source_paths.clone());
    let mismatch = server
        .mutation(&endpoint, "wrong-path-set")
        .json(&wrong_paths)
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    assert_eq!(
        server
            .service
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .status(),
        SetupRunStatus::OutcomeUnknown,
    );

    for _ in 0..2 {
        let completed = server
            .mutation(&endpoint, &complete_key)
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::OK);
        let body: Value = completed.json().await.unwrap();
        assert_eq!(body["operation_id"], operation_id);
        assert_eq!(body["reconciled"], true);
    }
    assert_eq!(
        server
            .service
            .load_setup_run(operation_id)
            .unwrap()
            .unwrap()
            .status(),
        SetupRunStatus::Completed,
    );
    let journal = ".satelle-offline-storage-maintenance-v1";
    assert!(
        std::path::Path::new(&source_paths.state_root)
            .join(journal)
            .exists()
    );
    assert!(
        !std::path::Path::new(&stage.plan.destination.state_root)
            .join(journal)
            .exists()
    );
    let cleanup_endpoint =
        format!("/v1/maintenance/storage-migration/{operation_id}/source/cleanup");
    let retained_log =
        std::path::Path::new(&source_paths.operator_log_root).join("added-after-migration.log");
    satelle_core::persist_new_owner_only_config_file(&retained_log, b"new local file\n").unwrap();
    std::fs::write(&copied_log, b"operator changed this source\n").unwrap();
    let changed = server
        .mutation(&cleanup_endpoint, "changed-source")
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    assert!(std::path::Path::new(&source_paths.sqlite_store).exists());
    assert_eq!(
        std::fs::read(&copied_log).unwrap(),
        b"operator changed this source\n"
    );
    std::fs::write(&copied_log, b"original log\n").unwrap();
    let preview = server.request(&cleanup_endpoint).send().await.unwrap();
    assert_eq!(preview.status(), StatusCode::OK);
    assert_eq!(preview.headers()["Satelle-Protocol-Version"], "15");
    assert!(std::path::Path::new(&source_paths.sqlite_store).exists());
    let cleaned = server
        .mutation(&cleanup_endpoint, "cleanup-source")
        .send()
        .await
        .unwrap();
    assert_eq!(cleaned.status(), StatusCode::OK);
    let cleaned: Value = cleaned.json().await.unwrap();
    assert!(
        !cleaned["cleanup"]["removed_files"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!std::path::Path::new(&source_paths.sqlite_store).exists());
    assert!(!copied_log.exists());
    assert!(retained_controller.exists());
    assert!(retained_log.exists());
    assert!(std::path::Path::new(&stage.plan.destination.sqlite_store).exists());
    let replay = server
        .mutation(&cleanup_endpoint, "cleanup-source")
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    let replay: Value = replay.json().await.unwrap();
    assert_eq!(replay["cleanup"], cleaned["cleanup"]);
    let RunningServer {
        _state,
        service,
        server,
        ..
    } = server;
    server.shutdown().await.unwrap();
    drop(service);
    let restarted = RunningServer::start_with_service(
        ApiScopes::ADMIN,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        _state,
        HostService::production_for_host(&config),
    )
    .await;
    let replay = restarted
        .mutation(&cleanup_endpoint, "cleanup-source")
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        replay.json::<Value>().await.unwrap()["cleanup"],
        cleaned["cleanup"]
    );
    let complete_replay = restarted
        .mutation(&endpoint, &complete_key)
        .json(&request)
        .send()
        .await
        .unwrap();
    assert_eq!(complete_replay.status(), StatusCode::OK);
    restarted.server.shutdown().await.unwrap();
}
