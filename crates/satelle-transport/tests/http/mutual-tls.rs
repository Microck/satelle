use super::*;
use rcgen::{Certificate, CertificateParams, Issuer, KeyPair};
use satelle_transport::{ClientCertificate, ClientCertificateError, DaemonClientTrust};
use sha2::{Digest, Sha256};

struct ClientAuthority {
    certificate: Certificate,
    issuer: Issuer<'static, KeyPair>,
}

impl ClientAuthority {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        Self {
            certificate,
            issuer: Issuer::new(params, key),
        }
    }

    fn client(&self, serial: u64) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.serial_number = Some(serial.into());
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "PRIVATE_CLIENT_SUBJECT_CANARY");
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        (params.signed_by(&key, &self.issuer).unwrap(), key)
    }

    fn crl(&self, serials: &[u64], expired: bool) -> String {
        let now = time::OffsetDateTime::now_utc();
        rcgen::CertificateRevocationListParams {
            this_update: now - time::Duration::days(2),
            next_update: if expired {
                now - time::Duration::days(1)
            } else {
                now + time::Duration::days(1)
            },
            crl_number: 1_u64.into(),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|serial| rcgen::RevokedCertParams {
                    serial_number: (*serial).into(),
                    revocation_time: now - time::Duration::days(2),
                    reason_code: Some(rcgen::RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&self.issuer)
        .unwrap()
        .pem()
        .unwrap()
    }
}

fn client_pem(client: &(Certificate, KeyPair)) -> String {
    format!("{}{}", client.0.pem(), client.1.serialize_pem())
}

fn https_client(server_pem: &str, client: Option<&(Certificate, KeyPair)>) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .tls_certs_only([reqwest::Certificate::from_pem(server_pem.as_bytes()).unwrap()]);
    let builder = match client {
        Some(client) => {
            builder.identity(reqwest::Identity::from_pem(client_pem(client).as_bytes()).unwrap())
        }
        None => builder,
    };
    builder.build().unwrap()
}

fn direct_binding(server: &DaemonServer, host_identity: &str) -> DirectHostBinding {
    let mut config = SatelleConfig::defaults()
        .hosts
        .remove("local-demo")
        .unwrap();
    config.transport = TransportKind::Direct;
    config.address = Some(format!("https://localhost:{}", server.local_addr().port()));
    config.expected_host_id = Some(host_identity.to_string());
    config.api_token = Some(ApiTokenSource::File {
        path: std::env::temp_dir().join("unused-mtls-token"),
    });
    DirectHostBinding::from_host_config(&config).unwrap()
}

#[tokio::test]
async fn mutual_tls_preserves_bearer_scopes_and_audits_http_and_wss() {
    let authority = ClientAuthority::new("client authority");
    let identity = authority.client(10);
    let untrusted = ClientAuthority::new("untrusted authority").client(11);
    let server_identity = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let server_pem = server_identity.cert.pem();
    let state = TestStateDir::new().unwrap();
    let service = HostService::local_demo_for_tests_at(state.path()).unwrap();
    let host_identity = service
        .initialize_daemon()
        .unwrap()
        .host_identity()
        .to_string();
    let token = ApiBearerToken::generate().unwrap();
    let principal = service
        .register_api_token(&token, "mtls-read-principal", ApiScopes::READ, None)
        .unwrap();
    let authorization = format!("Bearer {}", token.expose().as_str());
    let tls = DaemonTlsConfig::from_pem(
        server_pem.as_bytes(),
        server_identity.signing_key.serialize_pem().as_bytes(),
        Some(DaemonClientTrust {
            ca_pem: authority.certificate.pem().as_bytes(),
            crl_pem: None,
        }),
    )
    .unwrap();
    let server = DaemonServer::bind_tls(
        service.clone(),
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        tls,
    )
    .await
    .unwrap();
    let url = format!("https://localhost:{}", server.local_addr().port());
    for client in [
        https_client(&server_pem, None),
        https_client(&server_pem, Some(&untrusted)),
    ] {
        assert!(
            client.get(format!("{url}/v1/live")).send().await.is_err(),
            "mTLS applies before even the public liveness handler"
        );
    }
    let client = https_client(&server_pem, Some(&identity));
    assert_eq!(
        client
            .get(format!("{url}/v1/host/status"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let request_id = RequestId::new();
    let response = client
        .get(format!("{url}/v1/host/status"))
        .header("Authorization", &authorization)
        .header("Satelle-Expected-Host-Identity", &host_identity)
        .header("Satelle-Request-Id", request_id.as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = client
        .post(format!("{url}/v1/sessions"))
        .header("Authorization", &authorization)
        .header("Satelle-Expected-Host-Identity", &host_identity)
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .header(
            "Satelle-Protocol-Version",
            satelle_core::host_update::HOST_PROTOCOL_VERSION,
        )
        .header("Idempotency-Key", "mtls-read-cannot-run")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(service.initialize_daemon().unwrap().session_count(), 0);

    let binding = direct_binding(&server, &host_identity);
    let event_identity = ClientCertificate::from_pem(
        identity.0.pem().as_bytes(),
        identity.1.serialize_pem().as_bytes(),
    )
    .unwrap();
    let event_client = DaemonEventClient::wss(
        &binding,
        ApiBearerToken::parse(token.expose().as_str()).unwrap(),
        Some(server_pem.as_bytes()),
        Some(&event_identity),
    )
    .unwrap();
    let stream = event_client
        .connect_events(vec![EventSubscription::Host])
        .await
        .unwrap();
    drop(stream);
    let pem = identity.0.pem();
    let key = identity.1.serialize_pem();
    tokio::task::spawn_blocking(move || {
        let identity = ClientCertificate::from_pem(pem.as_bytes(), key.as_bytes()).unwrap();
        DaemonClient::https(
            &binding,
            token,
            Some(server_pem.as_bytes()),
            Some(&identity),
        )
        .unwrap()
        .capabilities()
        .unwrap();
    })
    .await
    .unwrap();
    let audit_database = rusqlite::Connection::open(state.path().join("satelle.sqlite3")).unwrap();
    audit_database.execute_batch("CREATE TRIGGER reject_audit_fixture BEFORE INSERT ON client_certificate_audit BEGIN SELECT RAISE(ABORT, 'audit-write-failure-fixture'); END;").unwrap();
    let refused = client
        .get(format!("{url}/v1/host/status"))
        .header("Authorization", &authorization)
        .header("Satelle-Expected-Host-Identity", &host_identity)
        .header("Satelle-Request-Id", RequestId::new().as_str())
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !refused
            .text()
            .await
            .unwrap()
            .contains("audit-write-failure-fixture")
    );
    audit_database
        .execute_batch("DROP TRIGGER reject_audit_fixture;")
        .unwrap();
    drop(audit_database);
    drop(client);
    drop(event_client);
    server.shutdown().await.unwrap();
    drop(service);

    let database = rusqlite::Connection::open(state.path().join("satelle.sqlite3")).unwrap();
    let records = database.prepare("SELECT request_id, principal_ref, token_id, credential_revision, scopes, certificate_sha256 FROM client_certificate_audit ORDER BY sequence").unwrap()
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, u8>(4)?, row.get::<_, Vec<u8>>(5)?))).unwrap()
        .collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(records.len(), 4);
    assert!(records.iter().any(|record| record.0 == request_id.as_str()));
    let fingerprint = Sha256::digest(identity.0.der());
    for (id, owner, token_id, revision, scopes, fingerprint_bytes) in records {
        RequestId::parse(&id).unwrap();
        assert_eq!(owner, principal.principal_ref());
        assert_eq!(token_id, principal.token_id());
        assert_eq!(revision, 1);
        assert_eq!(scopes, 1);
        assert_eq!(fingerprint_bytes.as_slice(), fingerprint.as_slice());
    }
}

#[tokio::test]
async fn mutual_tls_revocation_reload_closes_existing_connections_and_rejects_old_identity() {
    let authority = ClientAuthority::new("client authority");
    let old_client = authority.client(10);
    let replacement = authority.client(11);
    let server_identity = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let server_pem = server_identity.cert.pem();
    let key_pem = server_identity.signing_key.serialize_pem();
    let ca_pem = authority.certificate.pem();
    let state = TestStateDir::new().unwrap();
    let service = HostService::local_demo_for_tests_at(state.path()).unwrap();
    let host_identity = service
        .initialize_daemon()
        .unwrap()
        .host_identity()
        .to_string();
    let token = ApiBearerToken::generate().unwrap();
    service
        .register_api_token(&token, "mtls-reload-principal", ApiScopes::READ, None)
        .unwrap();
    let tls = DaemonTlsConfig::from_pem(
        server_pem.as_bytes(),
        key_pem.as_bytes(),
        Some(DaemonClientTrust {
            ca_pem: ca_pem.as_bytes(),
            crl_pem: None,
        }),
    )
    .unwrap();
    let server = DaemonServer::bind_tls(
        service,
        DaemonServerConfig::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        tls,
    )
    .await
    .unwrap();
    let binding = direct_binding(&server, &host_identity);
    let old_identity = ClientCertificate::from_pem(
        old_client.0.pem().as_bytes(),
        old_client.1.serialize_pem().as_bytes(),
    )
    .unwrap();
    let events = DaemonEventClient::wss(
        &binding,
        token,
        Some(server_pem.as_bytes()),
        Some(&old_identity),
    )
    .unwrap();
    let mut stream = events
        .connect_events(vec![EventSubscription::Host])
        .await
        .unwrap();
    let old_https = https_client(&server_pem, Some(&old_client));
    let live_url = format!("https://localhost:{}/v1/live", server.local_addr().port());
    assert_eq!(
        old_https.get(&live_url).send().await.unwrap().status(),
        StatusCode::OK
    );
    let expired = authority.crl(&[], true);
    assert_eq!(
        server.reload_tls_from_pem(
            server_pem.as_bytes(),
            key_pem.as_bytes(),
            Some(DaemonClientTrust {
                ca_pem: ca_pem.as_bytes(),
                crl_pem: Some(expired.as_bytes())
            })
        ),
        Err(DaemonTlsReloadError::InvalidConfiguration(
            DaemonTlsConfigError::ClientCrlOutsideValidity
        ))
    );
    // Invalid material retains the old policy and a live upgraded connection.
    assert_eq!(
        old_https.get(&live_url).send().await.unwrap().status(),
        StatusCode::OK
    );
    let revoked = authority.crl(&[10], false);
    server
        .reload_tls_from_pem(
            server_pem.as_bytes(),
            key_pem.as_bytes(),
            Some(DaemonClientTrust {
                ca_pem: ca_pem.as_bytes(),
                crl_pem: Some(revoked.as_bytes()),
            }),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), stream.next_event())
        .await
        .expect("reload closes idle WSS without waiting for its next heartbeat")
        .expect_err("existing mTLS connection must reauthenticate");
    assert!(old_https.get(&live_url).send().await.is_err());
    assert!(
        events
            .connect_events(vec![EventSubscription::Host])
            .await
            .is_err()
    );
    assert_eq!(
        https_client(&server_pem, Some(&replacement))
            .get(&live_url)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    drop(stream);
    server.shutdown().await.unwrap();
}

#[test]
fn mutual_tls_material_validation_rejects_bad_trust_revocation_and_client_keys() {
    let authority = ClientAuthority::new("client authority");
    let unrelated = ClientAuthority::new("unrelated authority");
    let server = rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let server_pem = server.cert.pem();
    let key_pem = server.signing_key.serialize_pem();
    let ca_pem = authority.certificate.pem();
    let unrelated_crl = unrelated.crl(&[], false);
    for (ca, crl, expected) in [
        (b"".as_slice(), None, DaemonTlsConfigError::InvalidClientCa),
        (
            server_pem.as_bytes(),
            None,
            DaemonTlsConfigError::InvalidClientCa,
        ),
        (
            ca_pem.as_bytes(),
            Some(b"".as_slice()),
            DaemonTlsConfigError::InvalidClientCrl,
        ),
        (
            ca_pem.as_bytes(),
            Some(b"malformed CRL".as_slice()),
            DaemonTlsConfigError::InvalidClientCrl,
        ),
        (
            ca_pem.as_bytes(),
            Some(unrelated_crl.as_bytes()),
            DaemonTlsConfigError::InvalidClientCrl,
        ),
    ] {
        assert_eq!(
            DaemonTlsConfig::from_pem(
                server_pem.as_bytes(),
                key_pem.as_bytes(),
                Some(DaemonClientTrust {
                    ca_pem: ca,
                    crl_pem: crl
                })
            )
            .unwrap_err(),
            expected
        );
    }
    let client = authority.client(1);
    assert_eq!(
        ClientCertificate::from_pem(client.0.pem().as_bytes(), key_pem.as_bytes()).unwrap_err(),
        ClientCertificateError::KeyMismatch
    );
    assert_eq!(
        ClientCertificate::from_pem(client.0.pem().as_bytes(), b"bad key").unwrap_err(),
        ClientCertificateError::InvalidPrivateKey
    );
    assert_eq!(
        ClientCertificate::from_pem(b"bad certificate", client.1.serialize_pem().as_bytes())
            .unwrap_err(),
        ClientCertificateError::InvalidCertificate
    );
    assert_eq!(
        ClientCertificate::from_pem(authority.certificate.pem().as_bytes(), key_pem.as_bytes())
            .unwrap_err(),
        ClientCertificateError::InvalidCertificate
    );
    for (before, after, expected) in [
        (
            rcgen::date_time_ymd(2020, 1, 1),
            rcgen::date_time_ymd(2021, 1, 1),
            ClientCertificateError::Expired,
        ),
        (
            rcgen::date_time_ymd(2100, 1, 1),
            rcgen::date_time_ymd(2101, 1, 1),
            ClientCertificateError::NotYetValid,
        ),
    ] {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.not_before = before;
        params.not_after = after;
        let certificate = params.signed_by(&client.1, &authority.issuer).unwrap();
        assert_eq!(
            ClientCertificate::from_pem(
                certificate.pem().as_bytes(),
                client.1.serialize_pem().as_bytes()
            )
            .unwrap_err(),
            expected
        );
    }
}
