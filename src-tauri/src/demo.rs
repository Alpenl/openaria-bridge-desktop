//! Fixed seed data for explicit `--features demo` builds.
//!
//! Production builds do not compile this module. Real discovery, pairing,
//! session inventory, file bytes, and S3 operations live in `composition.rs`.
//! These values exist only for UI development when no physical device is
//! available and must never be used as acceptance evidence.

use std::collections::HashMap;

use crate::models::{Device, DeviceState, Session, SessionFile};

pub fn seed_devices() -> (Vec<Device>, HashMap<String, Vec<Session>>) {
    let device_a_id = demo_device_id("30d5872d");
    let device_b_id = demo_device_id("a11c90f2");
    let device_c_id = demo_device_id("77e45b01");
    let devices = vec![
        Device {
            id: device_a_id.clone(),
            display_id: "YLX-30D5872D".into(),
            ip: Some("192.168.1.42".into()),
            state: DeviceState::Connected,
            last_seen: None,
        },
        Device {
            id: device_b_id.clone(),
            display_id: "YLX-A11C90F2".into(),
            ip: Some("192.168.1.57".into()),
            state: DeviceState::Connected,
            last_seen: None,
        },
        Device {
            id: device_c_id,
            display_id: "YLX-77E45B01".into(),
            ip: None,
            state: DeviceState::Offline,
            last_seen: Some("3 天前".into()),
        },
    ];

    let mut sessions = HashMap::new();
    sessions.insert(
        device_a_id,
        vec![
            session(
                "20260731-142233",
                "2026-07-31T14:22:33Z",
                121.4,
                483_920_112,
                14_520,
                &[
                    ("video/segment_000.mp4", 241_938_221),
                    ("video/segment_001.mp4", 241_981_891),
                    ("preview/imu.jsonl", 1_758_433),
                    ("events.jsonl", 4_021),
                    ("session.json", 812),
                ],
            ),
            session(
                "20260731-091045",
                "2026-07-31T09:10:45Z",
                62.8,
                198_220_144,
                7_534,
                &[
                    ("video/segment_000.mp4", 198_220_144),
                    ("preview/imu.jsonl", 903_211),
                    ("events.jsonl", 2_118),
                    ("session.json", 796),
                ],
            ),
            session(
                "20260730-173318",
                "2026-07-30T17:33:18Z",
                305.1,
                1_042_399_201,
                36_611,
                &[
                    ("video/segment_000.mp4", 347_433_021),
                    ("video/segment_001.mp4", 347_511_982),
                    ("video/segment_002.mp4", 347_454_198),
                    ("preview/imu.jsonl", 4_408_820),
                    ("events.jsonl", 6_602),
                    ("session.json", 824),
                ],
            ),
            session(
                "20260729-201107",
                "2026-07-29T20:11:07Z",
                44.0,
                139_920_442,
                5_280,
                &[
                    ("video/segment_000.mp4", 139_920_442),
                    ("preview/imu.jsonl", 637_120),
                    ("events.jsonl", 1_884),
                    ("session.json", 781),
                ],
            ),
        ],
    );
    sessions.insert(
        device_b_id,
        vec![session(
            "20260728-113302",
            "2026-07-28T11:33:02Z",
            88.6,
            279_310_221,
            10_632,
            &[
                ("video/segment_000.mp4", 279_310_221),
                ("preview/imu.jsonl", 1_273_044),
                ("events.jsonl", 2_740),
                ("session.json", 803),
            ],
        )],
    );

    (devices, sessions)
}

fn demo_device_id(display_hex: &str) -> String {
    format!("ylx-{}", display_hex.to_ascii_lowercase().repeat(8))
}

fn session(
    id: &str,
    date_label: &str,
    duration_seconds: f64,
    video_bytes: u64,
    imu_samples: u64,
    files: &[(&str, u64)],
) -> Session {
    Session {
        id: id.to_string(),
        revision: "demo-1".to_string(),
        date_label: date_label.to_string(),
        duration_seconds,
        total_bytes: files.iter().map(|(_, bytes)| *bytes).sum(),
        video_bytes,
        imu_samples: Some(imu_samples),
        files: files
            .iter()
            .map(|(path, bytes)| {
                SessionFile::new(path.to_string(), path.to_string(), *bytes, String::new())
            })
            .collect(),
    }
}
