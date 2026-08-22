//! Native Linux mounted-volume backend.
//!
//! UDisks2 is preferred because its ObjectManager exposes stable block/drive
//! relationships, every mounted byte-string path, removable hints, and native
//! eject/power-off operations. When the system bus or UDisks2 name is absent,
//! [`LinuxNativeBackend`] falls back to the read-only mountinfo backend. The
//! fallback can discover and reconcile mounts but deliberately reports only
//! `ReleasedForSystemEject` for eject.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::{self, JoinHandle};

use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::fdo::ManagedObjects;
use zbus::message::Type as MessageType;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::MatchRule;

pub use super::linux_fallback::{
    LinuxMountInfoBackend, MountInfoSubscription, UDisks2Api, UDisks2Backend, UDisks2Filesystem,
};
use super::{
    shutdown_subscription_worker, AttachRefusalReason, EjectUnavailableReason, EvidenceHint,
    MountedVolume, PlatformAttachReport, PlatformEjectOutcome, PlatformMountedVolume,
    PlatformVolumeBackend, RemovableMediaError, SubscriptionDrain, VolumeEventSubscription,
    VolumeGeneration, VolumeIdentity, SUBSCRIPTION_SHUTDOWN_TIMEOUT,
};

const UDISKS_DESTINATION: &str = "org.freedesktop.UDisks2";
const UDISKS_ROOT: &str = "/org/freedesktop/UDisks2";
const OBJECT_MANAGER: &str = "org.freedesktop.DBus.ObjectManager";
const BLOCK_INTERFACE: &str = "org.freedesktop.UDisks2.Block";
const FILESYSTEM_INTERFACE: &str = "org.freedesktop.UDisks2.Filesystem";
const DRIVE_INTERFACE: &str = "org.freedesktop.UDisks2.Drive";
const DBUS_DESTINATION: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
const SUPPORTED_LINUX_NATIVE_FILESYSTEMS: &[&str] =
    &["ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs"];

type PropertyMap = HashMap<String, OwnedValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBackendKind {
    UDisks2,
    MountInfoFallback,
}

/// Production Linux backend with an explicit UDisks2-to-mountinfo fallback.
pub enum LinuxNativeBackend {
    UDisks2(NativeUDisks2Backend),
    MountInfo(LinuxMountInfoBackend),
}

impl Default for LinuxNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxNativeBackend {
    /// Prefer UDisks2 when the service currently owns its system-bus name.
    /// Merely connecting to D-Bus is not treated as proof the service exists.
    #[must_use]
    pub fn new() -> Self {
        match NativeUDisks2Backend::connect() {
            Ok(backend) => Self::UDisks2(backend),
            Err(_) => Self::MountInfo(LinuxMountInfoBackend::new()),
        }
    }

    pub fn require_udisks2() -> Result<Self, RemovableMediaError> {
        NativeUDisks2Backend::connect().map(Self::UDisks2)
    }

    #[must_use]
    pub const fn kind(&self) -> LinuxBackendKind {
        match self {
            Self::UDisks2(_) => LinuxBackendKind::UDisks2,
            Self::MountInfo(_) => LinuxBackendKind::MountInfoFallback,
        }
    }
}

pub enum LinuxNativeSubscription {
    UDisks2(UDisks2Subscription),
    MountInfo(MountInfoSubscription),
}

impl VolumeEventSubscription for LinuxNativeSubscription {
    fn drain(&mut self) -> Result<SubscriptionDrain, RemovableMediaError> {
        match self {
            Self::UDisks2(subscription) => subscription.drain(),
            Self::MountInfo(subscription) => subscription.drain(),
        }
    }

    fn release_volume(&mut self, generation: &VolumeGeneration) -> Result<(), RemovableMediaError> {
        match self {
            Self::UDisks2(subscription) => subscription.release_volume(generation),
            Self::MountInfo(subscription) => subscription.release_volume(generation),
        }
    }

    fn shutdown(&mut self) -> Result<(), RemovableMediaError> {
        match self {
            Self::UDisks2(subscription) => subscription.shutdown(),
            Self::MountInfo(subscription) => subscription.shutdown(),
        }
    }
}

impl PlatformVolumeBackend for LinuxNativeBackend {
    type Subscription = LinuxNativeSubscription;

    fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
        if let Self::UDisks2(backend) = self {
            if let Ok(subscription) = backend.subscribe() {
                return Ok(LinuxNativeSubscription::UDisks2(subscription));
            }
            // UDisks2 may disappear between construction and subscription.
            // Switching here is still subscribe-before-enumerate.
            *self = Self::MountInfo(LinuxMountInfoBackend::new());
        }
        match self {
            Self::MountInfo(backend) => backend.subscribe().map(LinuxNativeSubscription::MountInfo),
            Self::UDisks2(_) => unreachable!("UDisks2 branch returned or switched to fallback"),
        }
    }

    fn enumerate_mounted_readable(
        &mut self,
    ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
        match self {
            Self::UDisks2(backend) => backend.enumerate_mounted_readable(),
            Self::MountInfo(backend) => backend.enumerate_mounted_readable(),
        }
    }

    fn attach_removable_filesystems(
        &mut self,
    ) -> Result<PlatformAttachReport, RemovableMediaError> {
        match self {
            Self::UDisks2(backend) => backend.attach_removable_filesystems(),
            // The mountinfo fallback reads the mount table and owns no mount
            // authority, so it reports honestly that it attached nothing.
            Self::MountInfo(_) => Ok(PlatformAttachReport::unsupported()),
        }
    }

    fn release_volume_handles(
        &mut self,
        generation: &VolumeGeneration,
    ) -> Result<(), RemovableMediaError> {
        match self {
            Self::UDisks2(backend) => backend.release_volume_handles(generation),
            Self::MountInfo(backend) => backend.release_volume_handles(generation),
        }
    }

    fn request_eject(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
        match self {
            Self::UDisks2(backend) => backend.request_eject(volume),
            Self::MountInfo(backend) => backend.request_eject(volume),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UDisksTarget {
    block_path: OwnedObjectPath,
    drive_path: Option<OwnedObjectPath>,
    ejectable: bool,
    can_power_off: bool,
}

/// Concrete UDisks2 backend using zbus' blocking API. Calls occur only from
/// adapter methods; the signal callback thread merely coalesces invalidations.
pub struct NativeUDisks2Backend {
    connection: Connection,
    eject_targets: BTreeMap<VolumeIdentity, UDisksTarget>,
}

impl NativeUDisks2Backend {
    pub fn connect() -> Result<Self, RemovableMediaError> {
        let connection = Connection::system().map_err(subscription_error)?;
        let dbus = Proxy::new(&connection, DBUS_DESTINATION, DBUS_PATH, DBUS_INTERFACE)
            .map_err(subscription_error)?;
        let owned: bool = dbus
            .call("NameHasOwner", &(UDISKS_DESTINATION,))
            .map_err(subscription_error)?;
        if !owned {
            return Err(RemovableMediaError::Subscription(
                "UDisks2 is not available on the system bus".to_string(),
            ));
        }
        Ok(Self {
            connection,
            eject_targets: BTreeMap::new(),
        })
    }

    fn managed_objects(&self) -> Result<ManagedObjects, RemovableMediaError> {
        let manager = Proxy::new(
            &self.connection,
            UDISKS_DESTINATION,
            UDISKS_ROOT,
            OBJECT_MANAGER,
        )
        .map_err(enumeration_error)?;
        manager
            .call("GetManagedObjects", &())
            .map_err(enumeration_error)
    }

    fn enumerate_udisks(&mut self) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
        let objects = self.managed_objects()?;
        let mount_modes = read_mount_modes();
        let mut observations = Vec::new();
        let mut eject_targets = BTreeMap::new();

        for (object_path, interfaces) in &objects {
            let Some(filesystem) = interface(interfaces, FILESYSTEM_INTERFACE) else {
                continue;
            };
            let Some(block) = interface(interfaces, BLOCK_INTERFACE) else {
                continue;
            };
            let drive_path = property_object_path(block, "Drive")?;
            let drive_properties = drive_path
                .as_ref()
                .and_then(|path| objects.get(path))
                .and_then(|interfaces| interface(interfaces, DRIVE_INTERFACE));
            if !udisks_volume_is_eligible(block, drive_properties) {
                continue;
            }

            let mount_point_bytes =
                property_byte_arrays(filesystem, "MountPoints")?.unwrap_or_default();
            if mount_point_bytes.is_empty() {
                continue;
            }
            let mount_paths = decode_mount_points(&mount_point_bytes)?;
            if mount_paths.is_empty() {
                continue;
            }

            let size = property_u64(block, "Size");
            let uuid = property_string(block, "IdUUID").unwrap_or_default();
            let device = property_bytes(block, "Device")?.unwrap_or_default();
            let identity_material = if uuid.is_empty() {
                let mut material = object_path.as_str().as_bytes().to_vec();
                material.push(0);
                material.extend_from_slice(&device);
                material
            } else {
                format!("filesystem-uuid={uuid}\nsize={}", size.unwrap_or_default()).into_bytes()
            };
            let identity = VolumeIdentity::from_native("linux-udisks2", &identity_material)?;

            let removable = removable_hint(drive_properties);
            let block_read_only = property_bool(block, "ReadOnly");
            let read_only = if block_read_only == Some(true) {
                EvidenceHint::Yes
            } else {
                read_only_hint(&mount_paths, &mount_modes)
            };
            let filesystem_name = property_string(block, "IdType");
            let presence_marker = format!("udisks2:{}", object_path.as_str());

            let mut observation = PlatformMountedVolume::new(identity.clone(), mount_paths)
                .with_read_only(read_only)
                .with_removable(removable)
                .with_capacity_bytes(size)
                .with_presence_marker(presence_marker);
            if let Some(filesystem_name) = filesystem_name {
                observation = observation.with_filesystem(filesystem_name);
            }

            let target = UDisksTarget {
                block_path: object_path.clone(),
                drive_path: drive_path.clone(),
                ejectable: drive_properties
                    .and_then(|drive| property_bool(drive, "Ejectable"))
                    .unwrap_or(false),
                can_power_off: drive_properties
                    .and_then(|drive| property_bool(drive, "CanPowerOff"))
                    .unwrap_or(false),
            };
            if let Some(previous) = eject_targets.insert(identity.clone(), target.clone()) {
                if previous != target {
                    return Err(RemovableMediaError::InvalidObservation(
                        "UDisks2 reported one opaque volume identity for multiple devices"
                            .to_string(),
                    ));
                }
            }
            observations.push(observation);
        }

        self.eject_targets = eject_targets;
        Ok(observations)
    }

    /// Ask UDisks2 to mount every removable filesystem it reports as present
    /// and unmounted. The eligibility test is deliberately the same one
    /// enumeration uses, so this can never offer to mount something that would
    /// then be filtered out of the catalog anyway.
    ///
    /// Authorization stays with polkit under the calling user's own session:
    /// `org.freedesktop.udisks2.filesystem-mount` normally passes without a
    /// prompt for a local active session and normally fails for a remote one.
    /// Either verdict is reported as-is.
    fn attach_udisks(&mut self) -> Result<PlatformAttachReport, RemovableMediaError> {
        let objects = self.managed_objects()?;
        let mut report = PlatformAttachReport::default();

        for (object_path, interfaces) in &objects {
            let Some(filesystem) = interface(interfaces, FILESYSTEM_INTERFACE) else {
                continue;
            };
            let Some(block) = interface(interfaces, BLOCK_INTERFACE) else {
                continue;
            };
            let drive_properties = property_object_path(block, "Drive")?
                .as_ref()
                .and_then(|path| objects.get(path))
                .and_then(|interfaces| interface(interfaces, DRIVE_INTERFACE));
            if !udisks_volume_is_eligible(block, drive_properties) {
                continue;
            }

            // Only what the OS has not already mounted is offered; a volume
            // with any mount point is enumeration's business, not ours.
            if !property_byte_arrays(filesystem, "MountPoints")?
                .unwrap_or_default()
                .is_empty()
            {
                continue;
            }

            report.eligible = report.eligible.saturating_add(1);
            match call_udisks_mount(&self.connection, object_path.as_str()) {
                Ok(_) => report.mounted = report.mounted.saturating_add(1),
                Err(error) => report.refusals.push(classify_attach_failure(&error)),
            }
        }

        Ok(report)
    }
}

impl PlatformVolumeBackend for NativeUDisks2Backend {
    type Subscription = UDisks2Subscription;

    fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
        // A separate connection lets Drop close the blocking signal iterator
        // without disrupting enumeration/eject calls on the main connection.
        let event_connection = Connection::system().map_err(subscription_error)?;
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(UDISKS_DESTINATION)
            .map_err(subscription_error)?
            .path_namespace(UDISKS_ROOT)
            .map_err(subscription_error)?
            .build();
        let iterator = MessageIterator::for_match_rule(rule, &event_connection, Some(32))
            .map_err(subscription_error)?;
        let close_connection = event_connection.clone();
        let (notify_tx, notify_rx) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("ylx-udisks2-watch".to_string())
            .spawn(move || {
                for message in iterator {
                    match message {
                        Ok(_) => {
                            // Coalesce bursts. Enumeration, parsing, and I/O
                            // are intentionally absent from this callback.
                            let _ = notify_tx.try_send(());
                        }
                        Err(_) => return,
                    }
                }
            })
            .map_err(subscription_error)?;
        Ok(UDisks2Subscription {
            invalidations: notify_rx,
            close_connection: Some(close_connection),
            worker: Some(worker),
        })
    }

    fn enumerate_mounted_readable(
        &mut self,
    ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
        self.enumerate_udisks()
    }

    fn attach_removable_filesystems(
        &mut self,
    ) -> Result<PlatformAttachReport, RemovableMediaError> {
        self.attach_udisks()
    }

    fn request_eject(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
        let Some(target) = self
            .eject_targets
            .get(volume.generation.identity())
            .cloned()
        else {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Other(
                    "UDisks2 no longer has an eject target for this volume".to_string(),
                ),
            });
        };

        if let Err(error) = call_udisks_method(
            &self.connection,
            target.block_path.as_str(),
            FILESYSTEM_INTERFACE,
            "Unmount",
        ) {
            return Ok(classify_unmount_failure(error));
        }

        let Some(drive_path) = target.drive_path else {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            });
        };
        let method = if target.ejectable {
            Some("Eject")
        } else if target.can_power_off {
            Some("PowerOff")
        } else {
            None
        };
        let Some(method) = method else {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            });
        };
        match call_udisks_method(
            &self.connection,
            drive_path.as_str(),
            DRIVE_INTERFACE,
            method,
        ) {
            Ok(()) => Ok(PlatformEjectOutcome::Ejected),
            Err(error) => Ok(classify_post_unmount_eject_failure(error)),
        }
    }
}

pub struct UDisks2Subscription {
    invalidations: Receiver<()>,
    close_connection: Option<Connection>,
    worker: Option<JoinHandle<()>>,
}

impl VolumeEventSubscription for UDisks2Subscription {
    fn drain(&mut self) -> Result<SubscriptionDrain, RemovableMediaError> {
        let mut invalidations = 0usize;
        loop {
            match self.invalidations.try_recv() {
                Ok(()) => invalidations = invalidations.saturating_add(1),
                Err(TryRecvError::Empty) => {
                    return Ok(SubscriptionDrain {
                        invalidations,
                        disconnected: false,
                    });
                }
                Err(TryRecvError::Disconnected) => {
                    return Ok(SubscriptionDrain {
                        invalidations,
                        disconnected: true,
                    });
                }
            }
        }
    }

    fn shutdown(&mut self) -> Result<(), RemovableMediaError> {
        let mut first_error = None;
        if let Some(connection) = self.close_connection.take() {
            if let Err(error) = connection.close() {
                first_error = Some(subscription_error(error));
            }
        }
        if let Err(error) = shutdown_subscription_worker(
            &mut self.worker,
            SUBSCRIPTION_SHUTDOWN_TIMEOUT,
            "UDisks2 event worker",
        ) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for UDisks2Subscription {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn interface<'a>(
    interfaces: &'a HashMap<zbus::names::OwnedInterfaceName, PropertyMap>,
    name: &str,
) -> Option<&'a PropertyMap> {
    interfaces
        .iter()
        .find(|(interface_name, _)| interface_name.as_str() == name)
        .map(|(_, properties)| properties)
}

fn cloned_property(properties: &PropertyMap, name: &str) -> Option<OwnedValue> {
    properties.get(name)?.try_clone().ok()
}

fn property_bool(properties: &PropertyMap, name: &str) -> Option<bool> {
    bool::try_from(cloned_property(properties, name)?).ok()
}

fn property_u64(properties: &PropertyMap, name: &str) -> Option<u64> {
    u64::try_from(cloned_property(properties, name)?).ok()
}

fn property_string(properties: &PropertyMap, name: &str) -> Option<String> {
    String::try_from(cloned_property(properties, name)?).ok()
}

fn property_object_path(
    properties: &PropertyMap,
    name: &str,
) -> Result<Option<OwnedObjectPath>, RemovableMediaError> {
    let Some(value) = cloned_property(properties, name) else {
        return Ok(None);
    };
    OwnedObjectPath::try_from(value)
        .map(Some)
        .map_err(|_| invalid_udisks_property(name))
}

fn property_bytes(
    properties: &PropertyMap,
    name: &str,
) -> Result<Option<Vec<u8>>, RemovableMediaError> {
    let Some(value) = cloned_property(properties, name) else {
        return Ok(None);
    };
    Vec::<u8>::try_from(value)
        .map(Some)
        .map_err(|_| invalid_udisks_property(name))
}

fn property_byte_arrays(
    properties: &PropertyMap,
    name: &str,
) -> Result<Option<Vec<Vec<u8>>>, RemovableMediaError> {
    let Some(value) = cloned_property(properties, name) else {
        return Ok(None);
    };
    Vec::<Vec<u8>>::try_from(value)
        .map(Some)
        .map_err(|_| invalid_udisks_property(name))
}

fn invalid_udisks_property(name: &str) -> RemovableMediaError {
    RemovableMediaError::InvalidObservation(format!(
        "UDisks2 property {name} had an unexpected type"
    ))
}

fn decode_mount_points(values: &[Vec<u8>]) -> Result<Vec<PathBuf>, RemovableMediaError> {
    values
        .iter()
        .map(|value| {
            let mut value = value.clone();
            if value.last() == Some(&0) {
                value.pop();
            }
            if value.is_empty() || value.contains(&0) {
                return Err(RemovableMediaError::InvalidObservation(
                    "UDisks2 mount point was empty or contained NUL".to_string(),
                ));
            }
            Ok(PathBuf::from(OsString::from_vec(value)))
        })
        .collect()
}

fn read_mount_modes() -> BTreeMap<PathBuf, bool> {
    let Ok(value) = fs::read_to_string("/proc/self/mountinfo") else {
        return BTreeMap::new();
    };
    value
        .lines()
        .filter_map(|line| {
            let left = line.split_once(" - ")?.0;
            let fields: Vec<&str> = left.split_ascii_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let path = decode_mountinfo_path(fields[4])?;
            let read_only = fields[5].split(',').any(|option| option == "ro");
            Some((path, read_only))
        })
        .collect()
}

fn decode_mountinfo_path(value: &str) -> Option<PathBuf> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..index + 4]
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'7'))
            {
                return None;
            }
            decoded.push(
                (bytes[index + 1] - b'0') * 64
                    + (bytes[index + 2] - b'0') * 8
                    + (bytes[index + 3] - b'0'),
            );
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    (!decoded.contains(&0)).then(|| PathBuf::from(OsString::from_vec(decoded)))
}

fn read_only_hint(paths: &[PathBuf], mount_modes: &BTreeMap<PathBuf, bool>) -> EvidenceHint {
    let mut saw_read_only = false;
    let mut saw_writable = false;
    for path in paths {
        match mount_modes.get(path) {
            Some(true) => saw_read_only = true,
            Some(false) => saw_writable = true,
            None => {}
        }
    }
    match (saw_read_only, saw_writable) {
        (true, false) => EvidenceHint::Yes,
        (false, true) => EvidenceHint::No,
        _ => EvidenceHint::Unknown,
    }
}

fn call_udisks_method(
    connection: &Connection,
    path: &str,
    interface: &str,
    method: &str,
) -> Result<(), zbus::Error> {
    let proxy = Proxy::new(connection, UDISKS_DESTINATION, path, interface)?;
    let options = HashMap::<String, OwnedValue>::new();
    proxy.call(method, &(options,))
}

/// `Filesystem.Mount` needs its own call because, unlike the other operations,
/// it answers with the mount path UDisks2 chose. The empty options map leaves
/// filesystem type and mount flags entirely to UDisks2' own policy.
fn call_udisks_mount(connection: &Connection, path: &str) -> Result<String, zbus::Error> {
    let proxy = Proxy::new(connection, UDISKS_DESTINATION, path, FILESYSTEM_INTERFACE)?;
    let options = HashMap::<String, OwnedValue>::new();
    proxy.call("Mount", &(options,))
}

/// Shared qualification gate for both mounted-volume enumeration and UDisks2
/// attach. Missing properties fail closed: a volume must be explicitly
/// removable, explicitly non-virtual/non-system, and use the shipped native
/// filesystem allowlist before this process will either expose or mount it.
fn udisks_volume_is_eligible(block: &PropertyMap, drive: Option<&PropertyMap>) -> bool {
    udisks_eligibility_facts(
        property_bool(block, "HintIgnore"),
        property_bool(block, "HintSystem"),
        property_string(block, "IdUsage").as_deref(),
        property_string(block, "IdType").as_deref(),
        removable_hint(drive),
        drive.and_then(|properties| property_bool(properties, "Virtual")),
    )
}

fn udisks_eligibility_facts(
    hint_ignore: Option<bool>,
    hint_system: Option<bool>,
    id_usage: Option<&str>,
    filesystem: Option<&str>,
    removable: EvidenceHint,
    virtual_drive: Option<bool>,
) -> bool {
    hint_ignore == Some(false)
        && hint_system == Some(false)
        && id_usage == Some("filesystem")
        && supported_linux_native_filesystem(filesystem)
        && removable == EvidenceHint::Yes
        && virtual_drive == Some(false)
}

#[must_use]
pub fn supported_linux_native_filesystem(filesystem: Option<&str>) -> bool {
    let Some(filesystem) = filesystem.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    SUPPORTED_LINUX_NATIVE_FILESYSTEMS
        .iter()
        .any(|supported| filesystem.eq_ignore_ascii_case(supported))
}

/// Removable evidence for the drive backing a block device. A drive that
/// reports nothing at all stays `Unknown`; absence of a hint is never read as
/// proof that a device is fixed or that it is removable.
fn removable_hint(drive: Option<&PropertyMap>) -> EvidenceHint {
    drive.map_or(EvidenceHint::Unknown, |drive| {
        match (
            property_bool(drive, "Removable"),
            property_bool(drive, "MediaRemovable"),
        ) {
            (Some(true), _) | (_, Some(true)) => EvidenceHint::Yes,
            (Some(false), Some(false)) => EvidenceHint::No,
            _ => EvidenceHint::Unknown,
        }
    })
}

fn classify_attach_failure(error: &zbus::Error) -> AttachRefusalReason {
    match method_error_name(error) {
        Some(name) if is_authorization_error(name) => AttachRefusalReason::PermissionDenied,
        Some(name) if name.ends_with(".ServiceUnknown") || name.ends_with(".NoReply") => {
            AttachRefusalReason::NativeServiceUnavailable
        }
        _ => AttachRefusalReason::Other(safe_zbus_error(error)),
    }
}

fn classify_unmount_failure(error: zbus::Error) -> PlatformEjectOutcome {
    match method_error_name(&error) {
        Some(name) if name.ends_with(".DeviceBusy") => PlatformEjectOutcome::Vetoed {
            code: None,
            reason: "another process is using the mounted filesystem".to_string(),
        },
        Some(name) if is_authorization_error(name) => {
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::PermissionDenied,
            }
        }
        Some(name) if name.ends_with(".NotSupported") => {
            PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            }
        }
        _ => PlatformEjectOutcome::ReleasedForSystemEject {
            reason: EjectUnavailableReason::Other(safe_zbus_error(&error)),
        },
    }
}

fn classify_post_unmount_eject_failure(error: zbus::Error) -> PlatformEjectOutcome {
    let reason = match method_error_name(&error) {
        Some(name) if is_authorization_error(name) => EjectUnavailableReason::PermissionDenied,
        Some(name) if name.ends_with(".NotSupported") => EjectUnavailableReason::Unsupported,
        _ => EjectUnavailableReason::Other(format!(
            "native drive eject failed after filesystem release: {}",
            safe_zbus_error(&error)
        )),
    };
    PlatformEjectOutcome::ReleasedForSystemEject { reason }
}

fn method_error_name(error: &zbus::Error) -> Option<&str> {
    match error {
        zbus::Error::MethodError(name, _, _) => Some(name.as_str()),
        _ => None,
    }
}

fn is_authorization_error(name: &str) -> bool {
    name.ends_with(".NotAuthorized")
        || name.ends_with(".NotAuthorizedCanObtain")
        || name.ends_with(".NotAuthorizedDismissed")
}

fn safe_zbus_error(error: &zbus::Error) -> String {
    match error {
        zbus::Error::MethodError(name, _, _) => format!("D-Bus method error {name}"),
        zbus::Error::InputOutput(_) => "D-Bus I/O error".to_string(),
        _ => "D-Bus operation failed".to_string(),
    }
}

fn subscription_error(error: impl std::fmt::Display) -> RemovableMediaError {
    RemovableMediaError::Subscription(safe_error_text(&error.to_string()))
}

fn enumeration_error(error: impl std::fmt::Display) -> RemovableMediaError {
    RemovableMediaError::Enumeration(safe_error_text(&error.to_string()))
}

fn safe_error_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_filesystem_allowlist_is_explicit_and_case_insensitive() {
        for filesystem in ["ext2", "EXT3", "ext4", "btrfs", "xfs", "f2fs"] {
            assert!(supported_linux_native_filesystem(Some(filesystem)));
        }
        for filesystem in ["", " ", "vfat", "exfat", "ntfs", "overlay"] {
            assert!(!supported_linux_native_filesystem(Some(filesystem)));
        }
        assert!(!supported_linux_native_filesystem(None));
    }

    #[test]
    fn udisks_qualification_rejects_internal_unknown_virtual_and_unsupported_volumes() {
        let eligible = |removable, virtual_drive, filesystem| {
            udisks_eligibility_facts(
                Some(false),
                Some(false),
                Some("filesystem"),
                filesystem,
                removable,
                virtual_drive,
            )
        };

        assert!(eligible(EvidenceHint::Yes, Some(false), Some("ext4")));
        assert!(!eligible(EvidenceHint::No, Some(false), Some("ext4")));
        assert!(!eligible(EvidenceHint::Unknown, Some(false), Some("ext4")));
        assert!(!eligible(EvidenceHint::Yes, Some(true), Some("ext4")));
        assert!(!eligible(EvidenceHint::Yes, None, Some("ext4")));
        assert!(!eligible(EvidenceHint::Yes, Some(false), Some("vfat")));

        assert!(!udisks_eligibility_facts(
            Some(false),
            Some(true),
            Some("filesystem"),
            Some("ext4"),
            EvidenceHint::Yes,
            Some(false),
        ));
        assert!(!udisks_eligibility_facts(
            Some(false),
            Some(false),
            Some("crypto"),
            Some("ext4"),
            EvidenceHint::Yes,
            Some(false),
        ));
        assert!(!udisks_eligibility_facts(
            None,
            Some(false),
            Some("filesystem"),
            Some("ext4"),
            EvidenceHint::Yes,
            Some(false),
        ));
    }
}
