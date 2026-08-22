//! Native macOS mounted-volume backend.
//!
//! The backend observes only file systems that macOS has already mounted.
//! Foundation supplies the mounted volume URLs and resource values; Disk
//! Arbitration supplies invalidation callbacks and non-forced unmount/eject.
//! No raw disk handle, repair, mount, format, or privilege escalation path is
//! used here.

#![cfg(target_os = "macos")]

use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CStr};
use std::ptr;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::time::Duration;

use core_foundation_sys::base::{kCFAllocatorDefault, CFAllocatorRef, CFRelease, CFTypeRef};
use core_foundation_sys::dictionary::CFDictionaryRef;
use core_foundation_sys::string::{kCFStringEncodingUTF8, CFStringGetCString, CFStringRef};
use core_foundation_sys::url::CFURLRef;
use objc2::rc::autoreleasepool;
use objc2::runtime::AnyObject;
use objc2_foundation::{
    NSArray, NSDictionary, NSFileManager, NSNumber, NSString, NSURLResourceKey,
    NSURLVolumeIsEjectableKey, NSURLVolumeIsReadOnlyKey, NSURLVolumeIsRemovableKey,
    NSURLVolumeTotalCapacityKey, NSURLVolumeTypeNameKey, NSURLVolumeUUIDStringKey,
    NSVolumeEnumerationOptions, NSURL,
};

pub use super::macos_seam::{MacOsMountedVolume, MacOsVolumeApi, MacOsVolumeBackend};
use super::{
    EjectUnavailableReason, EvidenceHint, MountedVolume, PlatformEjectOutcome,
    PlatformMountedVolume, PlatformVolumeBackend, RemovableMediaError, SubscriptionDrain,
    VolumeEventSubscription, VolumeGeneration, VolumeIdentity,
};

const DISK_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CF_STRING_UTF8: usize = 512;

type DASessionRef = *mut c_void;
type DADiskRef = *mut c_void;
type DADissenterRef = *mut c_void;
type DAReturn = i32;
type DispatchQueue = *mut c_void;
type DiskAppearedCallback = unsafe extern "C" fn(DADiskRef, *mut c_void);
type DiskDisappearedCallback = unsafe extern "C" fn(DADiskRef, *mut c_void);
type DiskOperationCallback = unsafe extern "C" fn(DADiskRef, DADissenterRef, *mut c_void);

#[link(name = "DiskArbitration", kind = "framework")]
extern "C" {
    fn DASessionCreate(allocator: CFAllocatorRef) -> DASessionRef;
    fn DASessionSetDispatchQueue(session: DASessionRef, queue: DispatchQueue);
    fn DARegisterDiskAppearedCallback(
        session: DASessionRef,
        matching: CFDictionaryRef,
        callback: Option<DiskAppearedCallback>,
        context: *mut c_void,
    );
    fn DARegisterDiskDisappearedCallback(
        session: DASessionRef,
        matching: CFDictionaryRef,
        callback: Option<DiskDisappearedCallback>,
        context: *mut c_void,
    );
    fn DAUnregisterCallback(session: DASessionRef, callback: *mut c_void, context: *mut c_void);
    fn DADiskCreateFromVolumePath(
        allocator: CFAllocatorRef,
        session: DASessionRef,
        path: CFURLRef,
    ) -> DADiskRef;
    fn DADiskGetBSDName(disk: DADiskRef) -> *const c_char;
    fn DADiskUnmount(
        disk: DADiskRef,
        options: u32,
        callback: Option<DiskOperationCallback>,
        context: *mut c_void,
    );
    fn DADiskEject(
        disk: DADiskRef,
        options: u32,
        callback: Option<DiskOperationCallback>,
        context: *mut c_void,
    );
    fn DADissenterGetStatus(dissenter: DADissenterRef) -> DAReturn;
    fn DADissenterGetStatusString(dissenter: DADissenterRef) -> CFStringRef;
}

extern "C" {
    fn dispatch_queue_create(label: *const c_char, attr: *const c_void) -> DispatchQueue;
    fn dispatch_release(object: *mut c_void);
}

/// Concrete backend selected by the application on macOS.
pub struct MacOsNativeBackend {
    api: NativeMacOsVolumeApi,
}

impl Default for MacOsNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsNativeBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            api: NativeMacOsVolumeApi::new(),
        }
    }

    #[must_use]
    pub fn into_api(self) -> NativeMacOsVolumeApi {
        self.api
    }
}

/// Alias retained for callers that prefer the explicit volume wording.
pub type NativeMacOsVolumeBackend = MacOsNativeBackend;

impl PlatformVolumeBackend for MacOsNativeBackend {
    type Subscription = MacOsDiskArbitrationSubscription;

    fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
        self.api.register_disk_arbitration_callbacks()
    }

    fn enumerate_mounted_readable(
        &mut self,
    ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
        self.api
            .enumerate_mounted_volume_urls()?
            .into_iter()
            .map(|volume| {
                let identity =
                    VolumeIdentity::from_native("macos-volume", volume.volume_identity.as_bytes())?;
                let mut observation = PlatformMountedVolume::new(identity, volume.mounted_urls)
                    .with_read_only(volume.read_only)
                    .with_removable(volume.removable)
                    .with_capacity_bytes(volume.capacity_bytes);
                if let Some(filesystem) = volume.filesystem {
                    observation = observation.with_filesystem(filesystem);
                }
                if let Some(marker) = volume.disk_instance_marker {
                    observation = observation.with_presence_marker(marker);
                }
                Ok(observation)
            })
            .collect()
    }

    fn release_volume_handles(
        &mut self,
        generation: &VolumeGeneration,
    ) -> Result<(), RemovableMediaError> {
        self.api.release_volume_handles(generation)
    }

    fn request_eject(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
        self.api.request_disk_arbitration_eject(volume)
    }
}

pub struct NativeMacOsVolumeApi {
    disk_markers: BTreeMap<VolumeIdentity, String>,
}

impl NativeMacOsVolumeApi {
    #[must_use]
    pub fn new() -> Self {
        Self {
            disk_markers: BTreeMap::new(),
        }
    }

    fn enumerate_native(&mut self) -> Result<Vec<MacOsMountedVolume>, RemovableMediaError> {
        autoreleasepool(|_| {
            let session = DiskSession::create().ok_or_else(|| {
                RemovableMediaError::Enumeration(
                    "Disk Arbitration session could not be created".to_string(),
                )
            })?;
            let manager = NSFileManager::defaultManager();
            let keys = mounted_volume_resource_keys();
            let Some(urls) = manager.mountedVolumeURLsIncludingResourceValuesForKeys_options(
                Some(&keys),
                NSVolumeEnumerationOptions::SkipHiddenVolumes,
            ) else {
                return Ok(Vec::new());
            };

            let mut observations = Vec::new();
            let mut disk_markers = BTreeMap::new();
            for url in urls.to_vec() {
                let Some(volume) = inspect_mounted_url(&session, &url)? else {
                    continue;
                };
                if let Some(marker) = &volume.disk_instance_marker {
                    let identity = VolumeIdentity::from_native(
                        "macos-volume",
                        volume.volume_identity.as_bytes(),
                    )?;
                    disk_markers.insert(identity, marker.clone());
                }
                observations.push(volume);
            }
            self.disk_markers = disk_markers;
            Ok(observations)
        })
    }
}

impl Default for NativeMacOsVolumeApi {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsVolumeApi for NativeMacOsVolumeApi {
    type Subscription = MacOsDiskArbitrationSubscription;

    fn register_disk_arbitration_callbacks(
        &mut self,
    ) -> Result<Self::Subscription, RemovableMediaError> {
        MacOsDiskArbitrationSubscription::register()
    }

    fn enumerate_mounted_volume_urls(
        &mut self,
    ) -> Result<Vec<MacOsMountedVolume>, RemovableMediaError> {
        self.enumerate_native()
    }

    fn release_volume_handles(
        &mut self,
        _generation: &VolumeGeneration,
    ) -> Result<(), RemovableMediaError> {
        // Enumeration creates only short-lived Foundation/Disk Arbitration
        // references. Nothing is retained across adapter calls.
        Ok(())
    }

    fn request_disk_arbitration_eject(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
        let Some(path) = volume.mount_paths.first() else {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            });
        };
        autoreleasepool(|_| {
            let Some(url) = NSURL::from_directory_path(path) else {
                return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                    reason: EjectUnavailableReason::Unsupported,
                });
            };
            let Some(session) = DiskSession::create() else {
                return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                    reason: EjectUnavailableReason::NativeServiceUnavailable,
                });
            };
            let Some(disk) = Disk::from_volume_url(&session, &url) else {
                return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                    reason: EjectUnavailableReason::Unsupported,
                });
            };

            match run_disk_operation(|context| unsafe {
                DADiskUnmount(disk.as_ptr(), 0, Some(disk_operation_callback), context);
            }) {
                Ok(DiskOperationResult::Success) => {}
                Ok(DiskOperationResult::Dissented { code, reason }) => {
                    return Ok(PlatformEjectOutcome::Vetoed {
                        code: Some(code as u32),
                        reason,
                    });
                }
                Err(reason) => {
                    return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                        reason: EjectUnavailableReason::Other(reason),
                    });
                }
            }

            match run_disk_operation(|context| unsafe {
                DADiskEject(disk.as_ptr(), 0, Some(disk_operation_callback), context);
            }) {
                Ok(DiskOperationResult::Success) => Ok(PlatformEjectOutcome::Ejected),
                Ok(DiskOperationResult::Dissented { reason, .. }) => {
                    Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                        reason: EjectUnavailableReason::Other(format!(
                            "native disk eject failed after filesystem release: {reason}"
                        )),
                    })
                }
                Err(reason) => Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                    reason: EjectUnavailableReason::Other(reason),
                }),
            }
        })
    }
}

struct EventContext {
    sender: SyncSender<()>,
}

pub struct MacOsDiskArbitrationSubscription {
    session: Option<DiskSession>,
    queue: DispatchQueue,
    context_address: Option<usize>,
    invalidations: Receiver<()>,
}

// Disk Arbitration callbacks may arrive on the private dispatch queue. Drop
// unregisters callbacks and unschedules the session before reclaiming context.
unsafe impl Send for MacOsDiskArbitrationSubscription {}

impl MacOsDiskArbitrationSubscription {
    fn register() -> Result<Self, RemovableMediaError> {
        let Some(session) = DiskSession::create() else {
            return Err(RemovableMediaError::Subscription(
                "Disk Arbitration session could not be created".to_string(),
            ));
        };
        let queue = unsafe {
            dispatch_queue_create(
                c"ylx-removable-media.disk-arbitration".as_ptr(),
                ptr::null(),
            )
        };
        if queue.is_null() {
            return Err(RemovableMediaError::Subscription(
                "Disk Arbitration dispatch queue could not be created".to_string(),
            ));
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = Box::new(EventContext { sender });
        let context_address = Box::into_raw(context) as usize;
        unsafe {
            DARegisterDiskAppearedCallback(
                session.as_ptr(),
                ptr::null(),
                Some(disk_appeared_callback),
                context_address as *mut c_void,
            );
            DARegisterDiskDisappearedCallback(
                session.as_ptr(),
                ptr::null(),
                Some(disk_disappeared_callback),
                context_address as *mut c_void,
            );
            DASessionSetDispatchQueue(session.as_ptr(), queue);
        }
        Ok(Self {
            session: Some(session),
            queue,
            context_address: Some(context_address),
            invalidations: receiver,
        })
    }
}

impl VolumeEventSubscription for MacOsDiskArbitrationSubscription {
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
}

impl Drop for MacOsDiskArbitrationSubscription {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if let Some(address) = self.context_address {
                unsafe {
                    DAUnregisterCallback(
                        session.as_ptr(),
                        disk_appeared_callback as *const () as *mut c_void,
                        address as *mut c_void,
                    );
                    DAUnregisterCallback(
                        session.as_ptr(),
                        disk_disappeared_callback as *const () as *mut c_void,
                        address as *mut c_void,
                    );
                }
            }
            unsafe {
                DASessionSetDispatchQueue(session.as_ptr(), ptr::null_mut());
            }
        }
        if !self.queue.is_null() {
            unsafe {
                dispatch_release(self.queue.cast::<c_void>());
            }
            self.queue = ptr::null_mut();
        }
        if let Some(address) = self.context_address.take() {
            unsafe {
                drop(Box::from_raw(address as *mut EventContext));
            }
        }
    }
}

unsafe extern "C" fn disk_appeared_callback(_disk: DADiskRef, context: *mut c_void) {
    coalesce_disk_event(context);
}

unsafe extern "C" fn disk_disappeared_callback(_disk: DADiskRef, context: *mut c_void) {
    coalesce_disk_event(context);
}

unsafe fn coalesce_disk_event(context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let context = &*(context.cast::<EventContext>());
    let _ = context.sender.try_send(());
}

struct MountedVolumeResourceKeys {
    uuid: &'static NSURLResourceKey,
    filesystem: &'static NSURLResourceKey,
    read_only: &'static NSURLResourceKey,
    removable: &'static NSURLResourceKey,
    ejectable: &'static NSURLResourceKey,
    capacity: &'static NSURLResourceKey,
}

impl MountedVolumeResourceKeys {
    fn load() -> Self {
        // SAFETY: Foundation exports these process-lifetime immutable key
        // objects on every supported macOS version. This adapter only borrows
        // them when requesting mounted-volume resource values.
        unsafe {
            Self {
                uuid: NSURLVolumeUUIDStringKey,
                filesystem: NSURLVolumeTypeNameKey,
                read_only: NSURLVolumeIsReadOnlyKey,
                removable: NSURLVolumeIsRemovableKey,
                ejectable: NSURLVolumeIsEjectableKey,
                capacity: NSURLVolumeTotalCapacityKey,
            }
        }
    }

    fn as_array(&self) -> objc2::rc::Retained<NSArray<NSURLResourceKey>> {
        NSArray::from_slice(&[
            self.uuid,
            self.filesystem,
            self.read_only,
            self.removable,
            self.ejectable,
            self.capacity,
        ])
    }
}

fn mounted_volume_resource_keys() -> objc2::rc::Retained<NSArray<NSURLResourceKey>> {
    MountedVolumeResourceKeys::load().as_array()
}

fn inspect_mounted_url(
    session: &DiskSession,
    url: &NSURL,
) -> Result<Option<MacOsMountedVolume>, RemovableMediaError> {
    let Some(path) = url.to_file_path() else {
        return Ok(None);
    };
    if !path.is_absolute() {
        return Ok(None);
    }

    let resource_keys = MountedVolumeResourceKeys::load();
    let keys = resource_keys.as_array();
    let values = match url.resourceValuesForKeys_error(&keys) {
        Ok(values) => values,
        Err(_) => return Ok(None),
    };
    let bsd_name = Disk::from_volume_url(session, url).and_then(|disk| disk.bsd_name());
    let Some(identity) = ns_string_value(&values, resource_keys.uuid)
        .map(|uuid| format!("volume-uuid:{uuid}"))
        .or_else(|| bsd_name.as_ref().map(|name| format!("bsd-name:{name}")))
    else {
        return Ok(None);
    };

    let filesystem = ns_string_value(&values, resource_keys.filesystem);
    let read_only = evidence_from_bool(ns_bool_value(&values, resource_keys.read_only));
    let is_removable = ns_bool_value(&values, resource_keys.removable);
    let is_ejectable = ns_bool_value(&values, resource_keys.ejectable);
    let removable = match (is_removable, is_ejectable) {
        (Some(true), _) | (_, Some(true)) => EvidenceHint::Yes,
        (Some(false), Some(false)) => EvidenceHint::No,
        _ => EvidenceHint::Unknown,
    };
    let capacity_bytes = ns_u64_value(&values, resource_keys.capacity);

    Ok(Some(MacOsMountedVolume {
        volume_identity: identity,
        mounted_urls: vec![path],
        filesystem,
        read_only,
        removable,
        capacity_bytes,
        disk_instance_marker: bsd_name.map(|name| format!("bsd:{name}")),
    }))
}

fn ns_string_value(
    values: &NSDictionary<NSURLResourceKey, AnyObject>,
    key: &NSURLResourceKey,
) -> Option<String> {
    values
        .objectForKey(key)?
        .downcast::<NSString>()
        .ok()
        .map(|value| value.to_string())
}

fn ns_bool_value(
    values: &NSDictionary<NSURLResourceKey, AnyObject>,
    key: &NSURLResourceKey,
) -> Option<bool> {
    values
        .objectForKey(key)?
        .downcast::<NSNumber>()
        .ok()
        .map(|value| value.as_bool())
}

fn ns_u64_value(
    values: &NSDictionary<NSURLResourceKey, AnyObject>,
    key: &NSURLResourceKey,
) -> Option<u64> {
    values
        .objectForKey(key)?
        .downcast::<NSNumber>()
        .ok()
        .map(|value| value.as_u64())
}

fn evidence_from_bool(value: Option<bool>) -> EvidenceHint {
    match value {
        Some(true) => EvidenceHint::Yes,
        Some(false) => EvidenceHint::No,
        None => EvidenceHint::Unknown,
    }
}

struct DiskSession(DASessionRef);

impl DiskSession {
    fn create() -> Option<Self> {
        let session = unsafe { DASessionCreate(kCFAllocatorDefault) };
        (!session.is_null()).then_some(Self(session))
    }

    fn as_ptr(&self) -> DASessionRef {
        self.0
    }
}

impl Drop for DiskSession {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CFRelease(self.0.cast::<c_void>() as CFTypeRef);
            }
            self.0 = ptr::null_mut();
        }
    }
}

struct Disk(DADiskRef);

impl Disk {
    fn from_volume_url(session: &DiskSession, url: &NSURL) -> Option<Self> {
        let cf_url = (url as *const NSURL).cast::<c_void>() as CFURLRef;
        let disk =
            unsafe { DADiskCreateFromVolumePath(kCFAllocatorDefault, session.as_ptr(), cf_url) };
        (!disk.is_null()).then_some(Self(disk))
    }

    fn as_ptr(&self) -> DADiskRef {
        self.0
    }

    fn bsd_name(&self) -> Option<String> {
        let name = unsafe { DADiskGetBSDName(self.0) };
        if name.is_null() {
            return None;
        }
        unsafe { CStr::from_ptr(name) }
            .to_str()
            .ok()
            .map(ToOwned::to_owned)
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CFRelease(self.0.cast::<c_void>() as CFTypeRef);
            }
            self.0 = ptr::null_mut();
        }
    }
}

enum DiskOperationResult {
    Success,
    Dissented { code: DAReturn, reason: String },
}

struct DiskOperationContext {
    sender: SyncSender<DiskOperationResult>,
}

fn run_disk_operation(operation: impl FnOnce(*mut c_void)) -> Result<DiskOperationResult, String> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let context = Box::into_raw(Box::new(DiskOperationContext { sender }));
    operation(context.cast::<c_void>());
    receiver
        .recv_timeout(DISK_OPERATION_TIMEOUT)
        .map_err(|_| "Disk Arbitration did not complete the requested operation".to_string())
}

unsafe extern "C" fn disk_operation_callback(
    _disk: DADiskRef,
    dissenter: DADissenterRef,
    context: *mut c_void,
) {
    if context.is_null() {
        return;
    }
    let context = Box::from_raw(context.cast::<DiskOperationContext>());
    let result = if dissenter.is_null() {
        DiskOperationResult::Success
    } else {
        let code = DADissenterGetStatus(dissenter);
        let reason = cf_string_to_string(DADissenterGetStatusString(dissenter))
            .unwrap_or_else(|| format!("Disk Arbitration dissenter status {code}"));
        DiskOperationResult::Dissented { code, reason }
    };
    let _ = context.sender.try_send(result);
}

fn cf_string_to_string(value: CFStringRef) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let mut buffer = [0i8; MAX_CF_STRING_UTF8];
    let ok = unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr(),
            buffer.len() as isize,
            kCFStringEncodingUTF8,
        )
    };
    if ok == 0 {
        return None;
    }
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_str()
        .ok()
        .map(ToOwned::to_owned)
}
