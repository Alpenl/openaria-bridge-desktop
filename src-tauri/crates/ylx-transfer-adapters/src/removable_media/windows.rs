//! Native Windows mounted-volume backend.
//!
//! The backend stays at the already-mounted file-system boundary.  Volume
//! GUIDs and all volume mount paths are discovered through the Windows volume
//! APIs; a zero-access metadata handle and `IOCTL_STORAGE_GET_DEVICE_NUMBER`
//! are used only to associate a volume interface with its PnP devnode.  No
//! volume bytes, physical-disk handle, lock, dismount, or force-eject path is
//! used here.

#![cfg(target_os = "windows")]

use std::collections::BTreeMap;
use std::ffi::{c_void, OsStr};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::slice;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};

use windows::core::PCWSTR;
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_PropertyW, CM_Get_Parent, CM_Register_Notification, CM_Request_Device_EjectW,
    CM_Unregister_Notification, PNP_VetoTypeUnknown, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
    CM_NOTIFY_ACTION, CM_NOTIFY_FILTER, CM_NOTIFY_FILTER_0, CM_NOTIFY_FILTER_0_0,
    CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE, CR_ACCESS_DENIED, CR_CALL_NOT_IMPLEMENTED,
    CR_NOT_DISABLEABLE, CR_SUCCESS, DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HCMNOTIFICATION,
    SP_DEVICE_INTERFACE_DATA, SP_DEVICE_INTERFACE_DETAIL_DATA_W, SP_DEVINFO_DATA,
};
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_Capabilities, DEVPROPTYPE, DEVPROP_TYPE_UINT32,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDiskFreeSpaceExW,
    GetDriveTypeW, GetVolumeInformationW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::{
    GUID_DEVINTERFACE_VOLUME, IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER,
};
use windows::Win32::System::SystemServices::FILE_READ_ONLY_VOLUME;
use windows::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOVABLE};
use windows::Win32::System::IO::DeviceIoControl;

pub use super::windows_seam::{WindowsMountedVolume, WindowsVolumeApi, WindowsVolumeBackend};
use super::{
    EjectUnavailableReason, EvidenceHint, MountedVolume, PlatformEjectOutcome,
    PlatformMountedVolume, PlatformVolumeBackend, RemovableMediaError, SubscriptionDrain,
    VolumeEventSubscription, VolumeGeneration, VolumeIdentity,
};

const MAX_VOLUME_NAME_UTF16: usize = 1024;
const MAX_PATHS_UTF16: usize = 32768;
const MAX_FILESYSTEM_NAME_UTF16: usize = 128;
const MAX_VETO_NAME_UTF16: usize = 256;
const ERROR_NO_MORE_FILES_CODE: u32 = 18;
const ERROR_NO_MORE_ITEMS_CODE: u32 = 259;
const ERROR_INSUFFICIENT_BUFFER_CODE: u32 = 122;
const ERROR_NOT_READY_CODE: u32 = 21;
const ERROR_INVALID_FUNCTION_CODE: u32 = 1;
const ERROR_SHARING_VIOLATION_CODE: u32 = 32;

/// Concrete backend selected by the application on Windows.
pub struct WindowsNativeBackend {
    api: NativeWindowsApi,
}

impl Default for WindowsNativeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsNativeBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            api: NativeWindowsApi::new(),
        }
    }

    #[must_use]
    pub fn into_api(self) -> NativeWindowsApi {
        self.api
    }
}

/// Alias retained for callers that prefer the explicit volume wording.
pub type NativeWindowsVolumeBackend = WindowsNativeBackend;

impl PlatformVolumeBackend for WindowsNativeBackend {
    type Subscription = WindowsPnpSubscription;

    fn subscribe(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
        self.api.register_pnp_notifications()
    }

    fn enumerate_mounted_readable(
        &mut self,
    ) -> Result<Vec<PlatformMountedVolume>, RemovableMediaError> {
        self.api
            .enumerate_volume_guids()?
            .into_iter()
            .map(|volume| {
                let identity =
                    VolumeIdentity::from_native("windows-volume", volume.volume_guid.as_bytes())?;
                let mut observation = PlatformMountedVolume::new(identity, volume.mount_paths)
                    .with_read_only(volume.read_only)
                    .with_removable(volume.removable)
                    .with_capacity_bytes(volume.capacity_bytes);
                if let Some(filesystem) = volume.filesystem {
                    observation = observation.with_filesystem(filesystem);
                }
                if let Some(marker) = volume.device_instance_marker {
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
        self.api.request_pnp_eject(volume)
    }
}

/// Native API implementation.  The map contains only devnode numbers
/// discovered during the last full enumeration; it never owns a volume
/// handle between calls.
pub struct NativeWindowsApi {
    devnodes: BTreeMap<VolumeIdentity, u32>,
}

impl NativeWindowsApi {
    #[must_use]
    pub fn new() -> Self {
        Self {
            devnodes: BTreeMap::new(),
        }
    }

    fn enumerate_native(&mut self) -> Result<Vec<WindowsMountedVolume>, RemovableMediaError> {
        let mut volume_name = vec![0u16; MAX_VOLUME_NAME_UTF16];
        let find = unsafe { FindFirstVolumeW(&mut volume_name) }
            .map_err(|error| enumeration_error(&error))?;
        let mut next_devnodes = BTreeMap::new();
        let mut volumes = Vec::new();
        let result = (|| {
            loop {
                let guid = nul_terminated_utf16(&volume_name);
                if !guid.is_empty() {
                    if let Some(volume) = self.inspect_volume(&guid, &mut next_devnodes)? {
                        volumes.push(volume);
                    }
                }
                volume_name.fill(0);
                match unsafe { FindNextVolumeW(find, &mut volume_name) } {
                    Ok(()) => {}
                    Err(error) if win32_code(&error) == ERROR_NO_MORE_FILES_CODE => break,
                    Err(error) => return Err(enumeration_error(&error)),
                }
            }
            Ok(())
        })();
        let _ = unsafe { FindVolumeClose(find) };
        result?;
        self.devnodes = next_devnodes;
        Ok(volumes)
    }

    fn inspect_volume(
        &mut self,
        volume_guid: &str,
        next_devnodes: &mut BTreeMap<VolumeIdentity, u32>,
    ) -> Result<Option<WindowsMountedVolume>, RemovableMediaError> {
        let mount_paths = volume_mount_paths(volume_guid)?;
        if mount_paths.is_empty() {
            return Ok(None);
        }

        let (filesystem, read_only) = volume_information(&mount_paths);
        let capacity_bytes = volume_capacity(&mount_paths);
        let removable = drive_type_hint(&mount_paths);
        let identity = VolumeIdentity::from_native("windows-volume", volume_guid.as_bytes())?;

        // Failure to map a volume to a devnode is non-fatal.  Enumeration is
        // still useful for ordinary file import; eject then honestly reports
        // that the system eject UI is required.
        let device_instance_marker = match map_volume_devnode(volume_guid) {
            Ok(Some(devinst)) => {
                next_devnodes.insert(identity, devinst);
                Some(format!("devinst:{devinst}"))
            }
            Ok(None) => None,
            Err(_) => None,
        };

        Ok(Some(WindowsMountedVolume {
            volume_guid: volume_guid.to_string(),
            mount_paths,
            filesystem,
            read_only,
            removable,
            capacity_bytes,
            device_instance_marker,
        }))
    }
}

impl Default for NativeWindowsApi {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowsVolumeApi for NativeWindowsApi {
    type Subscription = WindowsPnpSubscription;

    fn register_pnp_notifications(&mut self) -> Result<Self::Subscription, RemovableMediaError> {
        WindowsPnpSubscription::register()
    }

    fn enumerate_volume_guids(&mut self) -> Result<Vec<WindowsMountedVolume>, RemovableMediaError> {
        self.enumerate_native()
    }

    fn release_volume_handles(
        &mut self,
        _generation: &VolumeGeneration,
    ) -> Result<(), RemovableMediaError> {
        // No native handle is retained across an adapter call.  This method
        // is intentionally explicit so a future metadata cache cannot turn
        // into an eject-blocking ownership leak.
        Ok(())
    }

    fn request_pnp_eject(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<PlatformEjectOutcome, RemovableMediaError> {
        let Some(devinst) = self.devnodes.get(volume.generation.identity()).copied() else {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            });
        };
        let eject_devinst = nearest_ejectable_devnode(devinst).unwrap_or(devinst);
        let mut veto_type = PNP_VetoTypeUnknown;
        let mut veto_name = [0u16; MAX_VETO_NAME_UTF16];
        let result = unsafe {
            CM_Request_Device_EjectW(eject_devinst, Some(&mut veto_type), Some(&mut veto_name), 0)
        };
        if result == CR_SUCCESS {
            return Ok(PlatformEjectOutcome::Ejected);
        }
        if result == CR_ACCESS_DENIED {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::PermissionDenied,
            });
        }
        if result == CR_CALL_NOT_IMPLEMENTED || result == CR_NOT_DISABLEABLE {
            return Ok(PlatformEjectOutcome::ReleasedForSystemEject {
                reason: EjectUnavailableReason::Unsupported,
            });
        }
        let reason = bounded_utf16(&veto_name).unwrap_or_else(|| {
            format!(
                "Windows PnP refused eject (configuration return {})",
                result.0
            )
        });
        Ok(PlatformEjectOutcome::Vetoed {
            code: Some(veto_type.0 as u32),
            reason,
        })
    }
}

/// Subscription callback context.  The callback only coalesces an
/// invalidation; it never enumerates, allocates an unbounded payload, or does
/// filesystem I/O.
struct NotificationContext {
    sender: SyncSender<()>,
}

pub struct WindowsPnpSubscription {
    handle: Option<HCMNOTIFICATION>,
    context_address: Option<usize>,
    invalidations: Receiver<()>,
}

// HCMNOTIFICATION and the callback context are used only through the native
// registration lifetime. Drop unregisters before reclaiming the context.
unsafe impl Send for WindowsPnpSubscription {}

impl WindowsPnpSubscription {
    fn register() -> Result<Self, RemovableMediaError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = Box::new(NotificationContext { sender });
        let context_address = Box::into_raw(context) as usize;
        let filter = CM_NOTIFY_FILTER {
            cbSize: size_of::<CM_NOTIFY_FILTER>() as u32,
            Flags: 0,
            FilterType: CM_NOTIFY_FILTER_TYPE_DEVICEINTERFACE,
            Reserved: 0,
            u: CM_NOTIFY_FILTER_0 {
                DeviceInterface: CM_NOTIFY_FILTER_0_0 {
                    ClassGuid: GUID_DEVINTERFACE_VOLUME,
                },
            },
        };
        let mut handle = HCMNOTIFICATION::default();
        let result = unsafe {
            CM_Register_Notification(
                &filter,
                Some(context_address as *const c_void),
                Some(pnp_callback),
                &mut handle,
            )
        };
        if result != CR_SUCCESS {
            unsafe {
                drop(Box::from_raw(context_address as *mut NotificationContext));
            }
            return Err(RemovableMediaError::Subscription(format!(
                "CM_Register_Notification returned {}",
                result.0
            )));
        }
        Ok(Self {
            handle: Some(handle),
            context_address: Some(context_address),
            invalidations: receiver,
        })
    }
}

impl VolumeEventSubscription for WindowsPnpSubscription {
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

impl Drop for WindowsPnpSubscription {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = unsafe { CM_Unregister_Notification(handle) };
        }
        if let Some(address) = self.context_address.take() {
            unsafe {
                drop(Box::from_raw(address as *mut NotificationContext));
            }
        }
    }
}

unsafe extern "system" fn pnp_callback(
    _notify: HCMNOTIFICATION,
    context: *const c_void,
    _action: CM_NOTIFY_ACTION,
    _event_data: *const windows::Win32::Devices::DeviceAndDriverInstallation::CM_NOTIFY_EVENT_DATA,
    _event_data_size: u32,
) -> u32 {
    if context.is_null() {
        return 0;
    }
    let context = &*(context.cast::<NotificationContext>());
    let _ = context.sender.try_send(());
    0
}

fn volume_mount_paths(volume_guid: &str) -> Result<Vec<PathBuf>, RemovableMediaError> {
    let wide = wide_null(volume_guid);
    let mut required = 0u32;
    let _ = unsafe {
        windows::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW(
            PCWSTR(wide.as_ptr()),
            None,
            &mut required,
        )
    };
    if required == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u16; (required as usize).saturating_add(1)];
    loop {
        let mut returned = required;
        match unsafe {
            windows::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW(
                PCWSTR(wide.as_ptr()),
                Some(&mut buffer),
                &mut returned,
            )
        } {
            Ok(()) => return Ok(parse_multi_string(&buffer)),
            Err(error) if win32_code(&error) == ERROR_INSUFFICIENT_BUFFER_CODE => {
                let needed = (returned as usize).saturating_add(1);
                if needed > MAX_PATHS_UTF16 {
                    return Err(RemovableMediaError::Enumeration(
                        "Windows volume mount-path list exceeded the safety bound".to_string(),
                    ));
                }
                buffer.resize(needed, 0);
                required = returned;
            }
            Err(error) if is_not_ready(&error) => return Ok(Vec::new()),
            Err(error) => return Err(enumeration_error(&error)),
        }
    }
}

fn volume_information(paths: &[PathBuf]) -> (Option<String>, EvidenceHint) {
    for path in paths {
        let wide = wide_null_path(path);
        let mut filesystem = [0u16; MAX_FILESYSTEM_NAME_UTF16];
        let mut flags = 0u32;
        let result = unsafe {
            GetVolumeInformationW(
                PCWSTR(wide.as_ptr()),
                None,
                None,
                None,
                Some(&mut flags),
                Some(&mut filesystem),
            )
        };
        if result.is_ok() {
            let name = bounded_utf16(&filesystem);
            let read_only = if flags & FILE_READ_ONLY_VOLUME != 0 {
                EvidenceHint::Yes
            } else {
                EvidenceHint::No
            };
            return (name, read_only);
        }
    }
    (None, EvidenceHint::Unknown)
}

fn volume_capacity(paths: &[PathBuf]) -> Option<u64> {
    paths.iter().find_map(|path| {
        let wide = wide_null_path(path);
        let mut total = 0u64;
        unsafe { GetDiskFreeSpaceExW(PCWSTR(wide.as_ptr()), None, Some(&mut total), None) }
            .ok()
            .map(|_| total)
    })
}

fn drive_type_hint(paths: &[PathBuf]) -> EvidenceHint {
    let mut saw_removable = false;
    let mut saw_fixed = false;
    for path in paths {
        let wide = wide_null_path(path);
        let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };
        if drive_type == DRIVE_REMOVABLE {
            saw_removable = true;
        } else if drive_type == DRIVE_FIXED {
            saw_fixed = true;
        }
    }
    match (saw_removable, saw_fixed) {
        (true, _) => EvidenceHint::Yes,
        (false, true) => EvidenceHint::No,
        _ => EvidenceHint::Unknown,
    }
}

fn map_volume_devnode(volume_guid: &str) -> Result<Option<u32>, RemovableMediaError> {
    let volume_handle = match open_metadata_handle(volume_guid) {
        Ok(handle) => handle,
        Err(error) if is_nonfatal_metadata_error(&error) => return Ok(None),
        Err(error) => return Err(enumeration_error(&error)),
    };
    let mut number = STORAGE_DEVICE_NUMBER::default();
    let mut bytes_returned = 0u32;
    let ioctl = unsafe {
        DeviceIoControl(
            volume_handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            None,
            0,
            Some((&mut number as *mut STORAGE_DEVICE_NUMBER).cast::<c_void>()),
            size_of::<STORAGE_DEVICE_NUMBER>() as u32,
            Some(&mut bytes_returned),
            None,
        )
    };
    let _ = unsafe { CloseHandle(volume_handle) };
    if ioctl.is_err() || bytes_returned < size_of::<STORAGE_DEVICE_NUMBER>() as u32 {
        return Ok(None);
    }
    find_matching_volume_interface(number)
}

fn find_matching_volume_interface(
    expected: STORAGE_DEVICE_NUMBER,
) -> Result<Option<u32>, RemovableMediaError> {
    let device_set = unsafe {
        SetupDiGetClassDevsW(
            Some(&GUID_DEVINTERFACE_VOLUME),
            PCWSTR::null(),
            None,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        )
    }
    .map_err(|error| enumeration_error(&error))?;
    let mut found = None;
    let result = (|| {
        for index in 0..u32::MAX {
            let mut interface_data = SP_DEVICE_INTERFACE_DATA {
                cbSize: size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
                ..Default::default()
            };
            match unsafe {
                SetupDiEnumDeviceInterfaces(
                    device_set,
                    None,
                    &GUID_DEVINTERFACE_VOLUME,
                    index,
                    &mut interface_data,
                )
            } {
                Ok(()) => {}
                Err(error) if win32_code(&error) == ERROR_NO_MORE_ITEMS_CODE => break,
                Err(error) => return Err(enumeration_error(&error)),
            }

            let mut required = 0u32;
            let _ = unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    device_set,
                    &interface_data,
                    None,
                    0,
                    Some(&mut required),
                    None,
                )
            };
            if required < size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32 {
                continue;
            }
            // usize-backed storage supplies the alignment required by the
            // generated C struct on x86/x64 while retaining the API's byte
            // length contract.
            let units = (required as usize).div_ceil(size_of::<usize>());
            let mut storage = vec![0usize; units];
            let detail = storage
                .as_mut_ptr()
                .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
            unsafe {
                ptr::write_unaligned(
                    ptr::addr_of_mut!((*detail).cbSize),
                    size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32,
                );
            }
            let mut devinfo = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    device_set,
                    &interface_data,
                    Some(detail),
                    required,
                    Some(&mut required),
                    Some(&mut devinfo),
                )
            }
            .is_err()
            {
                continue;
            }
            let device_path =
                unsafe { detail_device_path(detail, storage.len() * size_of::<usize>()) };
            if device_path.is_empty() {
                continue;
            }
            let Some(number) = device_interface_storage_number(&device_path) else {
                continue;
            };
            if number.DeviceType == expected.DeviceType
                && number.DeviceNumber == expected.DeviceNumber
                && number.PartitionNumber == expected.PartitionNumber
            {
                found = Some(devinfo.DevInst);
                break;
            }
        }
        Ok(())
    })();
    let _ = unsafe { SetupDiDestroyDeviceInfoList(device_set) };
    result?;
    Ok(found)
}

unsafe fn detail_device_path(
    detail: *const SP_DEVICE_INTERFACE_DETAIL_DATA_W,
    storage_bytes: usize,
) -> String {
    let base = detail.cast::<u8>();
    let offset = size_of::<u32>();
    if storage_bytes <= offset {
        return String::new();
    }
    let values = slice::from_raw_parts(
        base.add(offset).cast::<u16>(),
        (storage_bytes - offset) / size_of::<u16>(),
    );
    bounded_utf16(values).unwrap_or_default()
}

fn device_interface_storage_number(path: &str) -> Option<STORAGE_DEVICE_NUMBER> {
    let handle = open_metadata_handle(path).ok()?;
    let mut number = STORAGE_DEVICE_NUMBER::default();
    let mut returned = 0u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            None,
            0,
            Some((&mut number as *mut STORAGE_DEVICE_NUMBER).cast::<c_void>()),
            size_of::<STORAGE_DEVICE_NUMBER>() as u32,
            Some(&mut returned),
            None,
        )
    };
    let _ = unsafe { CloseHandle(handle) };
    result
        .ok()
        .and((returned >= size_of::<STORAGE_DEVICE_NUMBER>() as u32).then_some(number))
}

fn open_metadata_handle(path: &str) -> windows::core::Result<HANDLE> {
    let wide = wide_null(path);
    unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
}

fn nearest_ejectable_devnode(start: u32) -> Option<u32> {
    let mut current = start;
    for _ in 0..64 {
        if let Some(capabilities) = devnode_capabilities(current) {
            if capabilities & (2 | 4) != 0 {
                return Some(current);
            }
        }
        let mut parent = 0u32;
        let result = unsafe { CM_Get_Parent(&mut parent, current, 0) };
        if result != CR_SUCCESS || parent == current {
            break;
        }
        current = parent;
    }
    None
}

fn devnode_capabilities(devinst: u32) -> Option<u32> {
    let mut property_type = DEVPROPTYPE::default();
    let mut size = size_of::<u32>() as u32;
    let mut bytes = [0u8; size_of::<u32>()];
    let result = unsafe {
        CM_Get_DevNode_PropertyW(
            devinst,
            &DEVPKEY_Device_Capabilities,
            &mut property_type,
            Some(bytes.as_mut_ptr()),
            &mut size,
            0,
        )
    };
    if result != CR_SUCCESS || property_type.0 != DEVPROP_TYPE_UINT32.0 || size < 4 {
        return None;
    }
    Some(u32::from_ne_bytes(bytes))
}

fn parse_multi_string(values: &[u16]) -> Vec<PathBuf> {
    values
        .split(|value| *value == 0)
        .take_while(|part| !part.is_empty())
        .filter_map(|part| {
            let value = String::from_utf16(part).ok()?;
            let path = PathBuf::from(value);
            path.is_absolute().then_some(path)
        })
        .collect()
}

fn nul_terminated_utf16(values: &[u16]) -> String {
    bounded_utf16(values).unwrap_or_default()
}

fn bounded_utf16(values: &[u16]) -> Option<String> {
    let end = values
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(values.len());
    if end == 0 || end > MAX_PATHS_UTF16 {
        return None;
    }
    let value = String::from_utf16(&values[..end]).ok()?;
    let mut clean = String::with_capacity(value.len().min(512));
    for character in value.chars() {
        if character.is_control() {
            clean.push(' ');
        } else {
            clean.push(character);
        }
        if clean.len() >= 512 {
            break;
        }
    }
    (!clean.is_empty()).then_some(clean)
}

fn wide_null(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn wide_null_path(value: &Path) -> Vec<u16> {
    value
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn win32_code(error: &windows::core::Error) -> u32 {
    let code = error.code().0 as u32;
    if code & 0xffff_0000 == 0x8007_0000 {
        code & 0xffff
    } else {
        code
    }
}

fn is_not_ready(error: &windows::core::Error) -> bool {
    win32_code(error) == ERROR_NOT_READY_CODE
}

fn is_nonfatal_metadata_error(error: &windows::core::Error) -> bool {
    matches!(
        win32_code(error),
        5 | ERROR_NOT_READY_CODE | ERROR_INVALID_FUNCTION_CODE | ERROR_SHARING_VIOLATION_CODE
    )
}

fn enumeration_error(error: &windows::core::Error) -> RemovableMediaError {
    RemovableMediaError::Enumeration(safe_windows_error(error))
}

fn safe_windows_error(error: &windows::core::Error) -> String {
    format!("Windows error {}", win32_code(error))
}
