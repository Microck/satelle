#[cfg(windows)]
use flate2::{Compression, write::ZlibEncoder};
use satelle_core::SatelleError;
use satelle_core::sensitive_diagnostics::MAX_DESKTOP_SNAPSHOT_BYTES;
#[cfg(windows)]
use std::io::Write;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[cfg(target_os = "macos")]
struct SnapshotStaging {
    root: PathBuf,
}

#[cfg(target_os = "macos")]
impl SnapshotStaging {
    fn create() -> Result<Self, SatelleError> {
        let root = std::env::temp_dir().join(format!(
            "satelle-desktop-snapshot-{}",
            uuid::Uuid::now_v7().hyphenated()
        ));
        satelle_core::open_or_create_owner_only_directory(&root).map_err(|_| {
            SatelleError::desktop_snapshot_permission_required("staging_unavailable")
        })?;
        Ok(Self { root })
    }

    fn image_path(&self) -> PathBuf {
        self.root.join("current-desktop.png")
    }
}

#[cfg(target_os = "macos")]
impl Drop for SnapshotStaging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn capture_current_desktop_png() -> Result<Vec<u8>, SatelleError> {
    let captured = capture_platform_png()?;
    redact_png_metadata(&captured)
}

#[cfg(target_os = "macos")]
fn capture_platform_png() -> Result<Vec<u8>, SatelleError> {
    #[link(name = "ApplicationServices", kind = "framework")]
    unsafe extern "C" {
        fn CGPreflightScreenCaptureAccess() -> bool;
    }

    // This API only reads the current Screen Recording grant. It does not show
    // a permission dialog or mutate the user's privacy settings.
    if !unsafe { CGPreflightScreenCaptureAccess() } {
        return Err(SatelleError::desktop_snapshot_permission_required(
            "screen_recording_permission_denied",
        ));
    }
    let staging = SnapshotStaging::create()?;
    let path = staging.image_path();
    let status = std::process::Command::new("/usr/sbin/screencapture")
        .args(["-x", "-t", "png"])
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| {
            SatelleError::desktop_snapshot_permission_required("capture_runtime_unavailable")
        })?;
    if !status.success() {
        return Err(SatelleError::desktop_snapshot_permission_required(
            "screen_capture_failed",
        ));
    }
    read_bounded(&path)
}

#[cfg(windows)]
fn capture_platform_png() -> Result<Vec<u8>, SatelleError> {
    use windows_sys::Win32::Graphics::Gdi::{
        BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CAPTUREBLT, CreateCompatibleBitmap,
        CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject, GetDC, GetDIBits, HGDIOBJ,
        ReleaseDC, SRCCOPY, SelectObject,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN,
    };

    struct GdiCapture {
        screen: windows_sys::Win32::Graphics::Gdi::HDC,
        memory: windows_sys::Win32::Graphics::Gdi::HDC,
        bitmap: windows_sys::Win32::Graphics::Gdi::HBITMAP,
        previous: HGDIOBJ,
    }

    impl Drop for GdiCapture {
        fn drop(&mut self) {
            unsafe {
                if !self.memory.is_null() && !self.previous.is_null() {
                    SelectObject(self.memory, self.previous);
                }
                if !self.bitmap.is_null() {
                    DeleteObject(self.bitmap);
                }
                if !self.memory.is_null() {
                    DeleteDC(self.memory);
                }
                if !self.screen.is_null() {
                    ReleaseDC(std::ptr::null_mut(), self.screen);
                }
            }
        }
    }

    let x = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    let y = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    if width <= 0 || height <= 0 {
        return Err(SatelleError::desktop_snapshot_permission_required(
            "visible_desktop_unavailable",
        ));
    }
    let screen = unsafe { GetDC(std::ptr::null_mut()) };
    let memory = unsafe { CreateCompatibleDC(screen) };
    let bitmap = unsafe { CreateCompatibleBitmap(screen, width, height) };
    if screen.is_null() || memory.is_null() || bitmap.is_null() {
        let _cleanup = GdiCapture {
            screen,
            memory,
            bitmap,
            previous: std::ptr::null_mut(),
        };
        return Err(SatelleError::desktop_snapshot_permission_required(
            "screen_capture_unavailable",
        ));
    }
    let previous = unsafe { SelectObject(memory, bitmap) };
    let capture = GdiCapture {
        screen,
        memory,
        bitmap,
        previous,
    };
    if capture.previous.is_null() {
        return Err(SatelleError::desktop_snapshot_permission_required(
            "screen_capture_unavailable",
        ));
    }
    if unsafe {
        BitBlt(
            memory,
            0,
            0,
            width,
            height,
            screen,
            x,
            y,
            SRCCOPY | CAPTUREBLT,
        )
    } == 0
    {
        return Err(SatelleError::desktop_snapshot_permission_required(
            "screen_capture_failed",
        ));
    }

    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|width| width.checked_mul(4))
        .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?;
    let byte_count = row_bytes
        .checked_mul(usize::try_from(height).unwrap_or(usize::MAX))
        .filter(|size| *size <= MAX_DESKTOP_SNAPSHOT_BYTES * 4)
        .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?;
    let mut pixels = vec![0_u8; byte_count];
    let mut info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB,
            ..unsafe { std::mem::zeroed() }
        },
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe {
        GetDIBits(
            capture.memory,
            capture.bitmap,
            0,
            height as u32,
            pixels.as_mut_ptr().cast(),
            &raw mut info,
            DIB_RGB_COLORS,
        )
    } == 0
    {
        return Err(SatelleError::desktop_snapshot_permission_required(
            "screen_pixels_unavailable",
        ));
    }
    encode_bgra_png(width as u32, height as u32, &pixels)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn capture_platform_png() -> Result<Vec<u8>, SatelleError> {
    Err(SatelleError::desktop_snapshot_permission_required(
        "native_platform_unsupported",
    ))
}

#[cfg(target_os = "macos")]
fn read_bounded(path: &Path) -> Result<Vec<u8>, SatelleError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        SatelleError::desktop_snapshot_permission_required("capture_artifact_unavailable")
    })?;
    if !metadata.file_type().is_file()
        || usize::try_from(metadata.len())
            .ok()
            .is_none_or(|size| size > MAX_DESKTOP_SNAPSHOT_BYTES)
    {
        return Err(SatelleError::desktop_snapshot_redaction_failed());
    }
    std::fs::read(path).map_err(|_| SatelleError::desktop_snapshot_redaction_failed())
}

#[cfg(windows)]
fn encode_bgra_png(width: u32, height: u32, bgra: &[u8]) -> Result<Vec<u8>, SatelleError> {
    let width =
        usize::try_from(width).map_err(|_| SatelleError::desktop_snapshot_redaction_failed())?;
    let height =
        usize::try_from(height).map_err(|_| SatelleError::desktop_snapshot_redaction_failed())?;
    let expected = width
        .checked_mul(height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?;
    if bgra.len() != expected {
        return Err(SatelleError::desktop_snapshot_redaction_failed());
    }
    let row_size = width
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?;
    let mut raw = Vec::with_capacity(
        row_size
            .checked_mul(height)
            .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?,
    );
    for row in bgra.chunks_exact(width * 4) {
        raw.push(0);
        for pixel in row.chunks_exact(4) {
            raw.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
        }
    }
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(&raw)
        .map_err(|_| SatelleError::desktop_snapshot_redaction_failed())?;
    let compressed = encoder
        .finish()
        .map_err(|_| SatelleError::desktop_snapshot_redaction_failed())?;
    let mut png = PNG_SIGNATURE.to_vec();
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&(width as u32).to_be_bytes());
    header.extend_from_slice(&(height as u32).to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    append_chunk(&mut png, *b"IHDR", &header)?;
    append_chunk(&mut png, *b"IDAT", &compressed)?;
    append_chunk(&mut png, *b"IEND", &[])?;
    (png.len() <= MAX_DESKTOP_SNAPSHOT_BYTES)
        .then_some(png)
        .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)
}

fn redact_png_metadata(input: &[u8]) -> Result<Vec<u8>, SatelleError> {
    if input.len() > MAX_DESKTOP_SNAPSHOT_BYTES || !input.starts_with(PNG_SIGNATURE) {
        return Err(SatelleError::desktop_snapshot_redaction_failed());
    }
    let mut output = PNG_SIGNATURE.to_vec();
    let mut offset = PNG_SIGNATURE.len();
    let mut saw_header = false;
    let mut saw_data = false;
    let mut saw_end = false;
    while offset < input.len() {
        let prefix = input
            .get(offset..offset + 8)
            .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?;
        let length = usize::try_from(u32::from_be_bytes(prefix[..4].try_into().unwrap()))
            .map_err(|_| SatelleError::desktop_snapshot_redaction_failed())?;
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(length))
            .filter(|end| *end <= input.len())
            .ok_or_else(SatelleError::desktop_snapshot_redaction_failed)?;
        let chunk_type: [u8; 4] = prefix[4..8].try_into().unwrap();
        let chunk = &input[offset..end];
        let expected_crc = u32::from_be_bytes(chunk[end - offset - 4..].try_into().unwrap());
        if png_crc32(&chunk[4..chunk.len() - 4]) != expected_crc {
            return Err(SatelleError::desktop_snapshot_redaction_failed());
        }
        match &chunk_type {
            b"IHDR" if !saw_header && offset == PNG_SIGNATURE.len() && length == 13 => {
                saw_header = true;
                output.extend_from_slice(chunk);
            }
            b"PLTE" if saw_header && !saw_data && !saw_end => output.extend_from_slice(chunk),
            b"IDAT" if saw_header && !saw_end => {
                saw_data = true;
                output.extend_from_slice(chunk);
            }
            b"IEND" if saw_header && saw_data && !saw_end && length == 0 => {
                saw_end = true;
                output.extend_from_slice(chunk);
            }
            _ if chunk_type[0].is_ascii_lowercase() && saw_header && !saw_end => {}
            _ => return Err(SatelleError::desktop_snapshot_redaction_failed()),
        }
        offset = end;
    }
    if !saw_end || offset != input.len() {
        return Err(SatelleError::desktop_snapshot_redaction_failed());
    }
    Ok(output)
}

#[cfg(windows)]
fn append_chunk(
    output: &mut Vec<u8>,
    chunk_type: [u8; 4],
    contents: &[u8],
) -> Result<(), SatelleError> {
    let length = u32::try_from(contents.len())
        .map_err(|_| SatelleError::desktop_snapshot_redaction_failed())?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(&chunk_type);
    output.extend_from_slice(contents);
    let start = output.len() - contents.len() - chunk_type.len();
    output.extend_from_slice(&png_crc32(&output[start..]).to_be_bytes());
    Ok(())
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_removes_ancillary_png_chunks() {
        let mut input = PNG_SIGNATURE.to_vec();
        append_test_chunk(
            &mut input,
            *b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
        );
        append_test_chunk(&mut input, *b"tEXt", b"private metadata");
        append_test_chunk(&mut input, *b"IDAT", &[1, 2, 3]);
        append_test_chunk(&mut input, *b"IEND", &[]);

        let redacted = redact_png_metadata(&input).unwrap();

        assert!(!redacted.windows(4).any(|window| window == b"tEXt"));
        assert!(redacted.windows(4).any(|window| window == b"IDAT"));
    }

    #[test]
    fn redaction_rejects_corrupt_and_unknown_critical_chunks() {
        let mut corrupt = PNG_SIGNATURE.to_vec();
        append_test_chunk(
            &mut corrupt,
            *b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
        );
        append_test_chunk(&mut corrupt, *b"IDAT", &[1, 2, 3]);
        append_test_chunk(&mut corrupt, *b"IEND", &[]);
        *corrupt.last_mut().expect("IEND CRC") ^= 1;
        assert!(redact_png_metadata(&corrupt).is_err());

        let mut unknown = PNG_SIGNATURE.to_vec();
        append_test_chunk(
            &mut unknown,
            *b"IHDR",
            &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
        );
        append_test_chunk(&mut unknown, *b"ABCD", &[]);
        append_test_chunk(&mut unknown, *b"IDAT", &[1, 2, 3]);
        append_test_chunk(&mut unknown, *b"IEND", &[]);
        assert!(redact_png_metadata(&unknown).is_err());
    }

    fn append_test_chunk(output: &mut Vec<u8>, chunk_type: [u8; 4], contents: &[u8]) {
        output.extend_from_slice(&(contents.len() as u32).to_be_bytes());
        output.extend_from_slice(&chunk_type);
        output.extend_from_slice(contents);
        let start = output.len() - contents.len() - chunk_type.len();
        output.extend_from_slice(&png_crc32(&output[start..]).to_be_bytes());
    }
}
