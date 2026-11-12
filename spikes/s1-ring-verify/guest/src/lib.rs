//! Throwaway spike: the module measured inside wasmtime.

use ed25519_dalek::{Signature, VerifyingKey};

#[no_mangle]
pub extern "C" fn alloc(len: u32) -> *mut u8 {
    let mut buffer = Vec::<u8>::with_capacity(len as usize);
    let pointer = buffer.as_mut_ptr();
    core::mem::forget(buffer);
    pointer
}

/// # Safety
/// `pointer` must come from `alloc` with at least `len` bytes written.
#[no_mangle]
pub unsafe extern "C" fn ring_verify(pointer: *const u8, len: u32) -> i32 {
    let input = core::slice::from_raw_parts(pointer, len as usize);
    lsag::verify_encoded(input) as i32
}

/// Input layout: 32-byte key, 64-byte signature, message.
///
/// # Safety
/// `pointer` must come from `alloc` with at least `len` bytes written.
#[no_mangle]
pub unsafe extern "C" fn ed25519_verify(pointer: *const u8, len: u32) -> i32 {
    let input = core::slice::from_raw_parts(pointer, len as usize);
    if input.len() < 96 {
        return 0;
    }
    let Ok(key) = VerifyingKey::from_bytes(input[..32].try_into().unwrap()) else {
        return 0;
    };
    let signature = Signature::from_bytes(input[32..96].try_into().unwrap());
    key.verify_strict(&input[96..], &signature).is_ok() as i32
}
