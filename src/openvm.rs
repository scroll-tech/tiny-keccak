use alloc::vec::Vec;
use core::mem::MaybeUninit;
use crate::Hasher;

/// This is custom-0 defined in RISC-V spec document
pub const OPCODE: u8 = 0x0b;
pub const FUNCT3: u8 = 0b100;

/// The `Keccak` hash functions defined in [`Keccak SHA3 submission`].
#[derive(Clone)]
pub struct Keccak {
    input: Vec<u8>,
}

impl Keccak {
    /// Creates  new [`Keccak`] hasher with a security level of 256 bits.
    ///
    /// [`Keccak`]: struct.Keccak.html
    pub fn v256() -> Keccak {
        Keccak {
            input: Vec::with_capacity(1024),
        }
    }
}

impl Hasher for Keccak {
    fn update(&mut self, input: &[u8]) {
        self.input.extend_from_slice(input);
    }

    fn finalize(self, output: &mut [u8]) {
        native_keccak256(self.input.as_ptr(), self.input.len(), output.as_mut_ptr() as *mut u8);
    }
}

/// Copied from https://github.com/openvm-org/openvm/blob/31c5b18f9f69860a2284efba7dbd2e47966471b8/extensions/keccak256/guest/src/lib.rs#L27-L44
/// Native hook for keccak256.
///
/// # Safety
///
/// The VM accepts the preimage by pointer and length, and writes the
/// 32-byte hash.
/// - `bytes` must point to an input buffer at least `len` long.
/// - `output` must point to a buffer that is at least 32-bytes long.
///
/// [`keccak256`]: https://en.wikipedia.org/wiki/SHA-3
/// [`sha3`]: https://docs.rs/sha3/latest/sha3/
/// [`tiny_keccak`]: https://docs.rs/tiny-keccak/latest/tiny_keccak/
#[inline(always)]
#[no_mangle]
extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    openvm_platform::custom_insn_r!(OPCODE, FUNCT3, 0x0, output, bytes, len);
}