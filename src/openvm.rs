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
        unsafe {
            native_keccak256(self.input.as_ptr(), self.input.len(), output.as_mut_ptr() as *mut u8);
        }
    }
}

extern "C" {
    #[no_mangle]
    fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8);
}