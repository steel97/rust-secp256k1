
extern crate bitcoin_hashes;
extern crate secp256k1;
extern crate secp256k1_sys;

use std::env;

use bitcoin_hashes::{sha256, Hash};
use secp256k1_sys::{
    secp256k1_context_no_precomp, secp256k1_context_preallocated_create,
    secp256k1_context_preallocated_size, secp256k1_context_randomize, secp256k1_ec_pubkey_combine,
    secp256k1_ec_pubkey_create, secp256k1_ec_pubkey_parse, secp256k1_ec_pubkey_serialize,
    secp256k1_ec_pubkey_tweak_add, secp256k1_ec_pubkey_tweak_mul, secp256k1_ec_seckey_negate,
    secp256k1_ec_seckey_tweak_add, secp256k1_ecdsa_sign, secp256k1_ecdsa_signature_normalize,
    secp256k1_ecdsa_signature_parse_compact, secp256k1_ecdsa_signature_serialize_compact,
    secp256k1_ecdsa_verify, secp256k1_keypair_create, secp256k1_keypair_xonly_pub,
    secp256k1_nonce_function_bip340, secp256k1_nonce_function_rfc6979, secp256k1_schnorrsig_sign,
    secp256k1_schnorrsig_verify, secp256k1_xonly_pubkey_from_pubkey, secp256k1_xonly_pubkey_parse,
    secp256k1_xonly_pubkey_serialize, secp256k1_xonly_pubkey_tweak_add,
    secp256k1_xonly_pubkey_tweak_add_check, types::c_void, Context, KeyPair, Signature,
    XOnlyPublicKey, SECP256K1_SER_COMPRESSED, SECP256K1_SER_UNCOMPRESSED, SECP256K1_START_SIGN,
    SECP256K1_START_VERIFY,
    secp256k1_get_keyimage
};

/*use secp256k1_sys::recovery::{
    secp256k1_ecdsa_recover, secp256k1_ecdsa_recoverable_signature_parse_compact,
    secp256k1_ecdsa_recoverable_signature_serialize_compact, secp256k1_ecdsa_sign_recoverable,
    RecoverableSignature,
};*/

use secp256k1::{Error, Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

#[allow(clippy::large_stack_arrays)]
static CONTEXT_BUFFER: [u8; 1_114_336] = [0; 1_114_336];//1_114_320 1_114_326
static mut CONTEXT_SEED: [u8; 32] = [0; 32];

fn initialize_context_seed() {
    //use rand::Rng;
    //let mut rng = rand::thread_rng();
    let n2: u32 = 0x59376f1;//rng.gen::<u32>();

    unsafe {
        for offset in (0..8).map(|v| v * 4) {
            let value = n2;
            let bytes: [u8; 4] = value.to_ne_bytes();
            CONTEXT_SEED[offset..offset + 4].copy_from_slice(&bytes);
        }
    }
}

fn get_context() -> *const Context {
    static mut CONTEXT: *const Context = core::ptr::null();
    unsafe {
        if CONTEXT_SEED[0] == 0 {
            //println!("asdf {}", SECP256K1_START_SIGN | SECP256K1_START_VERIFY);
            let x = ((1 |(1<<9)) | (1 | (1<<8)));
            println!("asdf {}", x);
            let size =
                secp256k1_context_preallocated_size(x);
            assert_eq!(size, CONTEXT_BUFFER.len());
            let ctx = secp256k1_context_preallocated_create(
                CONTEXT_BUFFER.as_ptr() as *mut c_void,
                SECP256K1_START_SIGN | SECP256K1_START_VERIFY,
            );
            println!("asdf {}", x);
            initialize_context_seed();
            println!("asdf {}", x);
            let retcode = secp256k1_context_randomize(ctx, CONTEXT_SEED.as_ptr());
            println!("asdf {}", x);
            CONTEXT_SEED[0] = 1;
            CONTEXT_SEED[1..].fill(0);
            assert_eq!(retcode, 1);
            CONTEXT = ctx;
        }
        CONTEXT
    }
}
fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    unsafe {
    let secp = Secp256k1::new();

    let mut seckey = [
        59, 148, 11, 85, 134, 130, 61, 253, 2, 174, 59, 70, 27, 180, 51, 107,
        94, 203, 174, 253, 102, 39, 170, 146, 46, 252, 4, 143, 236, 12, 136, 28,
    ];
    /*let pubkey = PublicKey::from_slice(&[
        2,
        29, 21, 35, 7, 198, 183, 43, 14, 208, 65, 139, 14, 112, 205, 128, 231,
        245, 41, 91, 141, 134, 245, 114, 45, 63, 82, 19, 251, 210, 57, 79, 54,
    ]).unwrap();*/
    let msg = b"This is some message";

    //let res = secp256k1_get_keyimage(get_context(), ki, pk, sk);
    println!("hello there! 1");
    get_context();
    println!("hello there! 2");
    let res = secp256k1_get_keyimage(get_context(), seckey.as_mut_ptr(), seckey.as_mut_ptr(), seckey.as_mut_ptr());
    println!("hello there!");
    }
}
