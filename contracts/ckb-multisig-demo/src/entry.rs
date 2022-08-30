// Import from `core` instead of from `std` since we are in no-std mode
use core::{convert::TryInto, result::Result};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::WitnessArgs, prelude::*},
    debug,
    error::SysError,
    high_level::{load_input_since, load_script, load_tx_hash, load_witness_args, QueryIter},
};

use crate::error::Error;

use blake2b_ref::Blake2bBuilder;

const BLAKE160_SIZE: usize = 20;
const U64_SIZE: usize = 8;
const FLAGS_SIZE: usize = 4;
const SIGNATURE_SIZE: usize = 65;
const BLAKE2B_BLOCK_SIZE: usize = 32;
const CKB_HASH_PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    debug!("script args is {:?}", args);

    if args.len() != BLAKE160_SIZE && args.len() != BLAKE160_SIZE + U64_SIZE {
        return Err(Error::ArgumentsLen);
    }
    let since = if args.len() == BLAKE160_SIZE + U64_SIZE {
        u64::from_le_bytes(args[BLAKE160_SIZE..BLAKE160_SIZE + 8].try_into().unwrap())
    } else {
        0
    };

    let witness = load_witness_args(0, Source::GroupInput)?;
    let lock_bytes = {
        let lock_opt = witness.lock();
        if lock_opt.is_none() {
            return Err(Error::WitnessSize);
        }
        let lock_bytes = lock_opt.to_opt().unwrap().raw_data();
        if lock_bytes.len() < FLAGS_SIZE {
            return Err(Error::WitnessSize);
        }
        lock_bytes
    };

    if lock_bytes[0] != 0u8 {
        return Err(Error::InvalidReserveField);
    }
    let require_first_n: u8 = lock_bytes[1];

    let threshold = lock_bytes[2];
    if threshold == 0 {
        return Err(Error::InvalidThreshold);
    }
    let pubkeys_cnt: u8 = lock_bytes[3];
    if pubkeys_cnt == 0 {
        return Err(Error::InvalidPubkeysCnt);
    }
    if threshold > pubkeys_cnt {
        return Err(Error::InvalidThreshold);
    }
    if require_first_n > threshold {
        return Err(Error::InvalidRequireFirstN);
    }

    let multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * usize::from(pubkeys_cnt);
    let signatures_len = SIGNATURE_SIZE * usize::from(threshold);
    let required_lock_len = multisig_script_len + signatures_len;
    if lock_bytes.len() != required_lock_len {
        return Err(Error::WitnessSize);
    }

    {
        // check multisig args hash
        let mut tmp = [0; BLAKE2B_BLOCK_SIZE];
        let mut blake2b = Blake2bBuilder::new(BLAKE2B_BLOCK_SIZE)
            .personal(CKB_HASH_PERSONALIZATION)
            .build();
        blake2b.update(&lock_bytes[0..multisig_script_len]);
        blake2b.finalize(&mut tmp);

        if &args.as_ref()[0..BLAKE160_SIZE] != &tmp[0..BLAKE160_SIZE] {
            return Err(Error::MultsigScriptHash);
        }
    }
    check_since(since)?;

    let message = {
        let mut blake2b = Blake2bBuilder::new(BLAKE2B_BLOCK_SIZE)
            .personal(CKB_HASH_PERSONALIZATION)
            .build();
        blake2b.update(&load_tx_hash()?);
        blake2b.update(&(witness.total_size() as u64).to_le_bytes());

        {
            let mut zero_lock = lock_bytes.to_vec();
            zero_lock[multisig_script_len..multisig_script_len + signatures_len].fill(0);
            let init_witness = WitnessArgs::from_slice(witness.as_slice())
                .unwrap()
                .as_builder()
                .lock(Some(Bytes::from(zero_lock)).pack())
                .build();
            blake2b.update(init_witness.as_slice());
        }

        QueryIter::new(load_witness_args, Source::GroupInput)
            .skip(1)
            .for_each(|data| {
                blake2b.update(&(data.total_size() as u64).to_le_bytes());
                blake2b.update(data.as_slice());
            });
        // For safety consideration, this lock script will also hash and guard all witnesses that
        // have index values equal to or larger than the number of input cells. It assumes all
        // witnesses that do have an input cell with the same index, will be guarded by the lock
        // script of the input cell.
        //
        // For convenience reason, we provide a utility function here to calculate the number of
        // input cells in a transaction
        let i = calculate_inputs_len();
        QueryIter::new(load_witness_args, Source::Input)
            .skip(i)
            .for_each(|data| {
                blake2b.update(&(data.total_size() as u64).to_le_bytes());
                blake2b.update(data.as_slice());
            });
        let mut tmp = [0; BLAKE2B_BLOCK_SIZE];
        blake2b.finalize(&mut tmp);
        tmp
    };

    crate::secp256k1_helper::validate_secp256k1_multisignautre(
        require_first_n,
        threshold,
        pubkeys_cnt,
        &message,
        &(*lock_bytes),
        multisig_script_len,
    )
}

/* calculate inputs length */
fn calculate_inputs_len() -> usize {
    /* lower bound, at least tx has one input */
    let mut lo = 0;
    /* higher bound */
    let mut hi = 4;
    /* try to load input until failing to increase lo and hi */
    loop {
        if let Ok(_since) = load_input_since(hi, Source::Input) {
            lo = hi;
            hi *= 2;
        } else {
            break;
        }
    }

    /* now we get our lower bound and higher bound,
    count number of inputs by binary search */
    while lo + 1 != hi {
        let i = (lo + hi) / 2;
        if let Ok(_since) = load_input_since(i, Source::Input) {
            lo = i;
        } else {
            hi = i;
        }
    }
    /* now lo is last input index and hi is length of inputs */
    hi
}

fn check_since(since: u64) -> Result<(), Error> {
    const SINCE_VALUE_BITS: usize = 56;
    const SINCE_VALUE_MASK: u64 = 0x00ffffffffffffff;
    const SINCE_EPOCH_FRACTION_FLAG: u64 = 0b00100000;

    let since_flags = since >> SINCE_VALUE_BITS;
    let since_value = since & SINCE_VALUE_MASK;

    for i in 0.. {
        match load_input_since(i, Source::GroupInput) {
            Ok(input_since) => {
                let input_since_flags = input_since >> SINCE_VALUE_BITS;
                let input_since_value = input_since & SINCE_VALUE_MASK;
                if since_flags != input_since_flags {
                    return Err(Error::IncorrectSinceFlags);
                } else if input_since_flags == SINCE_EPOCH_FRACTION_FLAG {
                    let ret = epoch_number_with_fraction_cmp(input_since_value, since_value);
                    if ret < 0 {
                        return Err(Error::IncorrectSinceValue);
                    }
                } else if input_since_value < since_value {
                    return Err(Error::IncorrectSinceValue);
                }
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };
    }
    Ok(())
}

/* a and b are since value,
return 0 if a is equals to b,
return -1 if a is less than b,
return 1 if a is greater than b */
fn epoch_number_with_fraction_cmp(a: u64, b: u64) -> i32 {
    let number_offset = 0;
    let number_bits = 24;
    let number_maximum_value = 1 << number_bits;
    let number_mask = number_maximum_value - 1;
    let index_offset = number_bits;
    let index_bits = 16;
    let index_maximum_value = 1 << index_bits;
    let index_mask = index_maximum_value - 1;
    let length_offset = number_bits + index_bits;
    let length_bits = 16;
    let length_maximum_value = 1 << length_bits;
    let length_mask = length_maximum_value - 1;

    /* extract a epoch */
    let a_epoch = (a >> number_offset) & number_mask;
    let a_index = (a >> index_offset) & index_mask;
    let a_len = (a >> length_offset) & length_mask;

    /* extract b epoch */
    let b_epoch = (b >> number_offset) & number_mask;
    let b_index = (b >> index_offset) & index_mask;
    let b_len = (b >> length_offset) & length_mask;

    if a_epoch < b_epoch {
        return -1;
    } else if a_epoch > b_epoch {
        return 1;
    } else {
        /* a and b is in the same epoch,
          compare a_index / a_len <=> b_index / b_len
        */
        let a_block = a_index * b_len;
        let b_block = b_index * a_len;
        /* compare block */
        if a_block < b_block {
            return -1;
        } else if a_block > b_block {
            return 1;
        } else {
            return 0;
        }
    }
}
