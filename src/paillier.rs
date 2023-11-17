// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

use crate::{
    parameters::PRIME_BITS,
    utils::{modpow, random_bn_in_z_star, CRYPTOGRAPHIC_RETRY_MAX},
};
use libpaillier::unknown_order::BigNumber;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use thiserror::Error;
use tracing::error;
use zeroize::ZeroizeOnDrop;

#[cfg(test)]
use crate::utils::random_positive_bn;

/// The default Result type used in this crate
pub type Result<T> = std::result::Result<T, PaillierError>;

/// Paillier-specific errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PaillierError {
    #[error("Failed to create a Paillier decryption key from inputs")]
    CouldNotCreateKey,
    #[error("The inputs to a homomorphic operation on a Paillier ciphertext were malformed")]
    InvalidOperation,
    #[error("The attemped decryption of a Pailler ciphertext failed")]
    DecryptionFailed,
    #[error(
        "Cannot encrypt out-of-range value; x must be in the group of integers mod n. Got {x}, {n}"
    )]
    EncryptionFailed { x: BigNumber, n: BigNumber },
    #[error("The provided RNG failed to produce suitable values after a maximum number of attempts. Please check the RNG.")]
    RetryFailed,

    #[cfg(test)]
    #[error("No pre-generated primes with size {0}")]
    NoPregeneratedPrimes(usize),
}

/// A nonce generated as part of [`EncryptionKey::encrypt()`].
/// A nonce is drawn from the multiplicative group of integers modulo `n`, where
/// `n` is the modulus from the associated [`EncryptionKey`].
#[derive(Clone, Serialize, Deserialize, PartialEq, ZeroizeOnDrop)]
pub(crate) struct Nonce(BigNumber);
impl Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Nonce([redacted])")
    }
}

#[cfg(test)]
impl Nonce {
    /// Generate a random `Nonce` for testing only!
    pub(crate) fn random<R: CryptoRng + RngCore>(rng: &mut R, modulus: &BigNumber) -> Self {
        Nonce(random_positive_bn(rng, modulus))
    }
}

/// A masked version of [`Nonce`] produced by [`EncryptionKey::mask()`].
#[derive(Clone, Serialize, Deserialize, PartialEq, ZeroizeOnDrop)]
pub(crate) struct MaskedNonce(BigNumber);

impl Debug for MaskedNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MaskedNonce([redacted])")
    }
}

#[cfg(test)]
impl MaskedNonce {
    /// Generate a random `MaskedNonce` for testing only!
    pub(crate) fn random<R: CryptoRng + RngCore>(rng: &mut R, modulus: &BigNumber) -> Self {
        MaskedNonce(random_positive_bn(rng, modulus))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct Ciphertext(BigNumber);

impl Ciphertext {
    /// Converts a [`Ciphertext`] into its big-endian byte representation.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct EncryptionKey(libpaillier::EncryptionKey);

// This is stupid and should have been derived by the underlying crate.
impl PartialEq for EncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.n() == other.0.n() && self.0.nn() == other.0.nn()
    }
}
impl Eq for EncryptionKey {}

impl EncryptionKey {
    /// Return this [`EncryptionKey`]s modulus.
    pub(crate) fn modulus(&self) -> &BigNumber {
        self.0.n()
    }

    /// Compute the floor of `n/2` for the modulus `n`.
    ///
    /// Since `n` is the product of two primes, it'll be odd, so we
    /// can do this to make sure we get the actual floor. BigNumber division
    /// doesn't document whether it truncates or rounds for integer
    /// division.
    fn half_n(&self) -> BigNumber {
        (self.0.n() - 1) / 2
    }

    /// Encrypt plaintext `x` under the encryption key, returning the resulting
    /// [`Ciphertext`] and [`Nonce`].
    ///
    /// The plaintext must be an element of the integers mod `N`, where `N` is
    /// the modulus defined by the [`EncryptionKey`]. The expected format
    /// for these is the range `[-N/2, N/2]`. Encryption will fail if `x` is
    /// outside this range.
    pub(crate) fn encrypt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        x: &BigNumber,
    ) -> Result<(Ciphertext, Nonce)> {
        // Note: the check that `x` is in the proper range happens in
        // `encrypt_with_nonce`.
        let nonce =
            random_bn_in_z_star(rng, self.modulus()).map_err(|_| PaillierError::RetryFailed)?;
        let c = self.encrypt_with_nonce(x, &MaskedNonce(nonce.clone()))?;
        Ok((c, Nonce(nonce)))
    }

    /// Encrypt plaintext `x` using the provided [`MaskedNonce`], producing a
    /// [`Ciphertext`].
    ///
    /// The plaintext must be an element of the integers mod `N`, where `N` is
    /// the modulus defined by the [`EncryptionKey`]. The expected format
    /// for these is the range `[-N/2, N/2]`. Encryption will fail if `x` is
    /// outside this range.
    pub(crate) fn encrypt_with_nonce(
        &self,
        x: &BigNumber,
        nonce: &MaskedNonce,
    ) -> Result<Ciphertext> {
        if &self.half_n() < x || x < &-self.half_n() {
            Err(PaillierError::EncryptionFailed {
                x: x.clone(),
                n: self.modulus().clone(),
            })?
        }

        // We implement encryption ourselves instead of using libpaillier's `encrypt`
        // method because that method requires the plaintext to be in the
        // canonical range `[0, N)` instead of in our range around 0. It seemed
        // less confusing to implement encryption directly than to try to move
        // the plaintext to the canonical range.
        let one = BigNumber::one();
        let base = one + self.modulus();
        let a = base.modpow(x, self.0.nn());
        let b = nonce.0.modpow(self.modulus(), self.0.nn());
        let c = a.modmul(&b, self.0.nn());
        Ok(Ciphertext(c))
    }

    #[cfg(test)]
    /// Generate a random ciphertext for testing purposes.
    pub(crate) fn random_ciphertext(&self, rng: &mut (impl RngCore + CryptoRng)) -> Ciphertext {
        Ciphertext(random_positive_bn(rng, self.0.nn()))
    }

    /// Masks a [`Nonce`] `nonce` with another [`Nonce`] `mask` and exponent `e`
    /// for use in proving properties of `nonce`'s corresponding ciphertext.
    /// Both `nonce` and `mask` MUST have been generated by the given
    /// [`EncryptionKey`].
    ///
    /// The resulting [`MaskedNonce`] is computed as `mask * nonce^e mod N`,
    /// where `N` is the modulus of [`EncryptionKey`].
    pub(crate) fn mask(&self, nonce: &Nonce, mask: &Nonce, e: &BigNumber) -> MaskedNonce {
        MaskedNonce(
            mask.0
                .modmul(&modpow(&nonce.0, e, self.modulus()), self.modulus()),
        )
    }

    /// Computes `a ⊙ c1 ⊕ c2` homomorphically over [`Ciphertext`]s `c1` and
    /// `c2`.
    pub(crate) fn multiply_and_add(
        &self,
        a: &BigNumber,
        c1: &Ciphertext,
        c2: &Ciphertext,
    ) -> Result<Ciphertext> {
        // Ciphertext addition is modular multiplication, and ciphertext multiplication
        // is modular exponentiation.
        //
        // Note: We do not use `libpaillier::EncryptionKey::mul`
        // because it does a check that `0 < a < N`. However, the `a` passed in is
        // usually in the range `-N/2 <= a <= N/2` so could fail that check.
        // Instead, we do the operations directly and manually do the range
        // check.
        if &self.half_n() < a || a < &-self.half_n() {
            Err(PaillierError::InvalidOperation)?
        } else {
            Ok(Ciphertext(
                modpow(&c1.0, a, self.0.nn()).modmul(&c2.0, self.0.nn()),
            ))
        }
    }
}

#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct DecryptionKey(libpaillier::DecryptionKey);

impl Debug for DecryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecryptionKey([redacted])")
    }
}

impl PartialEq for DecryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.n() == other.0.n()
            && self.0.totient() == other.0.totient()
            && self.0.lambda() == other.0.lambda()
            && self.0.u() == other.0.u()
    }
}
impl Eq for DecryptionKey {}

impl DecryptionKey {
    /// Compute the floor of `n/2` for the modulus `n`.
    ///
    /// Since `n` is the product of two primes, it'll be odd, so we
    /// can do this to make sure we get the actual floor. BigNumber division
    /// doesn't document whether it truncates or rounds for integer
    /// division.
    fn half_n(&self) -> BigNumber {
        (self.0.n() - 1) / 2
    }

    pub(crate) fn decrypt(&self, c: &Ciphertext) -> Result<BigNumber> {
        let mut x = self
            .0
            .decrypt(&c.0)
            .ok_or(PaillierError::DecryptionFailed)
            .map(BigNumber::from_slice)?;

        // Switch representation into `[-N/2, N/2]`. libpaillier (and indeed,
        // `BigNumber`s in general) returns values represented in the canonical
        // range `[0, N)`. A single subtraction will land us in the expected
        // range for this application.
        if x > self.half_n() {
            x -= self.0.n();
        }

        Ok(x)
    }

    /// Generate a new [`DecryptionKey`] and its factors.
    ///
    /// The factors `p` and `q` are `PRIME_BITS`-long safe primes, and the
    /// resulting modulus is `2 * PRIME_BITS` long.
    pub(crate) fn new(
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Self, BigNumber, BigNumber)> {
        // Generate a pair of safe primes that are `PRIME_BITS` long and return them if
        // their product is `2 * PRIME_BITS` long (otherwise return `None`).
        let generate_prime_pair = || -> Result<(BigNumber, BigNumber)> {
            // As generating safe primes can be computationally expensive (> one minute per
            // prime in github CI), we read precomputed ones from a file (but
            // only in tests!)
            #[cfg(not(test))]
            let (p, q) = (
                prime_gen::get_random_safe_prime(rng),
                prime_gen::get_random_safe_prime(rng),
            );
            #[cfg(test)]
            let (p, q) = prime_gen::get_prime_pair_from_pool_insecure(rng)?;

            if p.bit_length() == PRIME_BITS
                && q.bit_length() == PRIME_BITS
                && (&p * &q).bit_length() == 2 * PRIME_BITS
            {
                Ok((p, q))
            } else {
                Err(PaillierError::CouldNotCreateKey)?
            }
        };

        // A Paillier decryption key is the product of the two primes, but sometimes two
        // n/2-bit primes can produce an n-1 bit modulus. Allow some (lazily
        // evaluated) retries to handle that error.
        let (p, q) = std::iter::repeat_with(generate_prime_pair)
            .take(CRYPTOGRAPHIC_RETRY_MAX)
            .find(|result| result.is_ok())
            // We hit the maximum number of retries without getting an acceptable pair.
            // We should never hit the second `?` unless `find` breaks.
            .ok_or(PaillierError::RetryFailed)??;

        let decryption_key = DecryptionKey(
            libpaillier::DecryptionKey::with_primes(&p, &q)
                .ok_or(PaillierError::CouldNotCreateKey)?,
        );

        // Double check that the modulus is the correct size.
        if decryption_key.0.n().bit_length() == 2 * PRIME_BITS {
            Ok((decryption_key, p, q))
        } else {
            Err(PaillierError::CouldNotCreateKey)?
        }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        // Note: the libpaillier crate just serializes the four fields; it doesn't
        // do any length prepending or other misuse-resistant things.
        self.0.to_bytes()
    }

    pub(crate) fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        // Convert bytes to libpaillier::DecryptionKey
        // This method does not validate the key for consistency
        let decryption_key = libpaillier::DecryptionKey::from_bytes(bytes).map_err(|err| {
            error!("Failed to deserialize decryption key: {}", err);
            PaillierError::CouldNotCreateKey
        })?;

        // Validate key itself (ideally, this would be checked by the above `from_bytes`
        // method)
        // Note: this isn't tested because we can't form a bad decryption key without
        // access to the libpaillier internals.
        if decryption_key.n().gcd(decryption_key.totient()) != BigNumber::one() {
            error!("Failed to deserialize decryption key: key bytes are not consistent");
            Err(PaillierError::CouldNotCreateKey)?
        }

        // Note: This method doesn't check anything about the `u` or `lambda` fields
        // of the libpaillier::DecryptionKey. At time of writing, we never use those
        // fields explicitly, but they are used in the libpaillier `decrypt` method.
        // This function doesn't ensure that they're correct, so it may produce
        // decryption keys for which decryption will fail.

        // Validate for this application: make sure the length is correct
        if decryption_key.n().bit_length() != 2 * PRIME_BITS {
            error!(
                "Deserialized key is not the correct length; expected {}, got {}",
                2 * PRIME_BITS,
                decryption_key.n().bit_length()
            );
            Err(PaillierError::CouldNotCreateKey)?
        }

        Ok(Self(decryption_key))
    }

    /// Retrieve the public [`EncryptionKey`] corresponding to this secret
    /// [`DecryptionKey`].
    pub(crate) fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey(libpaillier::EncryptionKey::from(&self.0))
    }

    /// Return this [`DecryptionKey`]s modulus.
    pub(crate) fn modulus(&self) -> &BigNumber {
        self.0.n()
    }

    /// Return the [totient](https://en.wikipedia.org/wiki/Euler%27s_totient_function) of the modulus.
    pub(crate) fn totient(&self) -> &BigNumber {
        self.0.totient()
    }
}

// Safe prime generation functions for production and testing.
pub(crate) mod prime_gen {
    use super::*;
    #[cfg(test)]
    use rand::Rng;
    use rand::{CryptoRng, RngCore};

    pub fn safe_prime_from_rng(size: usize, _rng: &mut impl RngCore) -> BigNumber {
        BigNumber::safe_prime(PRIME_BITS /* , rng */)
    }

    /// Sample a safe prime with length `PRIME_BITS` at random.
    pub(crate) fn get_random_safe_prime<R: RngCore + CryptoRng>(rng: &mut R) -> BigNumber {
        safe_prime_from_rng(PRIME_BITS, rng)
    }

    #[cfg(test)]
    lazy_static::lazy_static! {
        /// List of `PRIME_BITS`-length safe primes, generated _insecurely_.
        static ref POOL_OF_PRIMES: Vec<BigNumber> = get_safe_primes_from_file();
    }

    /// Load a set of pre-generated safe primes from a file for testing
    /// efficiency.
    #[cfg(test)]
    fn get_safe_primes_from_file() -> Vec<BigNumber> {
        match PRIME_BITS {
            // The list of 512-bit primes includes safe primes of different lengths (511-514), so
            // we filter out any that aren't exactly 512.
            512 => crate::safe_primes_512::SAFE_PRIMES
                .iter()
                .map(|s| BigNumber::from_slice(hex::decode(s).unwrap()))
                .filter(|prime| prime.bit_length() == PRIME_BITS)
                .collect(),

            // This is the recommended `PRIME_BITS` value.
            1024 => crate::safe_primes_1024::SAFE_PRIMES
                .iter()
                .map(|s| BigNumber::from_slice(hex::decode(s).unwrap()))
                .collect(),

            _ => Vec::new(),
        }
    }

    /// Sample a safe prime from a precompiled list. For testing purposes only!!
    ///
    /// Only returns `None` if there aren't any primes in the pool.
    #[cfg(test)]
    pub(crate) fn try_get_prime_from_pool_insecure<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<BigNumber> {
        if POOL_OF_PRIMES.len() == 0 {
            Err(PaillierError::NoPregeneratedPrimes(PRIME_BITS))?;
        }
        POOL_OF_PRIMES
            .get(rng.gen_range(0..POOL_OF_PRIMES.len()))
            .cloned()
            .ok_or(PaillierError::NoPregeneratedPrimes(PRIME_BITS))
    }

    /// Sample a pair of independent, non-matching safe primes from a
    /// precompiled list. For testing purposes only!!
    #[cfg(test)]
    pub(crate) fn get_prime_pair_from_pool_insecure<R: RngCore + CryptoRng>(
        rng: &mut R,
    ) -> Result<(BigNumber, BigNumber)> {
        let p = try_get_prime_from_pool_insecure(rng)?;
        loop {
            let q = try_get_prime_from_pool_insecure(rng)?;
            if p != q {
                break Ok((p, q));
            }
        }
    }
}

#[cfg(test)]
mod test {
    use libpaillier::unknown_order::BigNumber;
    use rand::{CryptoRng, Rng, RngCore};

    use crate::{
        paillier::Ciphertext,
        parameters::PRIME_BITS,
        utils::{random_plusminus, testing::init_testing},
    };

    use super::{prime_gen, DecryptionKey, EncryptionKey};

    #[test]
    #[ignore = "sometimes slow in debug mode"]
    fn get_random_safe_prime_512_produces_safe_primes() {
        let mut rng = init_testing();

        let p = prime_gen::get_random_safe_prime(&mut rng);
        assert!(p.is_prime());
        let q: BigNumber = (p - 1) / 2;
        assert!(q.is_prime());
    }

    #[test]
    fn paillier_keygen_produces_good_primes() {
        let mut rng = init_testing();
        let (decryption_key, p, q) = DecryptionKey::new(&mut rng).unwrap();

        assert!(p.is_prime());
        assert!(q.is_prime());

        let safe_p: BigNumber = (&p - 1) / 2;
        assert!(safe_p.is_prime());
        let safe_q: BigNumber = (&q - 1) / 2;
        assert!(safe_q.is_prime());

        assert_eq!(p.bit_length(), PRIME_BITS);
        assert_eq!(q.bit_length(), PRIME_BITS);

        let modulus = &p * &q;
        assert_eq!(decryption_key.0.n(), &modulus);
        assert_eq!(modulus.bit_length(), 2 * PRIME_BITS);
    }

    #[test]
    #[ignore = "slow"]
    fn paillier_keygen_always_produces_good_primes() {
        let _rng = init_testing();
        for _ in 0..100 {
            paillier_keygen_produces_good_primes()
        }
    }

    /// Draw a random message from the expected range [-N/2, N/2].
    fn random_message(
        rng: &mut (impl CryptoRng + RngCore),
        encryption_key: &EncryptionKey,
    ) -> BigNumber {
        random_plusminus(rng, &encryption_key.half_n())
    }

    #[test]
    fn paillier_encryption_works() {
        let mut rng = init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        for _ in 0..100 {
            let msg = random_message(&mut rng, &encryption_key);

            // Encryption on good inputs doesn't fail
            let enc_result = encryption_key.encrypt(&mut rng, &msg);
            assert!(enc_result.is_ok());
            let (ciphertext, _) = enc_result.unwrap();

            // Decryption on good inputs doesn't fail
            let dec_result = decryption_key.decrypt(&ciphertext);
            assert!(dec_result.is_ok());
            let decrypted_msg = dec_result.unwrap();

            // Decrypted message matches original
            assert_eq!(msg, decrypted_msg);
        }
    }

    #[test]
    fn pailler_decryption_requires_correct_key() {
        let mut rng = init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        let msg = random_message(&mut rng, &encryption_key);
        let (ciphertext, _) = encryption_key.encrypt(&mut rng, &msg).unwrap();

        let (wrong_decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let decryption_result = wrong_decryption_key.decrypt(&ciphertext);
        assert!(decryption_result.is_err() || decryption_result.unwrap() != msg);

        assert_eq!(decryption_key.decrypt(&ciphertext).unwrap(), msg);
    }

    #[test]
    fn pailler_encryption_requires_input_in_Zn() {
        let mut rng = init_testing();

        // Specifically, the integers mod N must be in the interval around 0.
        // So, inputs in the range [-N/2, N/2] are acceptable, but not [0, N).
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        // In the acceptable range, 0 is allowed
        assert!(encryption_key.encrypt(&mut rng, &BigNumber::zero()).is_ok());

        // Test a number in between N/2 and N (both + and -)
        let too_big = (encryption_key.modulus() / 3) * 2;
        assert!(encryption_key.encrypt(&mut rng, &too_big).is_err());
        assert!(encryption_key.encrypt(&mut rng, &-too_big).is_err());

        // Test a number bigger than N (both + and -)
        let way_too_big = encryption_key.modulus() + 1;
        assert!(encryption_key.encrypt(&mut rng, &way_too_big).is_err());
        assert!(encryption_key.encrypt(&mut rng, &-way_too_big).is_err());

        // Test the boundary cases
        let barely_in = encryption_key.half_n();
        assert!(encryption_key.encrypt(&mut rng, &barely_in).is_ok());
        assert!(encryption_key.encrypt(&mut rng, &-barely_in).is_ok());

        let barely_out = encryption_key.half_n() + 1;
        assert!(encryption_key.encrypt(&mut rng, &barely_out).is_err());
        assert!(encryption_key.encrypt(&mut rng, &-barely_out).is_err());
    }

    #[test]
    fn paillier_encryption_generates_unique_nonces() {
        let mut rng = init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        let nonces = std::iter::repeat_with(|| {
            let msg = random_message(&mut rng, &encryption_key);
            let (_, nonce) = encryption_key.encrypt(&mut rng, &msg).unwrap();
            nonce
        })
        .take(100)
        .collect::<Vec<_>>();

        // This slow, ugly uniqueness check is because `BigNumber` doesn't implement
        // `Hash`, so we can't use any reasonable, built-in solutions
        for nonce in nonces.clone() {
            assert_eq!(1, nonces.iter().filter(|n| n == &&nonce).count())
        }
    }

    #[test]
    fn paillier_ciphertext_bits_matter() {
        let mut rng = init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        let msg = random_message(&mut rng, &encryption_key);
        let (ciphertext, _) = encryption_key.encrypt(&mut rng, &msg).unwrap();

        let mut bytes = ciphertext.0.to_bytes();

        for i in 0..bytes.len() {
            let original_byte = bytes[i];

            // Mangle the ith byte by replacing it with something random
            loop {
                bytes[i] = rng.gen();
                if bytes[i] != original_byte {
                    break;
                }
            }

            // Re-serialize the ciphertext
            let mangled_ciphertext = Ciphertext(BigNumber::from_slice(&bytes));

            // Decryption should fail.
            let decryption_result = decryption_key.decrypt(&mangled_ciphertext);
            assert!(decryption_result.is_err() || decryption_result.clone().unwrap() != msg);

            // Put the ith byte back
            bytes[i] = original_byte;
        }

        // When it's all reconstructed, decryption should work
        let correct_ciphertext = Ciphertext(BigNumber::from_slice(&bytes));
        assert_eq!(decryption_key.decrypt(&correct_ciphertext).unwrap(), msg);
    }

    #[test]
    fn half_ns_match() {
        let mut rng = init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(&mut rng).unwrap();
        let encryption_key = decryption_key.encryption_key();

        assert_eq!(encryption_key.half_n(), decryption_key.half_n());
    }

    #[test]
    fn decryption_key_to_from_bytes_works() {
        let rng = &mut init_testing();
        let (decryption_key, _, _) = DecryptionKey::new(rng).unwrap();

        let bytes = decryption_key.clone().into_bytes();
        let reconstructed = DecryptionKey::try_from_bytes(&bytes);

        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), decryption_key);
    }

    #[test]
    fn deserialized_decryption_key_must_be_2048_bits() {
        let rng = &mut init_testing();

        // Generate too-small primes
        let p = prime_gen::safe_prime_from_rng(PRIME_BITS / 2, rng);
        let q = prime_gen::safe_prime_from_rng(PRIME_BITS / 2, rng);

        // Manually create small DK
        let small_decryption_key =
            DecryptionKey(libpaillier::DecryptionKey::with_primes(&p, &q).unwrap());

        let bytes = small_decryption_key.into_bytes();
        assert!(DecryptionKey::try_from_bytes(&bytes).is_err());

        // Generate too-large primes (this is sometimes slow)
        let p = prime_gen::safe_prime_from_rng(PRIME_BITS + 1, rng);
        let q = prime_gen::safe_prime_from_rng(PRIME_BITS + 1, rng);
        let large_decryption_key =
            DecryptionKey(libpaillier::DecryptionKey::with_primes(&p, &q).unwrap());
        assert!(large_decryption_key.modulus().bit_length() > 2 * PRIME_BITS);
        let bytes = large_decryption_key.into_bytes();
        assert!(DecryptionKey::try_from_bytes(&bytes).is_err());
    }
}
