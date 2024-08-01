use std::{fmt, ops::Deref};

use der::asn1::BitString;
use ed25519_dalek::{Signature as Ed25519DalekSignature, Signer, SigningKey, VerifyingKey};
use polyproto::certs::PublicKeyInfo;
use polyproto::errors::{ConversionError, InvalidInput};
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use rand::{CryptoRng, RngCore};
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Ed25519Signature {
    signature: Ed25519DalekSignature,
    algorithm: AlgorithmIdentifierOwned,
}

impl fmt::Display for Ed25519Signature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.signature, f) // pass through
    }
}

/// Private/public key pair for Ed25519
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ed25519KeyPair(SigningKey);

/// Public key for Ed25519
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Deref for Ed25519KeyPair {
    type Target = SigningKey;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<Ed25519PublicKey> for Ed25519KeyPair {
    #[inline(always)]
    fn as_ref(&self) -> &Ed25519PublicKey {
        const { assert!(size_of::<VerifyingKey>() == size_of::<Ed25519PublicKey>()) };

        // SAFETY: Ed25519PublicKey is a transparent wrapper around VerifyingKey, so references to
        // both types have the same memory layout.
        unsafe { std::mem::transmute::<&VerifyingKey, &Ed25519PublicKey>(self.0.as_ref()) }
    }
}

impl Deref for Ed25519PublicKey {
    type Target = VerifyingKey;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SignatureBitStringEncoding for Ed25519Signature {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        BitString::from_bytes(&self.as_signature().to_bytes())
    }
}

impl Signature for Ed25519Signature {
    // We define the signature type from the ed25519-dalek crate as the associated type.
    type Signature = Ed25519DalekSignature;

    // This is straightforward: we return a reference to the signature.
    #[inline(always)]
    fn as_signature(&self) -> &Self::Signature {
        &self.signature
    }

    // The algorithm identifier for a given signature implementation is constant. We just need
    // to define it here.
    #[inline(always)]
    fn algorithm_identifier() -> AlgorithmIdentifierOwned {
        const {
            AlgorithmIdentifierOwned {
                // This is the OID for Ed25519. It is defined in the IANA registry.
                oid: ObjectIdentifier::new_unwrap("1.3.101.112"),
                // For this example, we don't need or want any parameters.
                parameters: None,
            }
        }
    }

    fn from_bytes(signature: &[u8]) -> Result<Self, ConversionError> {
        match <&[u8; 64]>::try_from(signature) {
            Ok(signature_array) => Ok(Self {
                signature: Ed25519DalekSignature::from_bytes(signature_array),
                algorithm: Self::algorithm_identifier(),
            }),
            Err(_) => Err(ConversionError::InvalidInput(
                polyproto::errors::InvalidInput::Length {
                    min_length: 0,
                    max_length: 32,
                    actual_length: signature.len(),
                },
            )),
        }
    }
}

impl PrivateKey<Ed25519Signature> for Ed25519KeyPair {
    type PublicKey = Ed25519PublicKey;

    // Return a reference to the public key
    #[inline(always)]
    fn pubkey(&self) -> &Self::PublicKey {
        self.as_ref()
    }

    // Signs a message. The beauty of having to wrap the ed25519-dalek crate is that we can
    // harness all of its functionality, such as the `sign` method.
    fn sign(&self, data: &[u8]) -> Ed25519Signature {
        Ed25519Signature {
            signature: self.0.sign(data),
            algorithm: self.algorithm_identifier(),
        }
    }
}

impl PublicKey<Ed25519Signature> for Ed25519PublicKey {
    // Verifies a signature. We use the `verify_strict` method from the ed25519-dalek crate.
    // This method is used to mitigate weak key forgery.
    fn verify_signature(
        &self,
        signature: &Ed25519Signature,
        data: &[u8],
    ) -> Result<(), polyproto::errors::composite::PublicKeyError> {
        self.verify_strict(data, signature.as_signature())
            .map_err(|_| polyproto::errors::composite::PublicKeyError::BadSignature)
    }

    // Returns the public key info. Public key info is used to encode the public key in a
    // certificate or a CSR. It is named after the `SubjectPublicKeyInfo` type from the X.509
    // standard, and thus includes the information needed to encode the public key in a certificate
    // or a CSR.
    fn public_key_info(&self) -> PublicKeyInfo {
        PublicKeyInfo {
            algorithm: Ed25519Signature::algorithm_identifier(),
            public_key_bitstring: BitString::from_bytes(self.as_bytes()).unwrap(),
        }
    }

    fn try_from_public_key_info(public_key_info: PublicKeyInfo) -> Result<Self, ConversionError> {
        match <&[u8; 32]>::try_from(public_key_info.public_key_bitstring.raw_bytes()) {
            Ok(sig_array) => match VerifyingKey::from_bytes(sig_array) {
                Ok(key) => Ok(Self(key)),
                Err(e) => Err(ConversionError::InvalidInput(
                    polyproto::errors::InvalidInput::Malformed(e.to_string().into()),
                )),
            },
            Err(_) => Err(ConversionError::InvalidInput(InvalidInput::Length {
                min_length: 0,
                max_length: 32,
                actual_length: public_key_info.public_key_bitstring.raw_bytes().len(),
            })),
        }
    }
}

impl Ed25519KeyPair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(SigningKey::generate(rng))
    }
}
