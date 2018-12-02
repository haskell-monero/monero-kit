-- |
-- Module    : Monero
-- Stability : experimental

module Monero () where

import           Crypto.ECC.Edwards25519
import           Crypto.Error
import           Crypto.Hash
import           Data.ByteArray
import           Data.ByteString


-- | Every Monero output is owned by a keypair consisting of two Ed25519 keys.
-- These keys are used differently from one another and have different
-- consequences if compromised (separately).
data PublicAddress
  = PublicAddress
  { spendPublic :: Point
  , viewPublic  :: Point
  } deriving Eq


-- | This is the pair of private keys associated with a 'PublicAddress'
data SpendKey
  = SpendKey
  { spendPriv :: Scalar
  , viewPriv  :: Scalar -- Usually a hash of the 'spendPriv'
  } deriving Eq


-- | Generate a 'SpendKey' from the spend part of the 'SpendKey' by taking a hash of the private key for the view key.
spendKey :: Scalar -> SpendKey
spendKey pk = SpendKey pk (keccakScalar pk)


keccakScalar :: Scalar -> Scalar
keccakScalar = throwCryptoError . scalarDecodeLong . scrubbedKeccak . scalarEncode


scrubbedKeccak :: ByteString -> ScrubbedBytes
scrubbedKeccak = convert . keccak256


keccak256 :: ByteString -> Digest Keccak_256
keccak256 = hash


-- | All Monero payments spend to ephemeral addresses, which only the owner of
-- the view private key can recognize.
--
-- - [ ] Serialize instance
newtype StealthAddress = StealthAddress { unStealthAddress :: Point }
  deriving Eq


-- | The view (private) key of an address can be shared with a third party to
-- give them visibility over the transactions bound for the address, without
-- giving them the ability to spend
newtype ViewKey = ViewKey { unViewKey :: Scalar }
  deriving Eq
