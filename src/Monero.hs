-- |
-- Module    : Monero
-- Stability : experimental

module Monero () where

import           Crypto.ECC.Edwards25519


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
  , viewPriv  :: Scalar
  } deriving Eq


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

