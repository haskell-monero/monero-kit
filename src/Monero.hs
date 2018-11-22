-- |
-- Module    : Monero
-- Stability : experimental

{-# LANGUAGE RecordWildCards #-}

module Monero
  ( PublicAddress
  , PrivateKeypair
  , ViewKey
  , StealthAddress
  , isAssociatedStealth
  , generatePrivate
  , generateStealth
  , toPublic
  ) where

import           Crypto.ECC.Edwards25519
import           Crypto.Random


-- | Every Monero output is owned by a keypair consisting of two Ed25519 keys.
-- These keys are used differently from one another and have different
-- consequences if compromised (separately).
data PublicAddress
  = PublicAddress
  { spendPubkey :: Point
  , viewPubkey  :: Point
  } deriving Eq


-- | This is the pair of private keys associated with a 'PublicAddress'
data PrivateKeypair
  = PrivateKeypair
  { spendPriv :: Scalar
  , viewPriv  :: Scalar
  } deriving Eq


-- | All Monero payments spend to ephemeral addresses, which only the owner of
-- the view private key can recognize.
--
-- - [ ] Serialize instance
data StealthAddress
  = StealthAddress
  { stealthNonce  :: Point
  , stealthPubkey :: Point
  }  deriving Eq


-- | The view (private) key of an address can be shared with a third party to
-- give them visibility over the transactions bound for the address, without
-- giving them the ability to spend
newtype ViewKey = ViewKey { unViewKey :: Scalar }
  deriving Eq


-- | Test to see if a stealth address (R = rG, r A + B = a R + B) belongs to
-- the given PublicAddress
isAssociatedStealth :: ViewKey -> PublicAddress -> StealthAddress -> Bool
isAssociatedStealth (ViewKey viewKey) PublicAddress{..} StealthAddress{..} =
  (viewKey `pointMul` stealthNonce `pointAdd` spendPubkey) == stealthPubkey


-- | Generate a new private keypair
generatePrivate :: MonadRandom m => m PrivateKeypair
generatePrivate =
  scalarGenerate >>= \a ->
  scalarGenerate >>= \b ->
    pure $ PrivateKeypair a b


-- | Get the public key associated to a private key
toPublic :: PrivateKeypair -> PublicAddress
toPublic PrivateKeypair{..} = PublicAddress (toPoint spendPriv) (toPoint viewPriv)


-- | Create a new stealth address
generateStealth :: MonadRandom m => PublicAddress -> m StealthAddress
generateStealth PublicAddress{..} =
  scalarGenerate >>= \r ->
    let stP = r `pointMul` viewPubkey `pointAdd` spendPubkey in
    pure $ StealthAddress (toPoint r) stP
