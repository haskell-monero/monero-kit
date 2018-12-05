-- |
-- Module    : Monero
-- Stability : experimental

{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

module Monero
    ( PublicAddress
    , ViewKey
    , PrivateKeypair
    , toPublic

    , StealthAddress
    , isAssociatedStealth
    , generateStealth

    , subAddress
    ) where

import           Crypto.ECC.Edwards25519
import           Crypto.Error
import           Crypto.Hash
import           Crypto.Random
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Lazy    as BSL
import           Data.Int
import           Data.Serialize
import           Data.Word

-- ~~~~~~~~~ --
-- Addresses --
-- ~~~~~~~~~ --

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


-- | Get the public key associated to a private key
toPublic :: PrivateKeypair -> PublicAddress
toPublic PrivateKeypair{..} = PublicAddress (toPoint spendPriv) (toPoint viewPriv)


-- | Create a new stealth address
generateStealth :: MonadRandom m => PublicAddress -> m StealthAddress
generateStealth PublicAddress{..} =
    scalarGenerate >>= \r ->
        let stP = r `pointMul` viewPubkey `pointAdd` spendPubkey in
        pure $ StealthAddress (toPoint r) stP


-- | Derive a subaddress
--
-- Subaddresses are parameterized by major and minor indices @(i,j)@.  The major
-- index represents a user-level account, whereas the minor index tracks the
-- position in a chain of subaddresses under an account.
--
-- Given a pair of private keys @(a,b)@ and a pair of indices @(i,j)@ the
-- corresponding subaddress pair of private keys is @(a * (b + m), b + m)@ where
--
-- > m = le_int32_to_scalar(keccak256("SubAddr"|a|i|j))
--
-- monero-project/monero:
-- * ab6c17cc154914df61778ad48577ed70d8b03f88:src/device/device_default.cpp#L127
-- * ab6c17cc154914df61778ad48577ed70d8b03f88:src/device/device_default.cpp#L197
--
subAddress :: PrivateKeypair -> Int32 -> Int32 -> PrivateKeypair
subAddress PrivateKeypair{..} majorIndex minorIndex = PrivateKeypair s v
    where
        s = k `scalarAdd` spendPriv
        v = viewPriv `scalarMul` s
        k = throwCryptoError $ scalarDecodeLong m
        m = hashWith Keccak_256 . BSL.toStrict . BS.toLazyByteString $
            BS.byteString "SubAddr" <>
            BS.byteString (scalarEncode viewPriv) <>
            BS.int32LE majorIndex <>
            BS.int32LE minorIndex


-- ~~~~~~~~~~~~ --
-- Transactions --
-- ~~~~~~~~~~~~ --


data Transaction = Transaction

-- ~~~~~~ --
-- Blocks --
-- ~~~~~~ --

-- | A Monero block header
data BlockHeader
  = BlockHeader
  { majorVersion   :: Word8
  , minorVersion   :: Word8
  , blockTimestamp :: Word64
  , previousBlock  :: _
  -- ^ Keccak with 1600-bit digest
  , blockNonce     :: Word32
  } deriving Eq

instance Serialize BlockHeader where

  put BlockHeader{..} =
    BlockHeader
      <$> putVarint
      <*> putVarint
      <*> _ -- putWord64be ?
      <*> _
      <*> _

  get =
    BlockHeader
    <$> getVarint
    <*> getVarint
    <*> _
    <*> _
    <*> _


-- | A Monero block
data Block
  = Block
  { blockHeader       :: BlockHeader
  , coinbaseTx        :: Transaction
  , transactionHashes :: _
  -- ^ what structure do these hashes have ?
  } deriving Eq


-- ~~~~~~~~~~~~~~~~~~~~~ --
-- Serialization helpers --
-- ~~~~~~~~~~~~~~~~~~~~~ --

data Varint = Varint

getVarint :: Get Varint
getVarint = _

putVarint :: Putter Varint
putVarint = _
