-- |
-- Module    : Monero
-- Stability : experimental

{-# LANGUAGE RecordWildCards #-}

module Monero () where

import           Crypto.ECC.Edwards25519
import           Crypto.Hash
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
