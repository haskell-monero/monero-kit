-- |
-- Module    : Monero
-- Stability : experimental

{-# LANGUAGE DeriveAnyClass    #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeFamilies      #-}

{-# OPTIONS_GHC -fdefer-typed-holes #-}

module Monero (
    -- * Keys and addresses
      PublicKeypair (..)
    , ViewKey (..)
    , PrivateKeypair
    , toPublic
    , viewKey
    , generateRandomKeypair

    , StealthAddress (..)
    , isAssociatedStealth
    , generateStealth

    , subAddress

    -- * Blocks and transactions

    , Id (..)
    , Hash256 (..)

    , Transaction

    , BlockHeader (..)
    , Block (..)

    ) where

import           Control.DeepSeq         (NFData)
import           Crypto.ECC.Edwards25519
import           Crypto.Error
import           Crypto.Hash
import           Crypto.Random
import           Data.ByteArray
import           Data.ByteString         (ByteString)
import qualified Data.ByteString         as BS
import qualified Data.ByteString.Builder as BS
import qualified Data.ByteString.Lazy    as BSL
import           Data.ByteString.Short   (ShortByteString)
import           Data.Int
import           Data.Serialize
import           Data.Vector             (Vector)
import           Data.Word
import           GHC.Generics            (Generic)


-- ~~~~~~~~~~~~~ --
-- General types --
-- ~~~~~~~~~~~~~ --

-- | Identifiers of all kinds
data family Id a

-- | FIXME confirm type
newtype instance Id Transaction = TransactionId { unTransactionId :: Hash256 }
    deriving Eq

-- | For when bytes are actually a hash digest
newtype Hash256 = Hash256 { unHash256 :: ShortByteString }
    deriving Eq


-- ~~~~~~~~~ --
-- Addresses --
-- ~~~~~~~~~ --

-- | Every Monero output is owned by a keypair consisting of two Ed25519 keys.
-- These keys are used differently from one another and have different
-- consequences if compromised (separately).
data PublicKeypair
    = PublicKeypair
    { spendPubkey :: Point
    , viewPubkey  :: Point
    } deriving Eq


-- | This is the pair of private keys associated with a 'PublicKeypair'
data PrivateKeypair
    = PrivateKeypair
    { spendPriv :: Scalar
    , viewPriv  :: Scalar
    } deriving (Eq, Generic, NFData)


-- | Generate a 'PrivateKeypair' from the spend part of the 'PrivateKeypair' by taking a
-- hash of the private key for the view key.
privateKeypair :: Scalar -> PrivateKeypair
privateKeypair pk = PrivateKeypair pk (keccak256Scalar pk)


keccak256Scalar :: Scalar -> Scalar
keccak256Scalar = throwCryptoError . scalarDecodeLong . scrubbedKeccak . scalarEncode


scrubbedKeccak :: ByteString -> ScrubbedBytes
scrubbedKeccak = convert . keccak256


keccak256 :: ByteString -> Digest Keccak_256
keccak256 = hash


-- | The view (private) key of an address can be shared with a third party to
-- give them visibility over the transactions bound for the address, without
-- giving them the ability to spend
newtype ViewKey = ViewKey { unViewKey :: Scalar }
    deriving Eq


-- | Extract the private view key from a keypair
viewKey :: PrivateKeypair -> ViewKey
viewKey PrivateKeypair{..} = ViewKey viewPriv


-- | Create a keypair where the spend and view keys have no relation to each other
generateRandomKeypair :: MonadRandom m => m PrivateKeypair
generateRandomKeypair = PrivateKeypair <$> scalarGenerate <*> scalarGenerate


-- | All Monero payments spend to ephemeral addresses, which only the owner of
-- the view private key can recognize.
data StealthAddress
    = StealthAddress
    { stealthNonce  :: Point
    , stealthPubkey :: Point
    } deriving (Eq, Show, Generic, NFData)


-- | Test to see if a stealth address (R = rG, r A + B = a R + B) belongs to
-- the given PublicKeypair
isAssociatedStealth :: ViewKey -> PublicKeypair -> StealthAddress -> Bool
isAssociatedStealth (ViewKey viewKey) PublicKeypair{..} StealthAddress{..} =
    (viewKey `pointMul` stealthNonce `pointAdd` spendPubkey) == stealthPubkey


-- | Get the public key associated to a private key
toPublic :: PrivateKeypair -> PublicKeypair
toPublic PrivateKeypair{..} = PublicKeypair (toPoint spendPriv) (toPoint viewPriv)


-- | Create a new stealth address
generateStealth :: MonadRandom m => PublicKeypair -> m StealthAddress
generateStealth PublicKeypair{..} =
    scalarGenerate >>= \r ->
        let stP = r `pointMul` viewPubkey `pointAdd` spendPubkey in
        pure $ StealthAddress (toPoint r) stP


-- ~~~~~~~~~~~~ --
-- Transactions --
-- ~~~~~~~~~~~~ --


data Transaction
    = Transaction
    { version       :: Word64
    , unlockTime    :: Word64
    , vin           :: [TxIn]
    , vout          :: [TxOut]
    , extra         :: ByteString
    , signatures    :: [[Signature]]
    , rctSignatures :: RctSig
    } deriving Eq


data Signature = Signature
    deriving Eq


data RctSig = RctSig
    deriving Eq


data TxIn
    = TxIn
    {
    } deriving Eq


data TxOut
    = TxOut
    {
    } deriving Eq


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
--
-- - @ab6c17cc154914df61778ad48577ed70d8b03f88:src\/device/device_default.cpp#L127@
-- - @ab6c17cc154914df61778ad48577ed70d8b03f88:src\/device/device_default.cpp#L197@
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


-- ~~~~~~ --
-- Blocks --
-- ~~~~~~ --

-- | A Monero block header
data BlockHeader
    = BlockHeader
    { majorVersion   :: Word8
    , minorVersion   :: Word8
    , blockTimestamp :: Word64
    , previousBlock  :: Hash256
    -- ^ FIXME confirm type
    , blockNonce     :: Word32
    } deriving Eq


-- | A Monero block
data Block
    = Block
    { blockHeader       :: BlockHeader
    , coinbaseTx        :: Transaction
    , transactionHashes :: Vector (Id Transaction)
    } deriving Eq
