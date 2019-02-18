-- |
-- Module: Crypto.ECC.Edwards25519.Extra
--
-- Support for converting integers to scalars; and subtraction for scalars.


module Crypto.ECC.Edwards25519.Extra
    ( toScalar
    , scalarSub
    , scalarNeg
    , scalarInv
    , pointMulInt

    -- * Constants
    , groupOrder
    , zeroPoint
    , zeroScalar
    , scalarOne
    , negativeOne
    ) where


import           Crypto.ECC.Edwards25519
import           Crypto.Error
import           Crypto.Number.ModArithmetic as MA
import           Data.Bits
import           Data.ByteString             as BS
import           Data.ByteString.Builder     as BSB
import           Data.ByteString.Lazy        as BSL
import           Data.Int
import           Data.Word


-- Order of the Curve25519 group
groupOrder :: Integer
groupOrder = 2^252 + 27742317777372353535851937790883648493


-- Useful constants

zeroPoint = toPoint zeroScalar
zeroScalar = throwCryptoError . scalarDecodeLong $ BS.empty
scalarOne = toScalar (1 :: Word8)
negativeOne = throwCryptoError . scalarDecodeLong
    . BS.pack . encodeLittleEndian $ groupOrder - 1


-- Some "missing" combinators

scalarNeg = scalarMul negativeOne
scalarSub x = scalarAdd x . scalarNeg

scalarInv x = toScalar <$> MA.inverse x' groupOrder
  where
    x' = decodeLittleEndian . BS.unpack . scalarEncode $ x


-- | Multiply a point by an 'Int64' instead of a 'Scalar'
pointMulInt :: Int64 -> Point -> Point
pointMulInt = pointMul . toScalar


-- | Warning this only works for non-negative values
toScalar :: (Bits a, Integral a) => a -> Scalar
toScalar x
    | x >= 0
    = toScalarPos x

    | x < 0
    = scalarNeg . toScalarPos . negate $ x
  where
    toScalarPos = throwCryptoError . scalarDecodeLong
        . BS.pack . encodeLittleEndian


-- | We need a version of little endian encoding for huge ints
encodeLittleEndian :: (Integral a, Bits a) => a -> [Word8]
encodeLittleEndian x
    | x == 0
    = []

    | otherwise
    = fromIntegral (x .&. 255) : encodeLittleEndian (x `shiftR` 8)


decodeLittleEndian :: [Word8] -> Integer
decodeLittleEndian []     = 0
decodeLittleEndian (x:xs) = fromIntegral x + 256 * decodeLittleEndian xs
