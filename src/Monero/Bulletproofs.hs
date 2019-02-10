-- |
-- Module: Monero.Bulletproofs
--
-- Stage 1: implement the range proof from the bulletproofs paper
-- Stage 2: port the algorithm from monero-project/monero

{-# LANGUAGE RecordWildCards #-}

module Monero.Bulletproofs
    ( prove
    , verify
    ) where


import           Crypto.ECC.Edwards25519 as Ed
import           Crypto.Error            as Err
import           Data.Bits               as B
import           Data.Bool
import           Data.ByteString         as BS
import           Data.ByteString.Builder as BSB
import           Data.ByteString.Lazy    as BSL
import           Data.Int
import           Data.Vector             as V
import           Data.Word


-- | These parameters allow us to create Pedersen commitments both to scalars
-- and vectors
data Params
    = Params
    { paramsH   :: Point
    , paramsVec ::  Vector (Point, Point)
    }


paramsVecG i = fst . (V.! i) . paramsVec
paramsVecH i = snd . (V.! i) . paramsVec


data Bulletproof
    = Bulletproof
    { bulletproofV  :: Point
    , bulletproofL  :: Vector Scalar
    , bulletproofR  :: Vector Scalar
    , bulletproofF1 :: (Point, Point, Point, Point)
    -- ^ (A, S, T1, T2)
    , bulletproofF2 :: (Scalar, Scalar, Scalar)
    -- ^ (τx, μ, t)
    } deriving Eq


newtype Nonzero a = Nonzero a


data ProofRandomValues
    = ProofRandomValues Scalar Scalar (Vector Scalar) (Vector Scalar) Scalar
        (Nonzero Scalar) (Nonzero Scalar) Scalar Scalar (Nonzero Scalar)


-- | Generate the randomness for a bulletproof
proofRandomness :: Int -> IO ProofRandomValues
proofRandomness n = attempt >>= validate
  where
    attempt = ProofRandomValues <$> scalarGenerate <*> scalarGenerate
        <*> vectorGenerate <*> vectorGenerate <*> scalarGenerate
        <*> (Nonzero <$> scalarGenerate) <*> (Nonzero <$> scalarGenerate)
        <*> scalarGenerate <*> scalarGenerate <*> (Nonzero <$> scalarGenerate)

    vectorGenerate = V.sequence . V.generate n $ const scalarGenerate

    validate prv@(ProofRandomValues _ _ _ _ _ (Nonzero x) (Nonzero y) _ _ (Nonzero z)) =
        bool (proofRandomness n) (return prv) $
        x /= zeroScalar && y /= zeroScalar && z /= zeroScalar


-- ~~~~~~~~~~~ --
-- Commitments --
-- ~~~~~~~~~~~ --


scalarCommitment :: Params -> Scalar -> Scalar -> Point
scalarCommitment Params{..} x y = toPoint x `pointAdd` (y `pointMul` paramsH)


vectorCommitment :: Params -> Vector (Scalar, Scalar) -> Point
vectorCommitment Params{..} = V.foldl' pointAdd zeroPoint . V.zipWith f paramsVec
  where
    f (g, h) (x, y) = (x `pointMul` g) `pointAdd` (y `pointMul` h)


prove :: Params -> ProofRandomValues -> Int -> Word64 -> Bulletproof
prove p rv n v =
    Bulletproof
    { bulletproofV=vv
    , bulletproofL=l
    , bulletproofR=r
    , bulletproofF1=(a, s, t1, t2)
    , bulletproofF2=(τx, μ, t)
    }

  where

    vv = scalarCommitment' (toScalar . fromIntegral $ v) γ

    a = (α `pointMul` h) `pointAdd` commitmentA
    s = (ρ `pointMul` h) `pointAdd` vectorCommitment' (sl `V.zip` sr)


    t0' = l0 `innerP` r0

    t1' = (l0 `innerP` r1) `scalarAdd` (l1 `innerP` r0)
    t1 = scalarCommitment' t1' τ1

    t2' = l1 `innerP` r1
    t2 = scalarCommitment' t2' τ2


    l0 = V.map toScalar al `vsa` V.generate n (const z)
    l1 = sl

    r0 = generate n $ \i ->
        (scalarPow i y `scalarMul` toScalar (ar V.! i)) `scalarAdd` z `scalarAdd` (z2 `scalarMul` toScalar (2^i))
    r1 = sr

    l = l0 `vsa` V.map (scalarMul x) l1
    r = r0 `vsa` V.map (scalarMul x) r1


    τx = (τ1 `scalarMul` x) `scalarAdd` (τ2 `scalarMul` x2) `scalarAdd` (z2 `scalarMul` γ)
    μ = α `scalarAdd` (x `scalarMul` ρ)

    t = t0' `scalarAdd` (x `scalarMul` t1') `scalarAdd` (x2 `scalarMul` t2')

    --

    h = paramsH p

    vectorCommitment' = vectorCommitment p
    scalarCommitment' = scalarCommitment p

    --

    al :: Vector Int64
    al = V.generate n $ bool 0 1 . testBit v

    ar :: Vector Int64
    ar = V.map (\i -> i - 1) al

    commitmentA =
        V.foldl' pointAdd zeroPoint . V.zipWith f u . paramsVec $ p
      where
        f (x,y) (g,h) = (x `pointMulInt` g) `pointAdd` (y `pointMulInt` h)
        u = al `V.zip` ar

    -- x^2
    x2 = x `scalarMul` x

    -- z^2
    z2 = z `scalarMul` z

    ProofRandomValues γ α sl sr ρ (Nonzero y) (Nonzero z) τ1 τ2 (Nonzero x) = rv



-- | Verify a bulletproof
verify :: Params -> (Nonzero Scalar, Nonzero Scalar, Nonzero Scalar) -> Bulletproof -> Bool
verify p@Params{..} (x, y, z) proof = condition1 && condition2 && condition3
  where
    condition1 = t == l `innerP` r
    condition2 = scalarCommitment p t τx == rhs0
    condition3 = pp == (μ `pointMul` paramsH) `pointAdd` vectorCommitment p' (l `V.zip` r)

    rhs0 = _

    -- - z^2 * < 1^n, y^n > - z^3 * < 1^n , 2^n >
    e0 = _

    pp = a `pointAdd` s `pointAdd` _
    p' = Params paramsH (V.imap (f y) paramsVec)

    f (Nonzero y) i (g,h) = (g, scalarPow (negate i) y `pointMul` h)

    Bulletproof v l r (a, s, t1, t2) (τx, μ, t) = proof


-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ --
-- Extensions to the Ed25519 api --
-- ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ --


groupOrder :: Integer
groupOrder = 2^252 + 27742317777372353535851937790883648493


-- Useful constants

zeroPoint = toPoint zeroScalar
zeroScalar = throwCryptoError . scalarDecodeLong $ BS.empty
negativeOne = throwCryptoError . scalarDecodeLong . BS.pack . littleEndian $ groupOrder - 1


-- Some "missing" combinators

scalarNeg = scalarMul negativeOne
scalarSub x = scalarAdd x . scalarNeg


-- | Multiply a point by an 'Int64' instead of a 'Scalar'
pointMulInt :: Int64 -> Point -> Point
pointMulInt = pointMul . toScalar


-- | Warning this only works for non-negative values
toScalar x
    | x >= 0
    = toScalarPos x

    | x < 0
    = scalarNeg . toScalarPos . negate $ x
  where
    toScalarPos = throwCryptoError . scalarDecodeLong
        . BSL.toStrict . BSB.toLazyByteString . BSB.int64LE


-- | Vector pointwise scalar multiplication
vsm = V.zipWith scalarMul

-- | Vector pointwise scalar addition
vsa = V.zipWith scalarAdd

-- | Scalar inner product
innerP u v = V.foldl' scalarAdd zeroScalar $ u `vsm` v

-- | Raise a scalar to a power
scalarPow i x
    | x == zeroScalar
    = zeroScalar

    | i > 0
    = x `scalarMul` scalarPow (i-1) x

    | otherwise
    = toScalar 1

-- | We need a version of little endian encoding for huge ints
littleEndian :: Integer -> [Word8]
littleEndian x
    | x == 0
    = []

    | otherwise
    = fromIntegral (x .&. 255) : littleEndian (x `shiftR` 8)

