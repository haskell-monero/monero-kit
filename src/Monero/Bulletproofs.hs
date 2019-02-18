-- |
-- Module: Monero.Bulletproofs
--
-- Stage 1: implement the range proof from the bulletproofs paper (long
-- version)
-- Stage 2: port the algorithm from monero-project/monero

{-# LANGUAGE RecordWildCards #-}

module Monero.Bulletproofs
    ( Params (..)
    , Bulletproof (..)
    , ProofRandomValues (..)
    , Nonzero (..)

    , prove
    , verify

    , proofRandomness
    , generateParams
    , verifierRandomness
    ) where


import           Control.Arrow                 ((***))
import           Crypto.ECC.Edwards25519       as Ed
import           Crypto.ECC.Edwards25519.Extra
import           Data.Bits                     as B
import           Data.Bool
import           Data.Int
import           Data.Vector                   as V
import           Data.Word


-- | These parameters allow us to create Pedersen commitments both to scalars
-- and vectors
data Params
    = Params
    { paramsH   :: Point
    , paramsN   :: Int
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


verifierRandomness (ProofRandomValues _ _ _ _ _ x y _ _ z) = (x, y, z)

-- | Generate the randomness for a bulletproof
proofRandomness :: Int -> IO ProofRandomValues
proofRandomness n = attempt >>= validate
  where
    attempt = ProofRandomValues <$> scalarGenerate <*> scalarGenerate
        <*> vectorGenerate n <*> vectorGenerate n <*> scalarGenerate
        <*> (Nonzero <$> scalarGenerate) <*> (Nonzero <$> scalarGenerate)
        <*> scalarGenerate <*> scalarGenerate <*> (Nonzero <$> scalarGenerate)


    validate prv@(ProofRandomValues _ _ _ _ _ (Nonzero x) (Nonzero y) _ _ (Nonzero z)) =
        bool (proofRandomness n) (return prv) $
        x /= zeroScalar && y /= zeroScalar && z /= zeroScalar


vectorGenerate n = V.sequence . V.generate n $ const scalarGenerate


-- | Generate random parameters
generateParams :: Int -> IO Params
generateParams n =
    Params <$> (toPoint <$> scalarGenerate) <*> pure n
    <*> (f <$> vectorGenerate n <*> vectorGenerate n)
  where
    f v1 v2 = (toPoint <$> v1) `V.zip` (toPoint <$> v2)


-- ~~~~~~~~~~~ --
-- Commitments --
-- ~~~~~~~~~~~ --


scalarCommitment :: Params -> Scalar -> Scalar -> Point
scalarCommitment Params{..} x y = toPoint x `pointAdd` (y `pointMul` paramsH)


vectorCommitment :: Params -> Vector (Scalar, Scalar) -> Point
vectorCommitment Params{..} = V.foldl' pointAdd zeroPoint . V.zipWith f paramsVec
  where
    f (g, h) (x, y) = (x `pointMul` g) `pointAdd` (y `pointMul` h)


prove :: Params -> ProofRandomValues -> Word64 -> Bulletproof
prove p rv v =
    Bulletproof
    { bulletproofV=vv
    , bulletproofL=l
    , bulletproofR=r
    , bulletproofF1=(a, s, t1, t2)
    , bulletproofF2=(τx, μ, t)
    }

  where

    n = paramsN p

    vv = scalarCommitment' (toScalar v) γ

    a = (α `pointMul` h) `pointAdd` commitmentA
    commitmentA = vectorCommitment' . fmap (toScalar *** toScalar) $ al `V.zip` ar

    s = (ρ `pointMul` h) `pointAdd` vectorCommitment' (sl `V.zip` sr)


    t0' = l0 `innerP` r0

    t1' = (l0 `innerP` r1) `scalarAdd` (l1 `innerP` r0)
    t1 = scalarCommitment' t1' τ1

    t2' = l1 `innerP` r1
    t2 = scalarCommitment' t2' τ2


    l0 = fmap toScalar al `pointwiseAdd` V.generate n (const . scalarNeg $ z)
    l1 = sl

    r0 = generate n $ \i ->
        (scalarPow i y `scalarMul` (z `scalarAdd` toScalar (ar V.! i)))
        `scalarAdd` (z2 `scalarMul` toScalar (2^i :: Word64))
    r1 = V.imap (scalarMul . flip scalarPow y) sr

    l = l0 `pointwiseAdd` fmap (scalarMul x) l1
    r = r0 `pointwiseAdd` fmap (scalarMul x) r1


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
    ar = fmap (\i -> i - 1) al

    -- x^2
    x2 = x `scalarMul` x

    -- z^2
    z2 = z `scalarMul` z

    ProofRandomValues γ α sl sr ρ (Nonzero x) (Nonzero y) τ1 τ2 (Nonzero z) = rv



-- | Verify a bulletproof
verify :: Params -> (Nonzero Scalar, Nonzero Scalar, Nonzero Scalar) -> Bulletproof -> Bool
verify p@Params{..} (Nonzero x, Nonzero y, Nonzero z) proof = condition1 && condition2 && condition3
  where
    condition1 = t == l `innerP` r
    condition2 = scalarCommitment p t τx == rhs0
    condition3 = pp == (μ `pointMul` paramsH) `pointAdd` vectorCommitment p' (l `V.zip` r)

    n = paramsN

    rhs0 = toPoint (k `scalarAdd` w0) `pointAdd` (z2 `pointMul` v)
        `pointAdd` (x `pointMul` t1)
        `pointAdd` (x2 `pointMul` t2)

    w0 = z `scalarMul` (oneN `innerP` yn)

    -- - z^2 * < 1^n, y^n > - z^3 * < 1^n , 2^n >
    k = scalarNeg $
        (z2 `scalarMul` (oneN `innerP` yn))
        `scalarAdd` (z3 `scalarMul` toScalar (2 ^ n - 1 :: Word64))

    oneN = V.generate n . const . toScalar $ (1 :: Word8)
    yn = V.generate n $ flip scalarPow y

    x2 = x `scalarMul` x
    z2 = z `scalarMul` z
    z3 = z `scalarMul` z2

    pp = a `pointAdd` (x `pointMul` s) `pointAdd` w1

    w1 = vectorCommitment p' $ V.generate n $ \i ->
        ( scalarNeg z
        , (z `scalarMul` scalarPow i y) `scalarAdd` (z2 `scalarMul` toScalar (2^i :: Word64))
        )

    p' = Params paramsH n (V.imap f paramsVec)

    f i (g,h) = (g, scalarPow (negate i) y `pointMul` h)

    Bulletproof v l r (a, s, t1, t2) (τx, μ, t) = proof


-- ~~~~~~~~~~~~~~~~~ --
-- Utility functions --
-- ~~~~~~~~~~~~~~~~~ --


-- | Vector pointwise scalar multiplication
pointwiseMul = V.zipWith scalarMul

-- | Vector pointwise scalar addition
pointwiseAdd = V.zipWith scalarAdd

-- | Scalar inner product
innerP u v = V.foldl' scalarAdd zeroScalar $ u `pointwiseMul` v

-- | Raise a scalar to a power
scalarPow :: Int -> Scalar -> Scalar
scalarPow i x
    | x == zeroScalar
    = zeroScalar

    | i > 0
    = x `scalarMul` scalarPow (i-1) x

    | i == 0
    = toScalar (1 :: Word8)

    | i < 0
    = maybe zeroScalar (scalarPow $ negate i) $ scalarInv x
