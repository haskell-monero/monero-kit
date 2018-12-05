import           Monero
import           Test.Hspec
import           Test.QuickCheck

main :: IO ()
main = hspec $ do

    describe "stealth addresses" $ do
        it "should match the output of the reference client" False
        it "should recognize a generated stealth address" $
            let testRecognition = do
                    sk <- generateRandomKeypair
                    stealth <- generateStealth (toPublic sk)
                    return $ isAssociatedStealth (viewKey sk) (toPublic sk) stealth
            in testRecognition `shouldReturn` True


    describe "subaddresses" $ do
        it "should match the output of the reference wallet" False


