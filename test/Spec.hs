import           Monero
import           Test.Hspec
import           Test.QuickCheck

main :: IO ()
main = hspec $ do

    describe "stealth addresses" $ do

        it "should match the output of the reference client" False

        sk <- runIO generateRandomKeypair
        stealth <- runIO $ generateStealth (toPublic sk)

        it "should recognize a generated stealth address" $
            stealth `shouldSatisfy` isAssociatedStealth (viewKey sk) (toPublic sk)


    describe "subaddresses" $ do
        it "should match the output of the reference wallet" False
