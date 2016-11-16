OAuth10a
===

Fully automatic luxury OAuth 1.0a headers.

(c) 2016 Gatlin Johnson <gatlin@niltag.net>

What is this thing
---

Generating OAuth 1.0a headers can be a bit tricky. This package provides
convenience types and functions to make the process less tricky. The aim of this
package is to be simple, correct, and fast.

The generated documentation on Hackage is more thorough but here is a whirlwind
tour of the package.

You may want to peruse the section "Starter kit" below or the `tests/Spec.hs`
file for example usage.

### Credentials and parameters

Two types are exported: `Credentials` and `Param`. Their definitions are
straightforward: 

```haskell
-- | HTTP request parameters
data Param = Param
    { paramKey   :: ByteString
    , paramValue :: ByteString
    } deriving (Show, Eq, Ord)

-- | Request credentials
data Credentials = Credentials
    { consumerKey :: ByteString
    , consumerSecret :: ByteString
    , token :: Maybe ByteString
    , tokenSecret :: Maybe ByteString
    } deriving (Show)
```

With the `OverloadedStrings` language extension enabled creating lists of
parameters and credential values is pretty clean.

Note that the last two parts of a `Credentials` value are `Maybe ByteString`s,
as sometimes you are not making a request with request or access tokens. The
library generates the correct values depending on the case.

### Signatures, nonces, timestamps, and IO

The meat of this package is in juggling `ByteString`s around for you to create
all the correct parts of an OAuth 1.0a header. This is the reason that some of
the functions have a `MonadIO` constraint: the time and (safely generated)
random values are acquired and encoded for you.

Note that many of the smaller functions that build up the `auth_header` function
are pure (and exported).

### Percent encoding

While some more advanced Haskellers might wince at this use of type classes
the package exports one called `PercentEncode`. Any member of this class - you
guessed it - may be percent encoded using the `percent_encode` function.

The two instances defined in this package are for `ByteString` and `Param`, the
latter of which simply makes use of the former. I think it makes the code easier
to read and reduces duplication. To wit:

```haskell
instance PercentEncode Param where
    percent_encode (Param a b) = Param (percent_encode a) (percent_encode b)
```

And then I can write things like `map percent_encode params` without incident.

Starter kit
---

The following is example client code using this package which defines a monad
DSL, with primitive API operations as the basic commands.

```haskell
{-# LANGUAGE OverloadedStrings, GeneralizedNewtypeDeriving #-}

module Foo
    (
      Foo(..)
    , runFoo
    , runFooWithManager
    , getManager
    , getCredentials
    , setCredentials
    , authHeader
    , Credentials(..)
    )
where

import Data.ByteString (ByteString)
import Control.Monad
import Control.Monad.Trans
import Control.Monad.State
import Control.Monad.IO.Class
import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)

import Net.OAuth.OAuth10a

data FooState = FooState
    { credentials :: Credentials
    , manager :: Manager
    }

newtype Foo a = Foo (StateT FooState IO a)
    deriving ( Functor
             , Applicative
             , Monad
             , MonadState FooState
             , MonadIO )

runFoo :: Credentials -> Foo a -> IO a
runFoo crd k = do
    manager <- newManager tlsManagerSettings
    runFooWithManager manager crd k

runFooWithManager :: Manager -> Credentials -> Foo a -> IO a
runFooWithManager manager crd (Foo c) = evalStateT c $ FooState crd manager

getCredentials :: Foo Credentials
getCredentials = get >>= return . credentials

-- | Perhaps we started with no tokens and have acquired them
setCredentials :: Credentials -> Foo ()
setCredentials crds = modify $ \st -> st { credentials = crds }

getManager :: Foo Manager
getManager = get >>= return . manager

-- | Makes use of 'auth_header' from oauth10a
authHeader
    :: ByteString -- ^ method
    -> ByteString -- ^ url
    -> [Param]    -- ^ extra parameters
    -> Foo ByteString
authHeader method url extras = do
    credentials <- getCredentials
    auth_header credentials method url extras

apiGetRequest
    :: String -- ^ Url
    -> [Param]
    -> Foo Request
apiGetRequest url params = do
    -- `param_string` is from oauth10a
    let queryString = "?"++(unpack $ param_string params)
    initialRequest <- liftIO $ parseRequest $ "GET " ++ url ++ querystring
    ah <- authHeader "GET" (pack url) params
    return $ initialRequest {
        requestHeaders = [("Authorization", ah)]
    }

{- ... etc ... -}
```

With the above, you could start to define commands for your API by generating
the requests with `apiGetRequest` and using the functions over in
`http-client`. The cool part is that your `GET` requests will automatically (and
luxuriously) have the correct OAuth 1.0a headers put in place.

License
---

See the `LICENSE` file.

Questions, comments, or free money?
---

Feel free to use the Issues feature on GitHub or email me at <gatlin@niltag.net>.
