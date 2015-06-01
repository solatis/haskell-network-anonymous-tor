> import           System.Environment    (getArgs)
> import           Control.Concurrent    (threadDelay, forkIO)
> import           Control.Monad (void)
> import System.IO (IOMode (ReadWriteMode))

> import           Network               (withSocketsDo)
> import qualified Network.Simple.TCP    as NST
> import           Network.Socket        (socketToHandle)
> import qualified Network.Socket.Splice as Splice

> import qualified Network.Anonymous.Tor as Tor

Our main function is fairly simple: get our configuration data and start
a new Tor Session. As soon as this session completes, exit the program.

> main = withSocketsDo $ do
>   torPort <- whichControlPort
>   portmap <- getPortmap

Once we got the configuration data, launch a Tor session and will continue
execution in the 'withinSession' function.

>   Tor.withSession torPort (withinSession portmap)
>
>   where

We need a simple function to detect which control port Tor listens at. By
default the Tor service uses port 9051, but the Tor Browser Bundle uses 9151,
to allow Tor and the TBB to run next to each other. This function is relatively
unsafe, since it assumes at least one Tor service is running (otherwise 'head'
will return an error).

>     whichControlPort = do
>       ports <- Tor.detectPort [9051, 9151]
>       return (head ports)

Some boilerplate code: we need to set up a port mapping, and rather than hard-
coding it, we allow the user to provide is as command line arguments. The first
argument is the public port we will listen at, the second argument the private
port we relay connections to.

>     getPortmap :: IO (Integer, Integer)
>     getPortmap = do
>       [pub, priv] <- getArgs
>       return (read pub, read priv)

Once a Tor session has been created and we are authenticated with the Tor
control service, let's set up a new onion service which redirects incoming
connections to the 'newConnection' function.

>     withinSession (publicPort, privatePort) controlSock = do
>       onion <- Tor.accept controlSock publicPort (newConnection privatePort)
>       putStrLn ("hidden service descriptor: " ++ show onion)

If we would leave this function at this point, our connection with the Tor
control service would be lost, which would cause Tor to clean up any mappings
and hidden services we have registered.

Since this is just an example, we will now wait for 5 minutes and then exit.

>       threadDelay 300000000

This function is called for all incoming connections. All it needs to do is
establish a connection with the local service and relay the connections to the
local, private server.

>     newConnection privatePort sPublic =
>       NST.connect "127.0.0.1" (show privatePort) $ \(sPrivate, addr) -> spliceSockets sPublic sPrivate

And to demonstrate that the sockets we deal with are just regular, normal
network sockets, we implement a function using the `splice` package that
creates a bidirectional pipe between the public and private sockets.

>     spliceSockets sLhs sRhs = do
>       hLhs <- socketToHandle sLhs ReadWriteMode
>       hRhs <- socketToHandle sRhs ReadWriteMode
>       _ <- forkIO $ Splice.splice 1024 (sLhs, Just hLhs) (sRhs, Just hRhs)
>       Splice.splice 1024 (sRhs, Just hRhs) (sLhs, Just hLhs)
