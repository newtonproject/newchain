## NewChain

NewChain is based on Official golang implementation of the Ethereum protocol.

NewChain made the following changes:

* In order to better integrate NewIoT technology, modify the signature algorithm from secp256-k1 to secp256-r1
* In order to support higher GasPrice settings, modify some of the limiting parameters, including maxPrice and SuggestPrice
* The consensus algorithm uses PoA, and the block interval is 3 seconds

Refer to [NewChain Deploy](https://github.com/newtonproject/newchain-deploy) to run your node.
