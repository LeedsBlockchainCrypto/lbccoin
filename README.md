Leeds Blockchain Crypto Coin - LBCcoin
======================================
LBC coin is a fork of litecoin, which is itself a fork of bitcoin, and is for *educational purposes only*. This coin is conceptually identical to Litecoin (for now at least) and as such adds no value. It's pegged to USD at a rate of $0.00 per LBCcoin.

The genesis block was created with the help of the [GenesisH0](https://github.com/lhartikk/GenesisH0) script. It contains the coinbase parameter "[Newsthump 29 Jan 2018 Barnsley man outraged by cultural appropriation in Monty Python Yorkshireman sketch](http://newsthump.com/2018/01/28/barnsley-man-outraged-by-cultural-appropriation-in-monty-python-yorkshireman-sketch/)".

I'm using [cpuminer](https://github.com/pooler/cpuminer) to mine as the difficulty is currently very low, so you can pretend it's 2011. But please don't point a hefty mining rig at this blockchain - it will just increase the difficulty and then exlude people without that kit from the learning experience.

See the `doc/build-*.md` files for build instructions. We've got this up and running on x64 (linux and osx) and ARM (raspberry pi).

Ports are 9937 and 9936 (RPC). Address prefix is 'Y' for Yorkshire! (e.g. Ykoifcaq22kyB8H5tAJd4RvkfgzPNV1RZ2)

Once you've got your own node running, first sync it with the one running at 139.162.230.135.

Then you'll be able to start mining, see the [litecoind man page](http://manpages.org/litecoinconf/5). E.g. you can connect `cpuminer` (to your own node) like this:
```
minerd -a scrypt -o http://127.0.0.1:9936 -O<user>:<pass> --coinbase-addr <address>
```
And of course there's a GUI wallet (`lbccoin-qt`) that you can use to generate an address to send mining rewards to.

The reg tests are broken and I've not even tried testnet. See [issues](https://github.com/LeedsBlockchainCrypto/lbccoin/issues). Contributions welcome via PR. 

The original Litecoin README follows...

Litecoin Core integration/staging tree
=====================================

[![Build Status](https://travis-ci.org/litecoin-project/litecoin.svg?branch=master)](https://travis-ci.org/litecoin-project/litecoin)

https://litecoin.org

What is Litecoin?
----------------

Litecoin is an experimental digital currency that enables instant payments to
anyone, anywhere in the world. Litecoin uses peer-to-peer technology to operate
with no central authority: managing transactions and issuing money are carried
out collectively by the network. Litecoin Core is the name of open source
software which enables the use of this currency.

For more information, as well as an immediately useable, binary version of
the Litecoin Core software, see [https://litecoin.org](https://litecoin.org).

License
-------

Litecoin Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/litecoin-project/litecoin/tags) are created
regularly to indicate new official, stable release versions of Litecoin Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md).

The developer [mailing list](https://groups.google.com/forum/#!forum/litecoin-dev)
should be used to discuss complicated or controversial changes before working
on a patch set.

Developer IRC can be found on Freenode at #litecoin-dev.

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and OS X, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

Translations
------------

We only accept translation fixes that are submitted through [Bitcoin Core's Transifex page](https://www.transifex.com/projects/p/bitcoin/).
Translations are converted to Litecoin periodically.

Translations are periodically pulled from Transifex and merged into the git repository. See the
[translation process](doc/translation_process.md) for details on how this works.

**Important**: We do not accept translation changes as GitHub pull requests because the next
pull from Transifex would automatically overwrite them again.
