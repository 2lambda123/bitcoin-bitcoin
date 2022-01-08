# Dynamo Core

Dynamo is built upon the effort of many individuals who, for over a decade, have championed the idea of currency by the people and for the people.  Our team is deeply grateful for their vision and effort.


All things Dynamo can be found at https://www.dynamocoin.org

Please pull v1.1 production tag code.  The master branch contains work in progress virtual machine development for v2.0 and is unstable/incompatible with current production.

## Building for windows

Clone using Visual Studio 2019 community and build.  There are package dependencies which can be most easily installed using VCPKG.  If you build the QT client you will also need runtime libs.  Alot more docs are needed on the build process - please connect with us on Discord for help if you want to build core.

The easiest way to resolve VCPKG dependencies is to allow VCPKG to resolve them for you:

- Install VS2019 community
- Install git for windows https://gitforwindows.org/
- Clone VCPKG into its own directory per instructions here: https://github.com/microsoft/vcpkg
- Run "vcpkg integrate install"
- Clone dynamo-core to a source repo either from VS or using git
- Install phython for windows from here https://www.python.org/downloads/windows/
- Run "py -3 msvc-autogen.py" from a command prompt in <your dir>\dynamo-core\build_msvc\
- Open <your dir>\dynamo-core\build_msvc\bitcoin.sln in visual studio
- Build dynamo-server project
- VCPKG will do all the work for you, yay! :)

## Building for Ubuntu

```bash
# Install dependencies
sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils python3
sudo apt-get install libevent-dev libboost-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev

# clone the repo
git clone https://github.com/dynamofoundation/dynamo-core.git
cd dynamo-core
git checkout v1.1

# Build the two necessary binaries
./autogen.sh
./configure --disable-wallet
make src/bitcoind
make src/bitcoin-cli
```

If you try to run `make` to build all tools, you will get errors as not all are yet supported.  The CLI and core will build and are the only binaries you need to run and interact with your node.

More docs are needed here, connect with us on Discord for help.
