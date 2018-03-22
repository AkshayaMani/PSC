# Building and Installing PSC

A PSC network consists of a Tally Server (TS), at least two Computation Parties (CPs) and one or more Data Parties (DPs). 

## Install PSC

### Install virtual environment

    git clone https://github.com/ekalinin/envirius.git
    cd envirius
    make install

Add following to your ~/.bashrc:

    [ -f "$HOME/.envirius/nv" ] && . ~/.envirius/nv

Restart your terminal.

### Check available versions of go

    nv ls-versions --go-prebuilt

### Create an environment <goenvironment_name> with go 1.9 or later

    nv mk <goenvironment_name> --go-prebuilt=1.9.4

### Activate environment

    nv on <goenvironment_name>

### Install PSC dependancies

    go get -u github.com/golang/protobuf/protoc-gen-go
    go get golang.org/x/net/publicsuffix
    go get github.com/armon/go-radix
    go get github.com/dedis/kyber
    cd $GOPATH/src/github.com/dedis/kyber
    go get -t ./...
    go build -tags vartime

### Download PSC

    cd $GOPATH/src
    git clone https://github.com/AkshayaMani/PSC.git

### Upgrade PSC

    cd $GOPATH/src/PSC
    git pull

### Deactivate environment

    nv off

## Installing PrivCount-patched Tor (Data Parties) dependencies

A custom compiled PrivCount-patched Tor must be used to run a Data Party. 

The most up to date instructions for installing a PrivCount-patched Tor can be found here:

    https://github.com/privcount/privcount/blob/master/INSTALL.markdown#installing-a-privcount-patched-tor-data-collectors

<!---
### Tor Dependencies

    Debian/Ubuntu:  libssl-dev libevent-dev
    Other Linux:    libssl libssl-dev libevent libevent-devel

### Tor Dependencies

#### Linux Sandbox (Optional)

    Debian/Ubuntu:  libseccomp-dev
    Other Linux:    libseccomp2 libseccomp-devel

#### Linux Capabilities (Optional)

    Debian/Ubuntu:  libcap-dev
    Other Linux:    libcap libcap-devel


#### Linux systemd notifications (Required if using systemd)

    Debian/Ubuntu:  libsystemd-dev pkg-config
    ./configure --enable-systems

#### scrypt Control Port Password Encryption (Optional)

    Debian/Ubuntu:  libscrypt-dev
    Other Linux:    libscrypt-devel

### Building Tor

Tor builds with --prefix=/usr/local by default. Perform the following steps to install a privcount-patched tor in /usr/local:

    git clone https://github.com/privcount/tor.git tor-privcount
    cd tor-privcount
    git checkout origin/privcount
    ./autogen.sh
    ./configure --disable-asciidoc --prefix=/usr/local
    make
    sudo make install
-->
