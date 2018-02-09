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

### Create an environment <goenvironment_name> with go 1.7 or later

    nv mk goenv --go-prebuilt=1.7.5

### Activate environment

    nv on goenv

### Install PSC dependancies

    go get -u github.com/golang/protobuf/protoc-gen-go
    go get gopkg.in/dedis/crypto.v0
    go get golang.org/x/net/publicsuffix
    go get github.com/armon/go-radix

### Download PSC

    cd $GOPATH/src
    git clone https://github.com/AkshayaMani/PSC.git

### Upgrade PSC

    cd $GOPATH/src/PSC
    git pull

### Deactivate environment

    nv off

## Installing PrivCount-patched Tor (Data Parties) dependencies

A custom compiled PrivCount-patched Tor can be used to run a Data Party.

The most up to date instructions are located here:

https://github.com/privcount/privcount/blob/master/INSTALL.markdown#installing-a-privcount-patched-tor-data-collectors

### Tor Dependencies

    Debian/Ubuntu:  libssl-dev libevent-dev
    Other Linux:    libssl libssl-dev libevent libevent-devel

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
