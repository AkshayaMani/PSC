Installing PSC

A PSC network consists of a Tally Server (TS), at least two Computation Parties (CPs) and one or more Data Parties (DPs). 

1. Download and Install Go

Download and install the latest version of Go for your platform from here: https://golang.org/doc/install#install.

2. Set your GOPATH

GOPATH environment variable specifies the location of your workspace. By default it would be a directory named go inside your home directory, i.e. $HOME/go on Unix. You can set GOPATH to other locations. Refer to the official Go documentation for more details: https://golang.org/doc/code.html.


3. Add $GOPATH/bin to PATH

Add the workspace's bin subdirectory to your PATH:

export PATH=$PATH:$GOPATH/bin

4. Install goenv package

go get github.com/crsmithdev/goenv

5. Install PSC

git clone https://github.com/PSC.git
cd PSC

6. Activate goenv

goenv -g $GOPATH/src
. goenv/activate

7. Install protocol buffers

Download protocol buffers compiler from
 https://developers.google.com/protocol-buffers/docs/downloads.html and follow the instructions in the README to install

8. Install PSC dependancies

go get -u github.com/golang/protobuf/protoc-gen-go
go get github.com/dedis/crypto
go get github.com/danieldk/par 
go get golang.org/x/net/publicsuffix
go get github.com/armon/go-radix

9. Deactivate goenv

deactivate

10. Installing a PrivCount-patched Tor (Data Parties) dependancies

Tor Dependencies
Debian/Ubuntu:  libssl-dev libevent-dev
Other Linux:    libssl libssl-dev libevent libevent-devel

Linux Sandbox (Optional)
Debian/Ubuntu:  libseccomp-dev
Other Linux:    libseccomp2 libseccomp-devel

Linux Capabilities (Optional)
Debian/Ubuntu:  libcap-dev
Other Linux:    libcap libcap-devel

Linux systemd notifications (Required if using systemd)
Debian/Ubuntu:  libsystemd-dev pkg-config
./configure --enable-systems

scrypt Control Port Password Encryption (Optional)
Debian/Ubuntu:  libscrypt-dev
Other Linux:    libscrypt-devel

11. Building Tor

Tor builds with --prefix=/usr/local by default. Perform the following steps to install a privcount-patched tor in /usr/local:

git clone https://github.com/privcount/tor.git tor-privcount
cd tor-privcount
git checkout origin/privcount
./autogen.sh
./configure --disable-asciidoc --prefix=/usr/local
make
sudo make install
