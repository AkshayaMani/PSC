# Deployment

First, download and install the latest version of PSC. 

If you are running a Data Party, also download, compile, install, and launch the latest version of the Tor PrivCount patch found here: 

```
    https://github.com/privcount/privcount/blob/master/INSTALL.markdown#installing-a-privcount-patched-tor-data-collectors
```

Refer INSTALL.markdown for details.

## Activate environment

Activate the go environment <goenvironment_name> created during installation:

```
    nv on <goenvironment_name>
```

## Generate network CA Key 

Generate new CA key for each network that runs PSC. See CAInstructions.markdown for details.

## Exchange CA certificates 

Send CA certificates to all participants and verify them through a trust chain. Add all CA certificates to $GOPATH/src/PSC/CA/certs folder.

## Generate Public key pair (TS, CP, DP)

Use the keypair.sh script to generate public key pairs for any CP(s), DP(s), or TS in the network. (Remember to modify default certificate folder in openssl.cnf)

```
    cd $GOPATH/src/PSC
    ./keypair.sh <usr> <usr_common_name>
```

### Arguments:
```
    <usr>           "CP", "DP" or "TS"
    <usr_common_name>   Common name
```

PSC uses the common name in the certificate to uniquely identify a node. So, use a unique common name for every \<usr\> while generating certificates. Forward the <common_name> and <hostname/ip>:<port> of the CP(s) and DP(s) to the TS.

## Tally Server

### Configuration

#### Listen Address

Choose an IP address and port that is accessible on the Internet. Forward the <TS_common_name> and <TS_hostname/ip>:<TS_port> to CP(s) and DP(s). Receive <common_name> and <hostname/ip>:<port> of all CP(s) and DP(s).

Set the PSC parameters in $GOPATH/src/PSC/TS/config/Gen_Config.go:

```
    const no_CPs = 2 //No.of CPs
    const no_DPs = 2 //No. of DPs
    const b = 2000 //Hash table size
    var cp_cnames = []string{"CP1", "CP2"} //CP common names
    var dp_cnames = []string{"DP1", "DP2"} //DP common names
    var cp_addr = []string{"10.176.5.24:6100", "10.176.5.25:6100"} //CP addresses
    var dp_addr = []string{"10.176.5.22:7100", "10.176.5.23:7100"} //DP addresses
    var epoch = 1 //Epoch for data collection
    var qname = "ExitSecondLevelDomainWebInitialStream" //Query name
    //var qname = "ExitSecondLevelDomainAlexaWebInitialStream" //Query name
    //var qname = "EntryRemoteIPAddress" //Query name
    //var qname = "EntryRemoteIPAddressCountry" //Query name
    //var qname = "EntryRemoteIPAddressAS" //Query name
    //var qlist = []string{"0", "-1"} //Query list
    //var qlist = []string{"15169", "56203", "6939"} //Query list
    //var qlist = []string{"US", "AA"} //Query list
    var qlist []string //Query list
    var qfile = map[string]string{"domain":"sld-Alexa-top-1m.txt"} //Filename map
    //var qfile = map[string]string{"ipv4":"as-ipv4-coalesced-20171126.ipasn", "ipv6":"as-ipv6-20171127.ipasn"} //Filename map
    var n = int64(789592)  //No. of noise vectors
```

And generate configuration:

```
    cd $GOPATH/src/PSC/TS/config/
    go run Gen_Config.go
```

Be careful while collecting and releasing PSC results: the configured epsilon and delta must protect a typical user's activity over a long enough period. And the collection period must be long enough to aggregate usage from many users (we use multiple days).

PSC is not designed for automated collection and results release: a long enough series of results can identify the activity of a single user.

#### PSC      

Then run PSC in Tally Server mode:

```
    cd $GOPATH/src/PSC/TS/
    go run ts.go -t "<TS_common_name>" -p "<TS_port>"
```

The run_psc.sh script provides an easy way to (re)start PSC:

```
    cd $GOPATH/src/PSC/
    ./run_psc.sh <goenvironment_name> TS CName Port RestartSeconds [OptArg...]
```

Note: if you specify any optional arguments, they must be all one string
(use a single pair of double quotes around them all). For example:
`"-c config/config.params -e 1"`

##### Optional arguments:
```
    -h   TS hostname to which to bind
    -c   Configuration file path
    -e   No. of experiments
```

## Computation Parties

### Configuration

#### Listen Address

Choose an IP address and port that is accessible on the Internet. Forward the <CP_common_name> and <CP_hostname/ip>:<CP_port> to TS. Receive <TS_common_name> and <TS_hostname/ip>:<TS_port>.

Set the TS information in $GOPATH/src/PSC/CP/ts.info:

```
    Addr <TS_hostname/ip>:<TS_port>
    CN <TS_common_name>
```

#### PSC

Run PSC in Computation Party mode:

```
    cd $GOPATH/src/PSC/CP/
    go run cp.go -c "<CP_common_name>" -p "<CP_port>"
```

The run_psc.sh script provides an easy way to (re)start PSC:

```
    cd $GOPATH/src/PSC/
    ./run_psc.sh <goenvironment_name> CP CName Port RestartSeconds [OptArg...]
```

Note: if you specify any optional arguments, they must be all one string
(use a single pair of double quotes around them all). For example:
`"-t ./ts.info"`

##### Optional arguments:
```
    -h    CP hostname to which to bind
    -t 	  TS information file path
```

## Data Parties

You need one PSC Data Party per tor relay.

### Configuration

#### Listen Address

Choose an IP address and port that is accessible on the Internet. Forward the <DP_common_name> and <DP_hostname/ip>:<DP_port> to TS. Receive <TS_common_name> and <TS_hostname/ip>:<TS_port>.

Set the TS information in $GOPATH/src/PSC/DP/ts.info:

```
    Addr <TS_hostname/ip>:<TS_port>
    CN <TS_common_name>
```

#### Relay Creation

The most up to date instructions are located here:

```
    https://github.com/privcount/privcount/blob/master/DEPLOY.markdown#data-collectors
```

If you are setting up your relays for the first time, we recommend you use a
script to create consistent relay configs. Debian and Ubuntu have:

    tor-instance-create

It creates a --defaults-torrc file in /etc/tor, and individual torrc files and
systemd configs for each relay.

If your distribution doesn't come with a script like this, we recommend you
configure your tor relays using a --defaults-torrc file for common settings:

    tor --defaults-torrc /etc/tor/torrc-defaults

#### Automatic Configuration

PSC does not set ```EnablePrivCount 1``` by default, so you must set it in
the torrc for each relay. This allows multiple simultaneous collections by
different projects, using the same relays. Having EnablePrivCount on all the
time might cause some bias towards long-running connections, circuits, or
streams. But we think these biases are small.

If PSC is configured to set ```EnablePrivCount 1```, it sets the option when
it starts a collection round, and turns it off at the end of the round. And
it also sets ```__ReloadTorrcOnSIGHUP 0``` to prevent the PrivCount option
being turned off by a HUP. This means that you can't change any torrc options
during a collection.

#### Tor Control Port

PSC securely authenticates to tor's control port. This prevents the
control port being used to run commands as the tor user.

You can configure a TCP port:

torrc:

```
ControlPort <control_port> //Default control port number is 9051
```

Cookie authentication requires the PSC user to have read access to tor's
cookie file. Password authentication requires a shared secret configured using
the event_source's control_password option.

Cookie Authentication (more secure, simpler):

torrc:
```
CookieAuthentication 1
```

Password Authentication:

```
cat /dev/random | hexdump -e '"%x"' -n 32 -v > $GOPATH/src/PSC/DP/control_password.txt
tor --hash-password `cat $GOPATH/src/PSC/DP/control_password.txt`
```

torrc:

```
HashedControlPassword (output of tor --hash-password)
```

#### PrivCount-Patched Tor

Start your PrivCount-patched tor relays. If you need to install a PrivCount-patched tor, see the instructions in INSTALL.markdown.

Start tor relay manually:

    screen
    /usr/local/bin/tor -f /path/to/torrc --defaults-torrc /path/to/torrc-defaults 2>&1 | tee -a tor.log


#### PSC

Then run PSC in Data Party mode:

```
    cd $GOPATH/src/PSC/DP/
    go run dp.go -d "<DP_common_name>" -p "<DP_port>"
```

The run_psc.sh script provides an easy way to (re)start PSC:

```
    cd $GOPATH/src/PSC/
    ./run_psc.sh <goenvironment_name> DP CName Port RestartSeconds [OptArg...]
```

Note: if you specify any optional arguments, they must be all one string
(use a single pair of double quotes around them all). For example:
`"-cp 1234 -t ./ts.info"`

##### Optional arguments:
```
    -h    DP hostname to which to bind
    -ca   Tor control port listen address
    -cp   Tor control port
    -pf   Tor control hashed password file path
    -t    TS information file path
    -pe   PrivCount enable (true/false)
```
