# Deployment

First, download and install the latest version of PSC. If you are running a Data Party, also download, compile, install, and launch the latest version of the Tor PrivCount patch.

See INSTALL.markdown for details.

## Generate network CA Key 

Generate new CA key for each network that runs PSC. See CAInstructions.markdown for details.

## Exchange CA certificates 

Send CA certificates to all participants and verify them through a trust chain. Add all CA certificates to PSC/CA/certs folder.

## Generate Public key pair (TS, CP, DP)

You can use PSC/keypair.sh to generate public key pairs for any CP(s), DP(s), or TS in the network. (Remember to modify default certificate folder in openssl.cnf)

```
    ./keypair.sh <usr> <usr_common_name>
```

### Arguments:
```
    <usr>           "CP", "DP" or "TS"
    <usr_common_name>   Common name
```

Enter <usr_common_name> when prompted and use a random passphrase. Refer CAInstructions.markdown for detailed step by step instruction. 

PSC uses the common name in the certificate to uniquely identify a node. So, forward the <common_name> and <hostname/ip>:<port> of the CP(s) and DP(s) to the TS.

## Tally Server

### Configuration

#### Listen Address

Choose an IP address and port that is accessible on the Internet. Forward the <TS_common_name> and <TS_hostname/ip>:<TS_port> to CP(s) and DP(s). Receive <common_name> and <hostname/ip>:<port> of all CP(s) and DP(s).

Set the PSC parameters in PSC/TS/config/Gen_Config.go:

```
    const no_CPs = 2 //No.of CPs
    const no_DPs = 2 //No. of DPs
    const b = 2000 //Hash table size
    var cp_cnames = []string{"CP1", "CP2"} //CP common names
    var dp_cnames = []string{"DP1", "DP2"} //DP common names
    var cp_addr = []string{"10.176.5.24:6100", "10.176.5.25:6100"} //CP addresses
    var dp_addr = []string{"10.176.5.22:7100", "10.176.5.23:7100"} //DP addresses
    var epoch = 1 //Epoch for data collection
    var epsilon = 0.3 //Epsilon
    var delta = math.Pow(10, -13) //Delta
    var query = "ExitFirstLevelDomainWebInitialStream" //Query
```

Be careful while collecting and releasing PSC results: the configured epsilon and delta must protect a typical user's activity over a long enough period. And the collection period must be long enough to aggregate usage from many users (we use multiple days).

PSC is not designed for automated collection and results release: a long enough series of results can identify the activity of a single user.

After configuring parameters, run Gen_Config.go:

```
    cd PSC/TS/config
    go run Gen_Config.go
```

#### PSC      

Then run PSC in Tally Server mode:

```
    cd PSC/TS/
    go run ts.go -t "<TS_common_name>" -p "<TS_port>"
```

##### Optional arguments:
```
    -c   Configuration file path
    -e   No. of experiments
```

## Computation Parties

### Configuration

#### Listen Address

Choose an IP address and port that is accessible on the Internet. Forward the <CP_common_name> and <CP_hostname/ip>:<CP_port> to TS. Receive <TS_common_name> and <TS_hostname/ip>:<TS_port>.

Set the TS information in PSC/CP/ts.info:

```
    Addr <TS_hostname/ip>:<TS_port>
    CN <TS_common_name>
```

### PSC

Run PSC in Computation Party mode:

```
    cd PSC/CP/
    go run cp.go -c "<CP_common_name>" -p "<CP_port>"
```

## Data Parties

You need one PSC Data Party per tor relay.

### Configuration

#### Listen Address

Choose an IP address and port that is accessible on the Internet. Forward the <DP_common_name> and <DP_hostname/ip>:<DP_port> to TS. Receive <TS_common_name> and <TS_hostname/ip>:<TS_port>.

Set the TS information in PSC/DP/ts.info:

```
    Addr <TS_hostname/ip>:<TS_port>
    CN <TS_common_name>
```

#### Relay Creation

If you are setting up your relays for the first time, we recommend you use a
script to create consistent relay configs. Debian and Ubuntu have:

    tor-instance-create

It creates a --defaults-torrc file in /etc/tor, and individual torrc files and
systemd configs for each relay.

If your distribution doesn't come with a script like this, we recommend you
configure your tor relays using a --defaults-torrc file for common settings:

    tor --defaults-torrc /etc/tor/torrc-defaults

#### Automatic Configuration

PSC sets ```EnablePrivCount 1``` when it starts a collection round, and
turns it off at the end of the round. This makes sure that all the totals it
collects are consistent. You MUST NOT set EnablePrivCount in the torrc: this
biases the results towards long-running connections.

When PSC is collecting data, it sets ```__ReloadTorrcOnSIGHUP 0``` to
prevent the PrivCount option being turned off by a HUP. This means that you
can't change any torrc options during a collection.

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
cat /dev/random | hexdump -e '"%x"' -n 32 -v > PSC/DP/control_password.txt
tor --hash-password `cat control_password.txt`
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
    cd PSC/DP/
    go run ts.go -d "<DP_common_name>" -p "<DP_port>"
```

##### Optional arguments:
```
    -ca   Tor control port listen address
    -cp   Tor control port
    -pf   Tor control hashed password file path
```
