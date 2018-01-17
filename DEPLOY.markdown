# Deployment

First, download and install the latest version of PSC. If you are running a Data Party, also download, compile, install, and launch the latest version of the Tor PrivCount patch.

See INSTALL.markdown for details.

## Generate network CA Key 

Generate new CA key for each network that runs PSC. See CAInstructions.markdown for details.

## Exchange CA certificates 

Verify CA certificates through a trust chain. Add all CA certificates to PSC/CA/certs folder.

## Generate Public key pair (TS, CP, DP)

Use the network CA key to generate public key pairs for any CP(s), DP(s), or TS in the network. See CAInstructions.markdown for details. 
PSC uses the common name in the certificate to uniquely identify a node. So, forward the <common_name> and <ip> of the CP(s) and DP(s) to the TS.

## Tally Server

### Configuration

#### Listen Address

Choose an IP address that is accessible on the Internet on port 5100. Forward the <common_name> and <ip> of the TS to CP(s) and DP(s).

Set the PSC parameters in PSC/TS/config/Gen_Config.go:

```
    const no_CPs = 3 //No.of CPs
    const no_DPs = 1 //No. of DPs
    const b = 2000 //Hash table size
    var cp_hname = []string{"CP1", "CP2", "CP3"} //CP hostnames
    var dp_hname = []string{"DP1"}//, "DP2", "DP3", "DP4", "DP5"} //DP hostnames
    var cp_ips = []string{"10.176.5.52", "10.176.5.53", "10.176.5.54"} //CP IPs
    var dp_ips = []string{"10.176.5.20"} //{"10.176.5.16", "10.176.5.17", "10.176.5.18", "10.176.5.19", "10.176.5.20"} //DP IPs
    var epoch = 1 //Epoch for data collection
    var epsilon = 0.3 //Epsilon
    var delta = math.Pow(10, -12) //Delta
    var query = "ExitFirstLevelDomainWebInitialStream" //Query
```

Be careful while collecting and releasing PSC results: the configured epsilon and delta must protect a typical user's activity over a long enough period. And the collection period must be long enough to $

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
    go run ts.go -t "<TS_common_name>" -i "<TS_IP>"
```

##### Optional arguments:
```
    -c   Configuration file path
    -e   No. of experiments
```

## Computation Parties

### PSC

Run PSC in Computation Party mode:

```
    cd PSC/CP/
    go run cp.go -c "<CP_common_name>" -i "<CP_IP>"
```

## Data Parties

You need one PrivCount Data Party per tor relay.

### Configuration

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
ControlPort <control_port_number> //Default control port number is 9051
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
    go run ts.go -d "<DP_common_name>" -i "<DP_IP>"
```

##### Optional arguments:
```
    -ca   Tor control port listen address
    -cp   Tor control port
    -pf   Tor control hashed password file path
```
