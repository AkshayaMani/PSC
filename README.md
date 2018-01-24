## Private Set-Union Cardinality (PSC)


# Description

PSC makes Tor statistics collection secure by providing differential privacy guarantees for Tor users.

PSC efficiently aggregates the count of unique items across a set of participating Tor relays "privately" -- that is, it does not expose any information other than the count.   


# Paper and License

For more information about PSC, refer:

```
  Distributed Measurement with Private Set-Union Cardinality
  24th ACM Conference on Computer and Communication Security (CCS 2017)
  Ellis Fenske*, Akshaya Mani*, Aaron Johnson, and Micah Sherr (* co-first authors)
  https://security.cs.georgetown.edu/~msherr/papers/psc.pdf
```

See LICENSE for licensing information.


# Installation

To run the Tally Server or a Computation Party, install PSC and its dependencies.

To run a Data Party, install PSC, a PrivCount-patched Tor instance, and all their dependencies.

See INSTALL.markdown for details.


# Running

To run PSC, simply activate the virtual environment that you created earlier and then run PSC. For example:

```
  nv on <goenvironment_name>
  ...
  nv off
```


# Deployment

To deploy a PSC network, configure collection period and noise to protect typical user activity.

Send CA certificates to all participants and verify them through a trust chain. Add all CA certificates to PSC/CA/certs.

Install, configure, and start all the Computation Parties and Data Prties.

Install, configure and start the Tally Server. Your network should start collecting automatically.

See DEPLOY.markdown for details.
