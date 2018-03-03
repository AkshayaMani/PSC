/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University

See LICENSE for licensing information
*/

package main

import (
    "fmt"
    "github.com/golang/protobuf/proto"
    "io/ioutil"
    "PSC/TS/tsmsg"
)

func main() {

    const no_CPs = 2 //No.of CPs
    const no_DPs = 2 //No. of DPs
    const b = 2000 //Hash table size
    var cp_cnames = []string{"CP1", "CP2"} //CP common names
    var dp_cnames = []string{"DP1", "DP2"} //DP common names
    var cp_addr = []string{"10.176.5.24:6100", "10.176.5.25:6100"} //CP addresses
    var dp_addr = []string{"10.176.5.22:7100", "10.176.5.23:7100"} //DP addresses
    var epoch = 1 //Epoch for data collection
    var query = "ExitSecondLevelDomainWebInitialStream"
    //var query = "ExitSecondLevelDomainAlexaWebInitialStream"
    //var query = "EntryRemoteIPAddress"
    //var query = "EntryRemoteIPAddressCountry"
    //var query = "EntryRemoteIPAddressAS"
    //var qlist = []string{"-1"} //Query list
    //var qlist = []string{"15169", "56203", "6939"} //Query list
    //var qlist = []string{"US", "AA"} //Query list
    var qlist []string //Query list
    var n = int64(789592)  //No. of noise vectors

    //Assign PSC configuration parameters
    config := new(TSmsg.Config)
    config.SNo  = proto.Int32(int32(0))
    config.Epoch = proto.Int32(int32(epoch))
    config.Noise = proto.Int64(n)
    config.Ncps = proto.Int32(int32(no_CPs))
    config.CPcnames = make([]string, no_CPs)
    config.CPaddr = make([]string, no_CPs)

    copy(config.CPcnames[:], cp_cnames)
    copy(config.CPaddr[:], cp_addr)

    config.Ndps = proto.Int32(int32(no_DPs))
    config.DPcnames = make([]string, no_DPs)
    config.DPaddr = make([]string, no_DPs)

    copy(config.DPcnames[:], dp_cnames)
    copy(config.DPaddr[:], dp_addr)

    config.Tsize = proto.Int64(int64(b))
    config.Query = proto.String(query)

    config.QList = make([]string, len(qlist))
    copy(config.QList[:], qlist)

    //Write to config file
    out, err := proto.Marshal(config)
    check(err)
    err = ioutil.WriteFile("config.params", out, 0644)
    check(err)

    //Read config file
    in, err := ioutil.ReadFile("config.params")
    check(err)
    config1 := &TSmsg.Config{}
    err = proto.Unmarshal(in, config1)
    check(err)

    //Display config file
    fmt.Println("Session No.:", *config1.SNo)
    fmt.Println("Epoch:", *config1.Epoch)
    fmt.Println("Noise:", *config1.Noise)
    fmt.Println("No. of CPs:", *config1.Ncps)
    fmt.Println("CP common names:", config1.CPcnames)
    fmt.Println("CP IPs:", config1.CPaddr)
    fmt.Println("No. of DPs:", *config1.Ndps)
    fmt.Println("DP common names:", config1.DPcnames)
    fmt.Println("DP IPs:", config1.DPaddr)
    fmt.Println("Table size:", *config1.Tsize)
    fmt.Println("Query:", *config1.Query)
    fmt.Println("Query list:", config1.QList)
}

//Check Error
func check(e error) {
    if e != nil {
        panic(e)
    }
}
