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
    "math"
    "PSC/TS/tsmsg"
)

func main() {

    const no_CPs = 3 //No.of CPs
    const no_DPs = 1 //No. of DPs
    const b = 2000 //Hash table size
    var cp_cnames = []string{"CP1", "CP2", "CP3"} //CP common names
    var dp_cnames = []string{"DP1"}//, "DP2", "DP3", "DP4", "DP5"} //DP common names
    var cp_ips = []string{"10.176.5.52", "10.176.5.53", "10.176.5.54"} //CP IPs
    var dp_ips = []string{"10.176.5.20"} //{"10.176.5.16", "10.176.5.17", "10.176.5.18", "10.176.5.19", "10.176.5.20"} //DP IPs
    var epoch = 1 //Epoch for data collection
    var epsilon = 0.3 //Epsilon
    var delta = math.Pow(10, -12) //Delta
    //var query = "ExitFirstLevelDomainWebInitialStream" //Query
    var query = "ExitFirstLevelDomainAlexa1MWebInitialStream" //Query

    //Assign PSC configuration parameters
    config := new(TSmsg.Config)
    config.SNo  = proto.Int32(int32(0))
    config.Epoch = proto.Int32(int32(epoch))
    config.Epsilon = proto.Float32(float32(epsilon))
    config.Delta = proto.Float32(float32(delta))
    config.Ncps = proto.Int32(int32(no_CPs))
    config.CPcnames = make([]string, no_CPs)
    config.CPips = make([]string, no_CPs)

    copy(config.CPcnames[:], cp_cnames)
    copy(config.CPips[:], cp_ips)

    config.Ndps = proto.Int32(int32(no_DPs))
    config.DPcnames = make([]string, no_DPs)
    config.DPips = make([]string, no_DPs)

    copy(config.DPcnames[:], dp_cnames)
    copy(config.DPips[:], dp_ips)

    config.Tsize = proto.Int64(int64(b))
    config.Query = proto.String(query)

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
    fmt.Println("Epsilon:", *config1.Epsilon)
    fmt.Println("Delta:", *config1.Delta)
    fmt.Println("No. of CPs:", *config1.Ncps)
    fmt.Println("CP common names:", config1.CPcnames)
    fmt.Println("CP IPs:", config1.CPips)
    fmt.Println("No. of DPs:", *config1.Ndps)
    fmt.Println("DP common names:", config1.DPcnames)
    fmt.Println("DP IPs:", config1.DPips)
    fmt.Println("Table size:", *config1.Tsize)
    fmt.Println("Query:", *config1.Query)
}

//Check Error
func check(e error) {
    if e != nil {
        panic(e)
    }
}
