/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University
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
    var cp_hname = []string{"CP1", "CP2", "CP3"} //CP hostnames
    var dp_hname = []string{"DP1"}//, "DP2", "DP3", "DP4", "DP5"} //DP hostnames
    var cp_ips = []string{"10.176.5.52", "10.176.5.53", "10.176.5.54"} //CP IPs
    var dp_ips = []string{"10.176.5.20"} //{"10.176.5.16", "10.176.5.17", "10.176.5.18", "10.176.5.19", "10.176.5.20"} //DP IPs
    var epoch = 1 //Epoch for data collection
    var epsilon = 0.3 //Epsilon
    var delta = math.Pow(10, -12) //Delta
    var query = "ExitFirstLevelDomainWebInitialStream" //Query

    //Assign PSC configuration parameters
    config := new(TSmsg.Config)
    config.SNo  = proto.Int32(int32(0))
    config.Epoch = proto.Int32(int32(epoch))
    config.Epsilon = proto.Float32(float32(epsilon))
    config.Delta = proto.Float32(float32(delta))
    config.Ncps = proto.Int32(int32(no_CPs))
    config.CPhname = make([]string, no_CPs)
    config.CPips = make([]string, no_CPs)

    copy(config.CPhname[:], cp_hname)
    copy(config.CPips[:], cp_ips)

    config.Ndps = proto.Int32(int32(no_DPs))
    config.DPhname = make([]string, no_DPs)
    config.DPips = make([]string, no_DPs)

    copy(config.DPhname[:], dp_hname)
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
    fmt.Println("CP Hostnames:", config1.CPhname)
    fmt.Println("CP IPs:", config1.CPips)
    fmt.Println("No. of DPs:", *config1.Ndps)
    fmt.Println("DP Hostnames:", config1.DPhname)
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
