/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University
*/

package main

import (
        "github.com/golang/protobuf/proto"
        "io/ioutil"
        "privcardinality/DP/No_of_UniqueIPs/ipcount"
        //"fmt"
        "math/rand"
        "strconv"
        "time"
)

func main() {

    for i := 0; i < 100; i++ {

        seed := rand.NewSource(time.Now().UnixNano())
        rnd := rand.New(seed)

        no_of_uniqIPs := rnd.Intn(1000 - 1) + 1
        uniq_IP_List := new(IPcount.UniqIP)
        uniq_IP_List.C = make([]int64, 500000)
 
        for j := 0; j < no_of_uniqIPs; j++ {   
            seed := rand.NewSource(time.Now().UnixNano())
            rnd := rand.New(seed)
            uniq_IP_List.C[rnd.Int63n(500000)] = 1    
        }

        out, err := proto.Marshal(uniq_IP_List)
        check(err)
        err = ioutil.WriteFile("Original/dp" + strconv.Itoa(i) + ".in", out, 0644)
        check(err)

        /*in, err := ioutil.ReadFile("Original/dp" + strconv.Itoa(i) + ".in")
        check(err)
        uniq_IP_List1 := &IPcount.UniqIP{}
        err = proto.Unmarshal(in, uniq_IP_List1)
        check(err)*/
    }
}

//Check Error
func check(e error) {
    if e != nil {
        panic(e)
    }
}


