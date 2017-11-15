/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University
*/

package main

import (
    "crypto/tls"
    "encoding/binary"
    "fmt"
    "github.com/dedis/crypto/abstract"
    "github.com/dedis/crypto/nist"
    "github.com/golang/protobuf/proto"
    "io/ioutil"
    "net"
    "os"
    "PSC/DP/dpres"
    "PSC/DP/No_of_UniqueIPs/ipcount"
    "strconv"
    "sync"
    "syscall"
)

func main() {
    b := 500 //No of entries in IP table
    no_CPs := 5 //No.of CPs
    no_DPs := 5 //No. of DPs
    agg := 0 //Actual Aggregate

    uniqIPList := make([]int64, b)

    for i := 0; i < no_DPs; i++ {

        //Read IPs Count from file
        in, err := ioutil.ReadFile("No_of_UniqueIPs/Original/dp" + strconv.Itoa(int(i)) + ".in")
        checkError(err)
        uniq_IP_List := &IPcount.UniqIP{}
        err = proto.Unmarshal(in, uniq_IP_List)
        checkError(err)

        k_ij := make([][]abstract.Scalar, b) //DP-CP Shared Key List
        c_j := make([]abstract.Scalar, b) //IP Counters
        c_ij := make([][]abstract.Scalar, b) //Random Shares of IP Counters     
        suite := nist.NewAES128SHA256P256()
        rand := suite.Cipher(abstract.RandomKey)

        //Iterate over all IP counters
        for j := 0; j < b; j++ {

            k_ij[j] = make([]abstract.Scalar, no_CPs) //Initialize DP-CP shared List
            c_ij[j] = make([]abstract.Scalar, no_CPs) //Initialize Random Shares List
            c_j[j] = suite.Scalar().Zero()
        }

        //Iterate over all CPs
        for j := 0; j < no_CPs; j++ {

            //Iterate over all IP counters
            for k := 0; k < b; k++ {
                k_ij[k][j] = suite.Scalar().Pick(rand) //Choose random keys
                c_j[k] = suite.Scalar().Add(c_j[k], k_ij[k][j]) //Add keys to each counter
            }
        }

        //Iterate over all IP counters
        for j := 0; j < b; j++ {

            //If the IP is observed
            if uniq_IP_List.C[j] == 1 {

                uniqIPList[j] = 1 //Set to 1 to Compute Actual Aggregate
                c_j[j] = suite.Scalar().Pick(rand) //Increment by adding a random number
            }
        }

        //Iterate over all IP counters
        for j := 0; j < b; j++ {

            tmp := suite.Scalar().Zero() //Sum of Random Shares except last CP's

            //Iterate over all CPs
            for k := 0; k < no_CPs - 1; k++ {

                c_ij[j][k] = suite.Scalar().Pick(rand) //Choose Random Value
                tmp = suite.Scalar().Add(c_ij[j][k], tmp)
            }
            c_ij[j][no_CPs - 1] = suite.Scalar().Sub(c_j[j], tmp) //Compute last Random Share
        }

        var wg sync.WaitGroup //WaitGroup counter

        wg.Add(no_CPs) //Increment WaitGroup counter

        //Iterate over all CPs
        for j := 0; j < no_CPs; j++ {

            fmt.Printf("dp %d cp %d \n", int(i) + 1, j + 1)

            resp := new(DPres.Response) //DP Key and Random Share
            resp.K = make([][]byte, b) //Initialize Key Share
            resp.C = make([][]byte, b) //Initialize Random Share

            //Iterate over all IP Counters
            for k := 0; k < b; k++ {

               resp.K[k] = k_ij[k][j].Bytes()
               resp.C[k] = c_ij[k][j].Bytes()
            }

            //Convert to bytes
            resp1, err := proto.Marshal(resp)
            checkError(err)
            
            //Send Data to Server
            sendDataToDest(resp1, int(i), j + 1)
        }
    }

    for i := 0; i < b; i++ {

        if(uniqIPList[i] == 1) {
            agg += 1
        }
    }
    fmt.Printf("Aggregate = %d \n", agg)
}

//Input: Data, Destination
//Function: Send Data to Destination
func sendDataToDest(data []byte, src int, dst int) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/DP1.cert", "private/DP1.key")
    checkError(err)

    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    //Dial TCP Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, InsecureSkipVerify: true} #ServerName: "CP" + strconv.Itoa(dst),}
    con,err := net.Dial("tcp", "localhost:606" + strconv.Itoa(dst))
    checkError(err)

    //Convert to TLS Connection
    file, err := con.(*net.TCPConn).File()
    err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
    conn := tls.Client(con, &config)

    l := make([]byte, 4) //Length of Data sent in bytes
    binary.BigEndian.PutUint32(l, uint32(len(data)))
    data = append(l, data...) //Append length to data
    _, err = conn.Write(data) //Send Data to Destination
    checkError(err)
}

//Input: Error
//Function: Check Error
func checkError(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
        os.Exit(1)
    }
}
