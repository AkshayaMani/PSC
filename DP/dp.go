/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University
*/

package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "flag"
    "fmt"
    "github.com/dedis/crypto/abstract"
    "github.com/dedis/crypto/nist"
    "github.com/golang/protobuf/proto"
    "io"
    "io/ioutil"
    "math"
    "net"
    "os"
    "PSC/DP/dpres"
    "PSC/TS/tsmsg"
    "sync"
    "syscall"
)

var no_CPs int32 //No.of CPs
var no_DPs int32 //No. of DPs
var epoch int //Epoch
var b int64 //Hash table size
var n int64 //No. of noise vectors

var ts_hname = "TS" //TS hostname
var ts_ip = "10.176.5.16" //TS IP
var cp_hname []string //CP hostnames
var dp_hname []string //DP hostnames
var cp_ips []string //CP IPs
var dp_ips []string //DP IPs
var dp_cname string //DP common name
var f_flag bool //Finish Flag
var step_no uint32 //DP Step Number
var ts_s_no uint32 //TS Session No.
var ts_config_flag bool //TS configuration flag
var ln net.Listener //Server listener
var finish chan bool //Channel to send finish flag
var k []abstract.Scalar //CP-DP Keys
var c []abstract.Scalar //Ciphers
var cs [][]abstract.Scalar //Cipher share
var mutex = &sync.Mutex{} //Mutex to lock common client variable
var wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown

func main() {

    dp_ip := parseCommandline(os.Args) //Parse DP common name

    for{
        //Initialize global variables
        initValues()

        //Listen to the TCP port
        ln, _ = net.Listen("tcp", dp_ip+":7100")

        fmt.Println("Started Data Party")

        //Channel to handle simultaneous connections
        clients := make(chan net.Conn)

        loop:

        for{

            conn, err := acceptConnections() //Accept connections

            if conn != nil { //If Data is available

                //Parse Common Name
                com_name := parseCommonName(conn)

                if com_name == ts_hname { //If TS

                    wg.Add(1) //Increment WaitGroup counter

                    //Handle connections in separate channels
                    go handleClients(clients, com_name)

                    //Handle each client in separate channel
                    clients <- conn

                } else { //If not TS

                    conn.Close() //Close connection
                }

            } else if err != nil {

                select {

                    case <-finish:

                        wg.Wait()                            

                        if step_no == 4 { //Finish

                            //Finishing measurement
                            fmt.Println("Finished measurement.")

                        } else {

                            //Quit and Re-start measurement
                            fmt.Println("Quitting... \n Re-starting measurement...")
                        }

                        break loop

                    default:
                }
            }
        }
    }
}

//Input: Finish flag, Session no.
//Function: Send TS signal
func sendTSSignal(fin bool, sno uint32) {

    sig := new(TSmsg.Signal) //TS signal

    sig.Fflag = proto.Bool(fin) //Set TS signal finish flag

    //Set TS session no.
    sig.SNo = proto.Int32(int32(sno))

    //Convert to Bytes
    sigb, _ := proto.Marshal(sig)

    //Send signal to TS
    sendDataToDest(sigb, ts_hname, ts_ip+":5100")
}

//Input: Client Socket Channel, Client common name
//Function: Handle client connection 
func handleClients(clients chan net.Conn, com_name string) {

    defer wg.Done() //Decrement counter when goroutine completes

    //Wait for next client connection to come off queue.
    conn := <-clients

    //Receive Data
    buf := receiveData(conn)

    mutex.Lock() //Lock mutex

    if f_flag == false { //Finish flag not set

        if ts_config_flag == true { //If TS configuration flag set

            ts_config_flag = false //Set configuration flag to false
       
            if com_name == ts_hname { //If data received from TS

                config := new(TSmsg.Config) //TS configuration
                proto.Unmarshal(buf, config) //Parse TS configuration

                assignConfig(config) //Assign configuration

                fmt.Println("Sending TS signal. Step No.", step_no)
                sendTSSignal(false, ts_s_no+step_no) //Send finish signal to TS

                step_no = 1 //TS step no.
                
            } else { //Data not received from TS

                fmt.Println("Error: Data not sent by Tally Server")

                sendTSSignal(true, ts_s_no+step_no) //Send finish signal to TS

                return
            }

        } else {

            if com_name == ts_hname { //If Data Received from TS

                sig := new(TSmsg.Signal) //TS signal
                proto.Unmarshal(buf, sig) //Parse TS signal

                if *sig.Fflag == true { //If finish flag set

                    shutdownDP() //Shutdown DP gracefully 

                } else { //Finish flag not set

                    if *sig.SNo == int32(ts_s_no+step_no) { //Check TS step no. 

                        suite := nist.NewAES128SHA256P256()
                        rand := suite.Cipher(abstract.RandomKey)
                        
                        if step_no == 1 { //If step no. 1

                            //Iterate over all CPs
                            for i := int32(0); i < no_CPs; i++ {

                                resp := new(DPres.Response) //CP-DP keys
                                resp.TSsno = proto.Int32(int32(ts_s_no+step_no)) //Initialize step no.

                                //Initialize CP-DP key
                                resp.M = make([][]byte, b)

                                //Iterate over hash table
                                for j := int64(0); j < b; j++ {

                                    k[j] = suite.Scalar().Pick(rand) //Choose random keys
                                    resp.M[j] = k[j].Bytes() //Assign CP-DP keys

                                    c[j] = suite.Scalar().Add(c[j], k[j]) //Add keys to each counter
                                }

                                //Convert to bytes
                                resp1, err := proto.Marshal(resp)
                                checkError(err)

                                //Send key to CP
                                fmt.Println("Sending symmetric key to CP", i,". Step No.", step_no)
                                sendDataToDest(resp1, cp_hname[i], cp_ips[i]+":6100")
	                    }

                            k = nil //Forget keys

                        } else if step_no == 2 { //If step no. 2

                            fmt.Println("Started data collection")
                            collectData() //Start collecting data

                        } else if step_no == 3 { //If step no. 3

                            //Iterate over hash table
                            for i := int64(0); i < b; i++ {

                                tmp := suite.Scalar().Zero() //Sum of random shares except last CP's

                                //Iterate over all CPs
                                for j := int32(0); j < no_CPs - 1; j++ {

                                    cs[i][j] = suite.Scalar().Pick(rand) //Choose Random Value
                                    tmp = suite.Scalar().Add(cs[i][j], tmp) //Add CP masked data share
                                }

                                cs[i][no_CPs - 1] = suite.Scalar().Sub(c[i], tmp) //Compute last data share
                            }

                            //Iterate over all CPs
                            for i := int32(0); i < no_CPs; i++ {

                                resp := new(DPres.Response) //DP step no. and masked data share
                                resp.TSsno = proto.Int32(int32(ts_s_no+step_no)) //Initialize step no.
                                resp.M = make([][]byte, b) //Initialize masked data share

                                //Iterate over hash table
                                for j := int64(0); j < b; j++ {

                                    resp.M[j] = cs[j][i].Bytes()
                                }

                                //Convert to bytes
                                resp1, err := proto.Marshal(resp)
                                checkError(err)

                                //Send data shares to CP
                                fmt.Println("Sending masked data shares to CP", i,". Step No.", step_no)
                                sendDataToDest(resp1, cp_hname[i], cp_ips[i]+":6100")
                            }
                        }

                        sendTSSignal(false, ts_s_no+step_no) //Send signal to TS
                        fmt.Println("Sent TS signal ", step_no)

                        step_no += 1 //Increment step no.

                    } else { //Wrong signal from TS

                        fmt.Println("Err: Wrong signal from TS")

                        sendTSSignal(true, ts_s_no+step_no) //Send finish signal to TS

                        return
                    }
                }
            }
        }
    }

    mutex.Unlock() //Unlock mutex
}

//Function: Collect data from Tor using oblivious counters
func collectData () {

    //c[event].Add(c[event], suite.Scalar().Pick(rand)) //Increment counter by adding a random number
}

//Input: Command-line Arguments
//Function: Parse Command-line Arguments
func parseCommandline(arg []string) (string){

    var dp_ip string //DP IP

    flag.StringVar(&dp_cname, "d", "", "DP common name (required)")
    flag.StringVar(&dp_ip, "i", "", "DP IP (required)")
    flag.Parse()

    if dp_cname == "" {

        fmt.Println("Argument required:")
        fmt.Println("     -d string")
        fmt.Println("     DP common name (Required)")
        os.Exit(0) //Exit

    } else if dp_ip == "" {

        fmt.Println("Argument required:")
        fmt.Println("     -i string")
        fmt.Println("     DP IP (Required)")
        os.Exit(0) //Exit
    }

    return dp_ip
}

//Function: Initialize variables
func initValues() {

    no_CPs = 0 //No.of CPs
    no_DPs = 0 //No. of DPs
    epoch = 0 //Epoch
    b = 0 //Hash table size
    n = 0 //No. of noise vectors

    cp_hname = nil //CP hostnames
    dp_hname = nil //DP hostnames
    cp_ips = nil //CP IPs
    dp_ips = nil //DP IPs
    f_flag = false //Finish flag
    step_no = 0 //DP step no.
    ts_s_no = 0 //TS session no.
    ts_config_flag = true //TS configuration flag
    ln = nil //Server listener
    finish = make(chan bool) //Channel to send finish flag
    k = nil //CP-DP Keys
    c = nil //Ciphers                          
    cs = nil //Cipher shares
    mutex = &sync.Mutex{} //Mutex to lock common client variable
    wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown
}

//Input: Configuration from TS
//Output: Assign configuration
func assignConfig(config *TSmsg.Config) {

    ts_s_no = uint32(*config.SNo) //TS session no.
    epoch = int(*config.Epoch) //Epoch
    epsilon := float64(*config.Epsilon) //Privacy parameter - epsilon
    delta := float64(*config.Delta) //Privacy parameter - delta
    n = int64(math.Floor((math.Log(2 / delta) * 64)/math.Pow(epsilon, 2))) + 1 //No. of Noise vectors 
    no_CPs = *config.Ncps //No. of CPs
    cp_hname = make([]string, no_CPs) //CP hostnames
    cp_ips = make([]string, no_CPs) //CP IPs    

    copy(cp_hname[:], config.CPhname) //Assign CP hostnames
    copy(cp_ips[:], config.CPips) //Assign CP IPs

    no_DPs = *config.Ndps //No. of DPs
    dp_hname = make([]string, no_DPs) //DP hostnames
    dp_ips = make([]string, no_DPs) //DP IPs

    copy(dp_hname[:], config.DPhname) //Assign DP hostnames
    copy(dp_ips[:], config.DPips) //Assign DP IPs

    b = *config.Tsize //Hash table size

    k = make([]abstract.Scalar, b) //CP-DP Keys
    c = make([]abstract.Scalar, b) //Ciphers
    cs = make([][]abstract.Scalar, b) //Cipher shares

    suite := nist.NewAES128SHA256P256() 

    //Iterate over the hashtable
    for i := int64(0); i < b; i++ {

        c[i] = suite.Scalar().Zero() //Initialize with zero
        cs[i] = make([]abstract.Scalar, no_CPs) //Initialize cipher shares list 
    }

    //Iterate over the hashtable
    for i := int32(0); i < no_CPs; i++ {

        k[i] = suite.Scalar().Zero() //Initialize with zero
    }
}

//Input: Client Socket
//Output: Common Name
//Function: Parse Common Name from Certificate
func parseCommonName(conn net.Conn) string {
    var com_name string //Common Name
    tlscon, ok := conn.(*tls.Conn)

    //If TLS connection
    if ok {
        tlscon.Handshake()
        for _, v := range tlscon.ConnectionState().PeerCertificates {
            com_name = v.Subject.CommonName //Get Common Name
        }
    }

    return com_name
}

//Input: Socket, Number of Bytes
//Output: Message Buffer
//Function: Read Exactly n Bytes from the Socket
func socketReadN(conn net.Conn, n uint32) []byte {
    buf := make([]byte, n)
    _, err := io.ReadFull(conn,buf) //Read n Bytes
    checkError(err)
    return buf
}

//Input: Socket
//Output: Message
//Function: Read Message from Socket
func receiveData(conn net.Conn) []byte {
    len_buf := socketReadN(conn, 4) //Read Message Length
    msg_len := binary.BigEndian.Uint32(len_buf) //Length of Message
    msg_buf := socketReadN(conn, msg_len) //Read Message
    return msg_buf
}

//Input: CP common name
//Output: Socket
//Function: Accept new connections in  Socket
func acceptConnections() (*tls.Conn, error) {
    //Create Server Socket
    cert, err1 := tls.LoadX509KeyPair("certs/"+ dp_cname +".cert", "private/" + dp_cname + ".key")
    checkError(err1)

    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    //Create TLS Listener and Accept Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caCertPool, ClientAuth: tls.RequireAndVerifyClientCert,}
    conn, err := ln.Accept()

    var sock *tls.Conn //Client socket

    //If error
    if err != nil {

        return nil, err

    } else { //If not error

        file, _ := conn.(*net.TCPConn).File()
        err1 = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
        sock = tls.Server(conn, &config)
    }

    return sock, err
}

func sendDataToDest(data []byte, dst_hname string, dst_addr string) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/" + dp_cname + ".cert", "private/" + dp_cname + ".key")
    checkError(err)

    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    //Dial TCP Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, ServerName: dst_hname,} //InsecureSkipVerify: true,}
    con,err := net.Dial("tcp", dst_addr)
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

//Function: Shutdown DP gracefully
func shutdownDP() {

    f_flag = true //Set finish flag

    close(finish) //Quit

    ln.Close() //Shutdown DP gracefully
}

//Input: Party list, Party name
//Output: Boolean output
//Function: Check if party in party list
func contains(pl []string, p string) bool {

    for _, party := range pl {

        if party == p {

            return true
        }
    }

    return false
}

//Input: Error
//Function: Check Error
func checkError(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
        os.Exit(1)
    }
}
