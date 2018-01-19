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
    "gopkg.in/dedis/crypto.v0/abstract"
    "gopkg.in/dedis/crypto.v0/nist"
    "github.com/golang/protobuf/proto"
    "golang.org/x/net/publicsuffix"
    "hash/fnv"
    "io"
    "io/ioutil"
    "math"
    "net"
    "os"
    "PSC/DP/dpres"
    "PSC/goControlTor"
    "PSC/match"
    "PSC/TS/tsmsg"
    "strings"
    "strconv"
    "sync"
    "syscall"
    "time"
)

const p = 200003 //Universal hash parameter p

var no_CPs int32 //No.of CPs
var no_DPs int32 //No. of DPs
var epoch int //Epoch
var b int64 //Hash table size

var ts_hname = "TS" //TS hostname
var ts_ip = "10.176.5.15" //TS IP
var query string //Query
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
var clients chan net.Conn //Channel to handle simultaneous client connections
var k []abstract.Scalar //CP-DP Keys
var c []abstract.Scalar //Ciphers
var cs [][]abstract.Scalar //Cipher share
var wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown

var torControl = &goControlTor.TorControl{} //Tor control port connection
var domain_map = map[string]bool{} //Domain map
var message chan string //Channel to receive message from Tor control port
var q_to_e = map[string]string{ //Map query

    "ExitFirstLevelDomainWebInitialStream": "PRIVCOUNT_STREAM_ENDED",
    "ExitFirstLevelDomainAlexa1MWebInitialStream": "PRIVCOUNT_STREAM_ENDED",
}

func main() {

    dp_ip, control_addr, control_port, passwd_file := parseCommandline(os.Args) //Parse DP common name & IP, Tor control address & port no., and hashed password file path

    torControlPortConnect(control_addr, control_port, passwd_file)

    for{
        //Initialize global variables
        initValues()

        //Listen to the TCP port
        ln, _ = net.Listen("tcp", dp_ip+":7100")

        fmt.Println("Started Data Party")

        wg.Add(1) //Increment WaitGroup counter

        go acceptConnections() //Accept connections

        wg.Add(1) //Increment WaitGroup counter

        go torControlPortReceive(torControl) //Receive events from Tor control port

        loop:

        for{

            select {

                case conn := <- clients:

                    //Parse Common Name
                    com_name := parseCommonName(conn)

                    if ts_hname == com_name {//If data received from TS

                        //Handle TS connection
                        handleTS(conn, com_name)

                    } else { //If not TS

                        conn.Close() //Close connection
                    }

                case msg := <- message:

                    event, _, err1 := torControl.CommandParse(msg) //Print command
                    checkError(err1)

                    if len(event) != 0 {

                        if event[0] == q_to_e[query] {

                            handle_stream_event(event[1:], query)
                        }
                    }

                case <-finish:

                    close(message) //Close Tor control port message channel

                    wg.Wait() //Wait for all go routines to finish

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

//Input: Session no.
//Function: Send TS signal
func sendTSSignal(sno uint32) {

    sig := new(TSmsg.Signal) //TS signal

    sig.Fflag = proto.Bool(f_flag) //Set TS signal finish flag

    //Set TS session no.
    sig.SNo = proto.Int32(int32(sno))

    //Convert to Bytes
    sigb, _ := proto.Marshal(sig)

    //Send signal to TS
    sendDataToDest(sigb, ts_hname, ts_ip+":5100")
}

//Input: Client Socket Channel, Client common name
//Function: Handle client connection
func handleTS(conn net.Conn, com_name string) {

    //Receive Data
    buf := receiveData(conn)

    conn.Close() //Close connection

    if f_flag == false { //Finish flag not set

        if ts_config_flag == true { //If TS configuration flag set

            ts_config_flag = false //Set configuration flag to false

            if com_name == ts_hname { //If data received from TS

                config := new(TSmsg.Config) //TS configuration
                proto.Unmarshal(buf, config) //Parse TS configuration

                assignConfig(config) //Assign configuration

                if query == "ExitFirstLevelDomainAlexa1MWebInitialStream" {

                    domain_list := match.LoadDomainList("domain-top-fld-1m.txt")

                    domain_map = match.ExactMatchCreateMap(domain_list)
                }

                fmt.Println("Sending TS signal. Step No.", step_no)
                sendTSSignal(ts_s_no+step_no) //Send signal to TS

                step_no = 1 //TS step no.

            } else { //Data not received from TS

                fmt.Println("Error: Data not sent by Tally Server")

                f_flag = true //Set finish flag

                sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                return
            }

        } else {

            if com_name == ts_hname { //If Data Received from TS

                sig := new(TSmsg.Signal) //TS signal
                proto.Unmarshal(buf, sig) //Parse TS signal

                if *sig.Fflag == true { //If finish flag set

                    fmt.Println("TS sent finish")
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

                        sendTSSignal(ts_s_no+step_no) //Send signal to TS
                        fmt.Println("Sent TS signal ", step_no)

                        step_no += 1 //Increment step no.

                    } else { //Wrong signal from TS

                        fmt.Println("Err: Wrong signal from TS")

                        f_flag = true //Set finish flag

                        sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                        return
                    }
                }
            }
        }
    }
}

//Input: Tor control address, Tor control port and Tor control hashed password file path
//Function: Authenticate and establish connection to Tor control port
func torControlPortConnect(control_addr, control_port, passwd_file string) {

    //Dial Tor control port
    err := torControl.Dial("tcp", control_addr + ":" + control_port, passwd_file)
    checkError(err)

    err = torControl.SendCommand("PROTOCOLINFO 1\r\n")
    checkError(err)

    for {
        msg, err := torControl.ReceiveCommand() //Receive command
        checkError(err)

        _, state, err1 := torControl.CommandParse(msg) //Print command
        checkError(err1)

        if state == "waiting" {

            break
        }
    }
}

//Function: Collect data from Tor using oblivious counters
func collectData () {

    err := torControl.StartCollection(q_to_e[query])
    checkError(err)
    time.Sleep(24 * time.Duration(epoch) * time.Hour)
    torControl.StopCollection()
}

//Input: Tor control port connection
//Function: Receive events from Tor control port
func torControlPortReceive(torControl *goControlTor.TorControl) {

    defer wg.Done() //Decrement counter when goroutine completes

    for {

	select {

            case _, ok := <- message:

                if !ok {

                    return

                } else {

                    msg, err := torControl.ReceiveCommand() //Receive command
                    checkError(err)

                    message <- msg
                }

            default:
        }
    }
}

//Input: Event, Query
//Function: Handle stream event and increment counter
func handle_stream_event(event []string, query string) {

    port := event[3] //Remote port
    remote_host := event[8] //Remote host address
    //remote_ip := event[9] //Resolved remote IP address
    exit_stream_number := event[10] //Circuit exit stream number

    stream_circ := "Subsequent" //Set stream as subsequent stream

    if exit_stream_number == strconv.Itoa(1) {

        stream_circ = "Initial" //First stream on circuit
    }

    stream_web := "NonWeb" //Set stream as non-web

    if port == strconv.Itoa(80) || port == strconv.Itoa(443) {

        stream_web = "Web" //Web stream
    }

    host_ip_version := "Hostname" //Set as hostname

    if net.ParseIP(remote_host) != nil {

        if net.ParseIP(remote_host).To4 != nil {

            host_ip_version = "IPv4Literal" //IPv4 address

        } else {

            host_ip_version = "IPv6Literal" //IPv6 address
        }
    }

    if host_ip_version == "Hostname" && stream_web == "Web" && stream_circ == "Initial" {

        fld, _ := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(remote_host))

        if query == "ExitFirstLevelDomainWebInitialStream" && fld != "" {

           incrementCounter(fld) //Increment counter

        } else if query == "ExitFirstLevelDomainAlexa1MWebInitialStream" && fld != "" {

            if exact_match := match.ExactMatch(domain_map, fld); exact_match != "" {

                incrementCounter(exact_match) //Increment counter
            }
        }
    }
}

//Input: Event
//Function: Hash and increment counter
func incrementCounter(event string) {

    suite := nist.NewAES128SHA256P256()
    rand := suite.Cipher(abstract.RandomKey)

    h := fnv.New32a()
    h.Write([]byte(strings.ToLower(event)))
    key := math.Mod(math.Mod(((4.0*float64(h.Sum32()))+7.0), float64(p)), float64(b)) //Map to one of the counters
    c[int(key)].Add(c[int(key)], suite.Scalar().Pick(rand)) //Increment counter by adding a random number
}

//Input: Command-line Arguments
//Function: Parse Command-line Arguments
func parseCommandline(arg []string) (string, string, string, string) {

    var dp_ip string //DP IP
    var e_flag = false //Exit flag
    var control_addr string //Tor control address
    var control_port string //Tor control port
    var passwd_file string //Tor control hashed password file path

    flag.StringVar(&dp_cname, "d", "", "DP common name (required)")
    flag.StringVar(&dp_ip, "i", "", "DP IP (required)")
    flag.StringVar(&control_addr, "ca", "127.0.0.1", "Tor control port listen address")
    flag.StringVar(&control_port, "cp", "9051", "Tor control port")
    flag.StringVar(&passwd_file, "pf", "control_password.txt", "Tor control hashed password file path")
    flag.Parse()

    if dp_cname == "" || dp_ip == "" {

        fmt.Println("Argument required:")
        e_flag = true //Set exit flag

        if dp_cname == "" {

            fmt.Println("   -d string")
            fmt.Println("      DP common name (Required)")
        }

        if dp_ip == "" {

            fmt.Println("   -i string")
            fmt.Println("      DP IP (Required)")
        }
    }

    if e_flag == true {//If exit flag set

        os.Exit(0) //Exit
    }

    return dp_ip, control_addr, control_port, passwd_file
}

//Function: Initialize variables
func initValues() {

    no_CPs = 0 //No.of CPs
    no_DPs = 0 //No. of DPs
    epoch = 0 //Epoch
    b = 0 //Hash table size

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
    message = make(chan  string) //Channel to receive message from Tor control port
    clients = make(chan net.Conn) //Channel to handle simultaneous client connections
    k = nil //CP-DP Keys
    c = nil //Ciphers
    cs = nil //Cipher shares
    wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown
}

//Input: Configuration from TS
//Output: Assign configuration
func assignConfig(config *TSmsg.Config) {

    ts_s_no = uint32(*config.SNo) //TS session no.
    epoch = int(*config.Epoch) //Epoch
    no_CPs = *config.Ncps //No. of CPs
    query = *config.Query //Query
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

//Input: DP common name
//Output: Socket
//Function: Accept new connections in  Socket
func acceptConnections() {

    defer wg.Done() //Decrement counter when goroutine completes

    for {

        //Create Server Socket
        cert, err1 := tls.LoadX509KeyPair("certs/"+ dp_cname +".cert", "private/" + dp_cname + ".key")
        checkError(err1)

        //Add CA certificate to pool
        files, _ := ioutil.ReadDir("../CA/certs/")
        caCertPool := x509.NewCertPool()
        for _, file := range files {

            if !file.IsDir() && strings.HasSuffix(file.Name(), ".cert") {

                caCert, _ := ioutil.ReadFile("../CA/certs/"+file.Name())
                caCertPool.AppendCertsFromPEM(caCert)
            }
        }

        //Create TLS Listener and Accept Connection
        config := tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caCertPool, ClientAuth: tls.RequireAndVerifyClientCert,}
        conn, err := ln.Accept()

        var sock *tls.Conn //Client socket

        //If error
        if err != nil {

            break

        } else { //If not error

            file, _ := conn.(*net.TCPConn).File()
            err1 = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
            sock = tls.Server(conn, &config)

            clients <- sock
        }
    }
}

func sendDataToDest(data []byte, dst_hname string, dst_addr string) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/" + dp_cname + ".cert", "private/" + dp_cname + ".key")
    checkError(err)

    //Add CA certificate to pool
    files, _ := ioutil.ReadDir("../CA/certs/")
    caCertPool := x509.NewCertPool()
    for _, file := range files {

        if !file.IsDir() && strings.HasSuffix(file.Name(), ".cert") {

            caCert, _ := ioutil.ReadFile("../CA/certs/"+file.Name())
            caCertPool.AppendCertsFromPEM(caCert)
        }
    }

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
