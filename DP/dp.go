/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University

See LICENSE for licensing information
*/

package main

import (
    "bufio"
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "flag"
    "fmt"
    "github.com/dedis/kyber"
    "github.com/dedis/kyber/group/edwards25519"
    "github.com/golang/protobuf/proto"
    "golang.org/x/net/publicsuffix"
    "hash/fnv"
    "io"
    "io/ioutil"
    "math"
    "net"
    "os"
    "PSC/DP/dpres"
    "PSC/asn"
    "PSC/goControlTor"
    "PSC/logging"
    "PSC/match"
    "PSC/TS/tsmsg"
    "strings"
    "strconv"
    "sync"
    "syscall"
    "time"
)

const p = 1000003 //Universal hash parameter p

var no_CPs int32 //No.of CPs
var no_DPs int32 //No. of DPs
var epoch int //Epoch
var b int64 //Hash table size

var ts_cname string //TS hostname
var ts_addr string //TS address
var qname string //Query
var qlist []string //Query list
var cp_cnames []string //CP common names
var dp_cnames []string //DP common names
var cp_addr []string //CP addresses
var dp_addr []string //DP addresses
var dp_cname string //DP common name
var f_flag bool //Finish Flag
var step_no uint32 //DP Step Number
var ts_s_no uint32 //TS Session No.
var ts_config_flag bool //TS configuration flag
var ln net.Listener //Server listener
var finish chan bool //Channel to send finish flag
var clients chan net.Conn //Channel to handle simultaneous client connections
var k []kyber.Scalar //CP-DP Keys
var c []kyber.Scalar //Ciphers
var cs [][]kyber.Scalar //Cipher share
var mutex = &sync.Mutex{} //Mutex to lock common client variable
var wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown

var privcount_enable_flag bool //PrivCount enable flag
var torControl = &goControlTor.TorControl{} //Tor control port connection
var domain_map = map[string]bool{} //Domain map
var ipv4asnmap = map[string]map[string]string{} //IPv4 to ASN map
var ipv6asnmap = map[string]map[string]string{} //IPv6 to ASN map  
var message chan string //Channel to receive message from Tor control port
var data_col_sig chan bool //Channel to send data collection signal
var d_flag bool //Data collection finish Flag
var q_to_e = map[string]string{ //Map query

    "ExitSecondLevelDomainWebInitialStream": "PRIVCOUNT_STREAM_ENDED",
    "ExitSecondLevelDomainAlexaWebInitialStream": "PRIVCOUNT_STREAM_ENDED",
    "EntryRemoteIPAddress": "PRIVCOUNT_CONNECTION_CLOSE",
    "EntryRemoteIPAddressCountry": "PRIVCOUNT_CONNECTION_CLOSE",
    "EntryRemoteIPAddressAS": "PRIVCOUNT_CONNECTION_CLOSE",
    "HSDirStoreOnionAddress": "PRIVCOUNT_HSDIR_CACHE_STORE",
    "HSDirFetchOnionAddress": "PRIVCOUNT_HSDIR_CACHE_FETCH",
}

func main() {

    logging.LogToFile("logs/Connection"+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"))

    dp_host, dp_port, control_addr, control_port, passwd_file, tsinfo_file := parseCommandline(os.Args) //Parse DP hostname, common name & port number, Tor control address & port no., hashed password file path, TS information file path an PrivCount enable flag

    //Assign TS information
    file, err := os.Open(tsinfo_file)
    checkError(err)

    //Read line by line
    scanner := bufio.NewScanner(file)
    no_of_lines := 0
    for scanner.Scan() {

        no_of_lines += 1
        t := scanner.Text()

        if no_of_lines <= 2 && strings.HasPrefix(t, "Addr ") {

            ts_addr = strings.TrimPrefix(t, "Addr ") //Assign TS address

            ts_address := strings.Split(ts_addr, ":")[0]

            ts_port, err := strconv.ParseUint(strings.Split(ts_addr, ":")[1], 10, 16)

            if strings.Contains(ts_address, " ") {

                checkError(fmt.Errorf("%s is not a valid address", ts_address))
            }

            if err != nil {

                checkError(fmt.Errorf("%s is not a valid port", ts_port))
            }

        } else if no_of_lines <= 2 && strings.HasPrefix(t, "CN ") {

            ts_cname = strings.TrimPrefix(t, "CN ") //Assign TS common name

            if strings.Contains(ts_cname, " ") {

                checkError(fmt.Errorf("%s is not a valid common name", ts_cname))
            }

        } else {

            checkError(fmt.Errorf("TS information file %s formatting error", tsinfo_file))
        }
    }

    file.Close()

    logging.Info.Println("Parsed command-line arguments")

    torControlPortConnect(control_addr, control_port, passwd_file)

    logging.Info.Println("Connected to Tor control port")

    for{
        //Initialize global variables
        initValues()

        //Listen to the TCP port
        var err error
        ln, err = net.Listen("tcp", dp_host+":"+dp_port)
        checkError(err)

        logging.LogToFile("logs/"+dp_cname+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"))
        logging.Info.Println("PSC is a free, open-source software, available for download at https://github.com/AkshayaMani/PSC")
        logging.Info.Println("PSC uses https://github.com/postfix/goControlTor library to connect to Tor control port")
        logging.Info.Println("Started Data Party")

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

                    if ts_cname == com_name {//If data received from TS

                        //Handle TS connection
                        handleTS(conn)

                    } else { //If not TS

                        conn.Close() //Close connection
                    }

                case <-finish:

                    torControl.SetTimeOut(time.Now().Add(0)) //Immediately time out

                    wg.Wait() //Wait for all go routines to finish

                    if step_no == 4 { //Finish

                        //Finishing measurement
                        logging.Info.Println("Finished measurement")

                    } else {

                        //Quit and Re-start measurement
                        logging.Info.Println("Quit")
                        logging.Info.Println("Re-start measurement")
                    }

                    break loop
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
    sendDataToDest(sigb, ts_cname, ts_addr)
}

//Input: TS Socket
//Function: Handle TS connection
func handleTS(conn net.Conn) {

    //Receive Data
    buf := receiveData(conn)

    conn.Close() //Close connection

    if ts_config_flag == true { //If TS configuration flag set

        ts_config_flag = false //Set configuration flag to false

        config := new(TSmsg.Config) //TS configuration
        proto.Unmarshal(buf, config) //Parse TS configuration

        assignConfig(config) //Assign configuration

        logging.Info.Println("Sending TS signal. Step No.", step_no)
        sendTSSignal(ts_s_no+step_no) //Send signal to TS

        step_no = 1 //TS step no.

    } else {

        sig := new(TSmsg.Signal) //TS signal
        proto.Unmarshal(buf, sig) //Parse TS signal

        if *sig.Fflag == true { //If finish flag set

            logging.Info.Println("TS sent finish")
            shutdownDP() //Shutdown DP gracefully

        } else { //Finish flag not set

            if *sig.SNo == int32(ts_s_no+step_no) { //Check TS step no.

                suite := edwards25519.NewBlakeSHA256Ed25519()
                rand := suite.RandomStream()

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

                            //Convert to bytes
                            var tb bytes.Buffer //Temporary buffer
                            _,_ = k[j].MarshalTo(&tb)
                            resp.M[j] = tb.Bytes() //Assign CP-DP keys

                            c[j] = suite.Scalar().Add(c[j], k[j]) //Add keys to each counter
                        }

                        //Convert to bytes
                        resp1, _ := proto.Marshal(resp)

                        //Send key to CP
                        logging.Info.Println("Sending symmetric key to CP", i,". Step No.", step_no)
                        sendDataToDest(resp1, cp_cnames[i], cp_addr[i])
	            }

                    k = nil //Forget keys

                } else if step_no == 2 { //If step no. 2

                    logging.Info.Println("Started data collection")

                    wg.Add(1) //Increment WaitGroup counter

                    go collectData() //Start collecting data

                } else if step_no == 3 && d_flag == true { //If step no. 3 and data collection finished

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

                            //Convert to bytes
                            var tb bytes.Buffer //Temporary buffer
                            _,_ = cs[j][i].MarshalTo(&tb)
                            resp.M[j] = tb.Bytes() //Assign masked data share
                        }

                        //Convert to bytes
                        resp1, _ := proto.Marshal(resp)

                        //Send data shares to CP
                        logging.Info.Println("Sending masked data shares to CP", i,". Step No.", step_no)
                        sendDataToDest(resp1, cp_cnames[i], cp_addr[i])
                    }
                }

                if step_no != 2 {

                    sendTSSignal(ts_s_no+step_no) //Send signal to TS
                    logging.Info.Println("Sent TS signal ", step_no)
                }

                step_no += 1 //Increment step no.

            } else { //Wrong signal from TS

                logging.Error.Println("Wrong signal from TS")

                f_flag = true //Set finish flag

                sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                return
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

        _, state, err1, log := torControl.CommandParse(msg) //Print command
        checkError(err1)

        if log != "" { //If log set

            if strings.HasPrefix(log, "Warning:") {

                logging.Warning.Println(strings.TrimPrefix(log, "Warning:"))

            } else if strings.HasPrefix(log, "Info:") {

                logging.Info.Println(strings.TrimPrefix(log, "Info:"))

            } else {

                checkError(fmt.Errorf("%s is not a valid log", log))
            }
        }

        if state == "waiting" {

            break
        }
    }
}

//Function: Collect data from Tor using oblivious counters
func collectData () {

    defer wg.Done() //Decrement counter when goroutine completes

    mutex.Lock() //Lock mutex

    err, log := torControl.StartCollection(q_to_e[qname], privcount_enable_flag)
    checkError(err)

    mutex.Unlock() //Unlock mutex

    data_col_sig <- true //Send data collection start signal

    if log != "" { //If log set

        if strings.HasPrefix(log, "Warning:") {

            logging.Warning.Println(strings.TrimPrefix(log, "Warning:"))

        } else if strings.HasPrefix(log, "Info:") {

            logging.Info.Println(strings.TrimPrefix(log, "Info:"))

        } else {

            checkError(fmt.Errorf("%s is not a valid log", log))
        }
    }

    sig := <- data_col_sig //Wait for data collection signal

    mutex.Lock() //Lock mutex

    err = torControl.StopCollection(privcount_enable_flag)
    checkError(err)

    d_flag = true //Set data collection finish flag

    if sig == true {

        sendTSSignal(ts_s_no+2) //Send signal to TS
        logging.Info.Println("Sent TS signal ", 2)
    }

    mutex.Unlock() //Unlock mutex
}

//Input: Tor control port connection
//Function: Receive events from Tor control port
func torControlPortReceive(torControl *goControlTor.TorControl) {

    defer wg.Done() //Decrement counter when goroutine completes

    <- data_col_sig //Wait for data collection start signal

    colstart := time.Now() //Data collection start time

    torControl.SetTimeOut(colstart.Add(24 * time.Duration(epoch) * time.Hour)) //Collect for an epoch

    for {

        msg, err := torControl.ReceiveCommand() //Receive command

        if  err != nil {

            if strings.HasSuffix(err.Error(), "i/o timeout") { //If timeout error

                if time.Now().After(colstart.Add(24 * time.Duration(epoch) * time.Hour)) { //Data collected for an epoch 

                    data_col_sig <- true //Send data collection finish signal

                } else {

                    data_col_sig <- false //Send data collection abort signal
                }

                return

            } else {

                checkError(err) //Check error
            }

        } else {

            event, _, err, log := torControl.CommandParse(msg) //Print command
            checkError(err)

            if log != "" { //If log set

                if strings.HasPrefix(log, "Warning:") {

                    logging.Warning.Println(strings.TrimPrefix(log, "Warning:"))

                } else if strings.HasPrefix(log, "Info:") {

                    logging.Info.Println(strings.TrimPrefix(log, "Info:"))

                } else {

                    checkError(fmt.Errorf("%s is not a valid log", log))
                }
            }

            if len(event) != 0 {

                if event[0] == q_to_e[qname] {

                    if q_to_e[qname] == "PRIVCOUNT_STREAM_ENDED" {

                        handle_stream_event(event[1:])

                    } else if q_to_e[qname] == "PRIVCOUNT_CONNECTION_CLOSE" {

                        handle_connection_event(event[1:])

                    } else if q_to_e[qname] == "PRIVCOUNT_HSDIR_CACHE_STORE" {

                        handle_hsdir_strore_event(event[1:])

                    } else if q_to_e[qname] == "PRIVCOUNT_HSDIR_CACHE_FETCH" {

                        handle_hsdir_fetch_event(event[1:])
                    }
                }
            }
        }
    }
}

//Input: Event
//Function: Handle stream event and increment counter
func handle_stream_event(event []string) {

    port := event[3] //Remote port
    remote_host := event[8] //Remote host address
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

        sld, _ := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(remote_host))

        if qname == "ExitSecondLevelDomainWebInitialStream" && sld != "" {

           incrementCounter(sld) //Increment counter

        } else if qname == "ExitSecondLevelDomainAlexaWebInitialStream" && sld != "" {

            if exact_match := match.ExactMatch(domain_map, sld); exact_match != "" {

                incrementCounter(exact_match) //Increment counter
            }
        }
    }
}

//Input: Event
//Function: Handle connection event and increment counter
func handle_connection_event(event []string) {

    eventmap := map[string]string{}

    for i := 0; i < len(event); i++ {

        tmp := strings.Split(event[i], "=")
        eventmap[tmp[0]] = tmp[1]
    }

    remote_is_client, _ := strconv.Atoi(eventmap["RemoteIsClientFlag"]) //Remote is client flag

    if remote_is_client == 1 { //If remote is client

        if qname == "EntryRemoteIPAddress" {

            if net.ParseIP(eventmap["RemoteIPAddress"]) != nil { //If IP address is valid

                incrementCounter(eventmap["RemoteIPAddress"]) //Increment counter
            }

        } else if qname == "EntryRemoteIPAddressCountry" {

            if eventmap["RemoteCountryCode"] != "!!" && eventmap["RemoteCountryCode"] != "??" { 

                if contains(qlist, eventmap["RemoteCountryCode"]) {

                    if net.ParseIP(eventmap["RemoteIPAddress"]) != nil { //If IP address is valid

                        incrementCounter(eventmap["RemoteIPAddress"])
                    }
                }
            }

        } else if qname == "EntryRemoteIPAddressAS" {

            var asno string //ASN

            if net.ParseIP(eventmap["RemoteIPAddress"]) != nil {

                if net.ParseIP(eventmap["RemoteIPAddress"]).To4 != nil {

                    asno = asn.FindASN(ipv4asnmap, 4, eventmap["RemoteIPAddress"]) //Find ASN from IPv4 to ASN map 

                } else {

                    asno = asn.FindASN(ipv6asnmap, 6, eventmap["RemoteIPAddress"]) //Find ASN from IPv6 to ASN map
                }
            }

            if contains(qlist, asno) {

                incrementCounter(eventmap["RemoteIPAddress"])
            }
        }
    }
}

//Input: Event
//Function: Handle hsdir store event and increment counter
func handle_hsdir_strore_event(event []string) {

    eventmap := map[string]string{}

    for i := 0; i < len(event); i++ {

        tmp := strings.Split(event[i], "=")
        eventmap[tmp[0]] = tmp[1]
    }

    if qname == "HSDirStoreOnionAddress" {

        if _, ok := eventmap["OnionAddress"]; ok {

            incrementCounter(eventmap["OnionAddress"]) //Increment counter
        }
    }
}

//Input: Event
//Function: Handle hsdir fetch event and increment counter
func handle_hsdir_fetch_event(event []string) {

    eventmap := map[string]string{}

    for i := 0; i < len(event); i++ {

        tmp := strings.Split(event[i], "=")
        eventmap[tmp[0]] = tmp[1]
    }

    if qname == "HSDirFetchOnionAddress" {

        if _, ok := eventmap["OnionAddress"]; ok {

            incrementCounter(eventmap["OnionAddress"]) //Increment counter
        }
    }
}

//Input: Event
//Function: Hash and increment counter
func incrementCounter(event string) {

    suite := edwards25519.NewBlakeSHA256Ed25519()
    rand := suite.RandomStream()

    h := fnv.New32a()
    h.Write([]byte(strings.ToLower(event)))
    key := math.Mod(math.Mod(((4.0*float64(h.Sum32()))+7.0), float64(p)), float64(b)) //Map to one of the counters
    c[int(key)].Add(c[int(key)], suite.Scalar().Pick(rand)) //Increment counter by adding a random number
}

//Input: Command-line Arguments
//Output: DP port number, Tor control address, Tor control port, Tor control hashed password file path, TS information file path
//Function: Parse Command-line Arguments
func parseCommandline(arg []string) (string, string, string, string, string, string) {

    var dp_host string //DP hostname
    var dp_port string //DP port number
    var e_flag = false //Exit flag
    var control_addr string //Tor control address
    var control_port string //Tor control port
    var passwd_file string //Tor control hashed password file path
    var tsinfo_file string //TS information file path

    flag.StringVar(&dp_host, "h", "", "DP hostname to which to bind")
    flag.StringVar(&dp_port, "p", "", "DP port number (required)")
    flag.StringVar(&dp_cname, "d", "", "DP common name (required)")
    flag.StringVar(&control_addr, "ca", "127.0.0.1", "Tor control port listen address")
    flag.StringVar(&control_port, "cp", "9051", "Tor control port")
    flag.StringVar(&passwd_file, "pf", "control_password.txt", "Tor control hashed password file path")
    flag.StringVar(&tsinfo_file, "t", "ts.info", "TS information file path")
    flag.BoolVar(&privcount_enable_flag, "pe", false, "PrivCount enable")
    flag.Parse()

    if dp_cname == "" || dp_port == "" {

        logging.Error.Println("Argument required:")
        e_flag = true //Set exit flag

        if dp_cname == "" {

            logging.Error.Println("   -d string")
            logging.Error.Println("      DP common name (Required)")
        }

        if dp_port == "" {

            logging.Error.Println("   -p string")
            logging.Error.Println("      DP port number (Required)")
        }
    }

    if e_flag == true {//If exit flag set

        os.Exit(0) //Exit
    }

    return dp_host, dp_port, control_addr, control_port, passwd_file, tsinfo_file
}

//Function: Initialize variables
func initValues() {

    no_CPs = 0 //No.of CPs
    no_DPs = 0 //No. of DPs
    epoch = 0 //Epoch
    b = 0 //Hash table size

    cp_cnames = nil //CP common names
    dp_cnames = nil //DP common names
    cp_addr = nil //CP addresses
    dp_addr = nil //DP addresses
    f_flag = false //Finish flag
    d_flag = false //Data collection finish flag
    step_no = 0 //DP step no.
    ts_s_no = 0 //TS session no.
    ts_config_flag = true //TS configuration flag
    ln = nil //Server listener
    finish = make(chan bool) //Channel to send finish flag
    message = make(chan  string) //Channel to receive message from Tor control port
    data_col_sig = make(chan bool) //Channel to send data collection signal
    clients = make(chan net.Conn) //Channel to handle simultaneous client connections
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
    no_CPs = *config.Ncps //No. of CPs
    qname = *config.Q.Name //Query name

    if _, ok := q_to_e[qname]; !ok { //Check if query is valid

        checkError(fmt.Errorf("%s is not a valid Query", qname))

    } else {

        if qname == "ExitSecondLevelDomainWebInitialStream" || qname == "EntryRemoteIPAddress" || qname == "HSDirStoreOnionAddress" || qname == "HSDirFetchOnionAddress" {

            if len(config.Q.List) != 0 {

                checkError(fmt.Errorf("%s has invalid list", qname))
            }

        } else {

            qlist = make([]string, len(config.Q.List)) //Query list
            copy(qlist[:], config.Q.List) //Assign Query list
        }
    }

    if qname == "ExitSecondLevelDomainAlexaWebInitialStream" {

        var from_index, to_index int //Domain list index

        if len(qlist) == 2 || len(qlist) == 1 || len(qlist) == 0 {

            if len(qlist) == 0 { //If entire list

                from_index = 0
                to_index = -1

            } else {

                tmp, err := strconv.Atoi(qlist[0]) //Convert to integer

      	       	checkError(err) //Check error

                if len(qlist) == 1 { //If only to_index specified

                    from_index = 0 
                    to_index = tmp

                } else {

                    from_index = tmp

                    to_index, err = strconv.Atoi(qlist[1]) //Convert to integer

                    checkError(err) //Check error
                }
            }

        } else {

            checkError(fmt.Errorf("%s has invalid list", qname)) //Invalid query list
        }

        domain_list := match.LoadDomainList("data/" + config.Q.File["domain"], from_index, to_index)

        domain_map = match.ExactMatchCreateMap(domain_list)

    } else if qname == "EntryRemoteIPAddressAS" {

        if len(qlist) == 0 {

            qname = "EntryRemoteIPAddress" 

        } else {

            ipv4asnmap = asn.CreateIPASNMap("data/" + config.Q.File["ipv4"], 4)
            ipv6asnmap = asn.CreateIPASNMap("data/" + config.Q.File["ipv6"], 6)
        } 

    } else if qname == "EntryRemoteIPAddressCountry" {

        if len(qlist) == 0 {

            qname = "EntryRemoteIPAddress"

        }
    }

    cp_cnames = make([]string, no_CPs) //CP common names
    cp_addr = make([]string, no_CPs) //CP addresses

    copy(cp_cnames[:], config.CPcnames) //Assign CP common names
    copy(cp_addr[:], config.CPaddr) //Assign CP addresses

    no_DPs = *config.Ndps //No. of DPs
    dp_cnames = make([]string, no_DPs) //DP common names
    dp_addr = make([]string, no_DPs) //DP addresses

    copy(dp_cnames[:], config.DPcnames) //Assign DP common names
    copy(dp_addr[:], config.DPaddr) //Assign DP addresses

    b = *config.Tsize //Hash table size

    k = make([]kyber.Scalar, b) //CP-DP Keys
    c = make([]kyber.Scalar, b) //Ciphers
    cs = make([][]kyber.Scalar, b) //Cipher shares

    suite := edwards25519.NewBlakeSHA256Ed25519()

    //Iterate over the hashtable
    for i := int64(0); i < b; i++ {

        c[i] = suite.Scalar().Zero() //Initialize with zero
        cs[i] = make([]kyber.Scalar, no_CPs) //Initialize cipher shares list
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
    io.ReadFull(conn,buf) //Read n Bytes
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

//Input: Data, Destination common name, Destination address
//Function: Send data to destination
func sendDataToDest(data []byte, dst_cname string, dst_addr string) {

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
    config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, ServerName: dst_cname,} //InsecureSkipVerify: true,}
    con, err := reDial(10, 180, dst_addr)
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

//Input: No. of attempts, Sleep time
//Output: TCP connection, Error
//Fuction: Attempt TCP dial up few times in case of failure 
func reDial(attempts int, sleep time.Duration, dst_addr string) (con net.Conn, err error) {

    for i := 0; i < attempts; i++ {

        con, err = net.Dial("tcp", dst_addr)

        if err == nil {

            return con, err
        }

        time.Sleep(sleep * time.Second)

        logging.Info.Println("Retrying after dial up error:", err)
    }

    return con, fmt.Errorf("After %d attempts, last error: %s", attempts, err)
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

        logging.Error.Println(err.Error())
        os.Exit(1)
    }
}
