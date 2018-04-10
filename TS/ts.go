/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University

See LICENSE for licensing information
*/

package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "flag"
    "fmt"
    "github.com/golang/protobuf/proto"
    "io"
    "io/ioutil"
    "math/rand"
    "net"
    "os"
    "PSC/logging"
    "PSC/TS/tsmsg"
    "strings"
    "sync"
    "syscall"
    "time"
)

var no_CPs int //No.of CPs
var no_DPs int //No. of DPs
var no_Expts int //No. of measurements
var qname string //Query name
var epoch int //Epoch
var cp_cnames []string //CP common names
var dp_cnames []string //DP common names
var cp_addr []string //CP addresses
var dp_addr []string //DP addresses
var ts_cname string //TS common name
var start time.Time //Data collection start time
var ln net.Listener //Server listener
var finish chan bool //Channel to send finish flag
var agg string //Aggregated result
var clients chan net.Conn //Channel to handle simultaneous client connections
var f_flag bool //Finish flag
var config_flag bool //Configuration flag
var data_flag bool //Data flag
var cp_bcast int //Next CP to broadcast
var cp_step_no uint32 //CP Step Number
var dp_step_no uint32 //DP Step Number
var ts_s_no uint32 //TS session No.
var no_dp_res int//No. of DPs responded
var no_cp_res int//No. of CPs responded
var config *TSmsg.Config //Configuration parameters
var mutex = &sync.Mutex{} //Mutex to lock common client variable
var wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown

func main() {

    logging.LogToFile("logs/Connection"+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"))

    ts_host, ts_port, config_file := parseCommandline(os.Args) //Parse TS hostname, common name & port number, and configuration file path

    logging.Info.Println("Parsed command-line arguments")

    assignConfig(config_file) //Assign configuration parameters

    logging.Info.Println("Assigned configuration parameters")

    expt_no := 0 //Set measurement no. to 0

    restart := false //Restart flag for experiments

    for{

        //Initialize global variables
        initValues()

        //Listen to the TCP port
        var err error
        ln, err = net.Listen("tcp", ts_host+":"+ts_port)
        checkError(err)

        logging.LogToFile("logs/"+ts_cname+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"))
        logging.Info.Println("PSC is a free, open-source software, available for download at https://github.com/AkshayaMani/PSC")
        logging.Info.Println("PSC uses https://github.com/postfix/goControlTor library to connect to Tor control port")
        logging.Info.Println("Sleeping...")

        if restart == true { //If re-started experiment

            restart = false //Set restart flag to false

            time.Sleep(10 * time.Minute) //Sleep for 10 minutes before re-starting

        } else if expt_no != 0 { //If not 1st experiment

            time.Sleep(24 * time.Duration(epoch) * time.Hour) //Sleep for an epoch before starting
        }

        logging.Info.Println("Started Tally Server")

        expt_no = expt_no + 1 //Increment measurement no.

        if expt_no <= no_Expts { //Continue measurements

            logging.Info.Println("Begin measurement no.", expt_no)

            seed := rand.NewSource(time.Now().UnixNano())
            rnd := rand.New(seed)

            //Generate TS session no.
            ts_s_no = 0
            for ts_s_no == 0 {

                ts_s_no = uint32(rnd.Int31()) //Set session no. to non-zero random number
            }

            //Assign TS session no.
            config.SNo = proto.Int32(int32(ts_s_no))

            //Convert to Bytes
            configbytes, _ := proto.Marshal(config)

            logging.Info.Println("Sending config to all CPs")
            //Send config to CPs
            for i := 0; i < no_CPs; i++ {

                sendDataToDest(configbytes, cp_cnames[i], cp_addr[i])
            }

            logging.Info.Println("Sending config to all DPs")
            //Send config to DPs
            for i := 0; i < no_DPs; i++ {

                sendDataToDest(configbytes, dp_cnames[i], dp_addr[i])
            }

            cp_step_no = ts_s_no //Set CP step no.
            dp_step_no = ts_s_no //Set DP step no.

            //Channel to handle simultaneous client connections
            clientconn := make(chan net.Conn)

            wg.Add(1) //Increment WaitGroup counter

            go acceptConnections() //Accept connections

            loop:

            for{

                select {

                    case conn := <- clients:

                        //Parse Common Name
                        com_name := parseCommonName(conn)

                        if contains(dp_cnames, com_name) || contains(cp_cnames, com_name) {//If data received from CP/DP

                            wg.Add(1) //Increment WaitGroup counter

                            //Handle clients in separate channels
                            go handleClients(clientconn, com_name)

                            //Add DPconnection to channel
                            clientconn <- conn

                        } else { //If not CPs or DPs

                            conn.Close() //Close connection
                        }

                    case <-finish:

                        //Send finish signal to all CPs
                        logging.Info.Println("Sending finish signal to CPs")
                        for i := 0; i < no_CPs; i++ {

                            signalParty(cp_cnames[i], cp_addr[i], true, cp_step_no)
                        }

                        if dp_step_no != ts_s_no + 4 { //If DPs have not finished

                            //Send finish signal to all DPs
                            logging.Info.Println("Sending finish signal to DPs")
                            for i := 0; i < no_DPs; i++ {

                                signalParty(dp_cnames[i], dp_addr[i], true, dp_step_no)
                            }
                        }

                        wg.Wait()

                        if cp_step_no == ts_s_no + 11 { //Finish

                            //Finishing measurement
                            logging.Info.Println("Finished measurement no.", expt_no)

                        } else {

                            //Quit and Re-start measurement
                            logging.Info.Println("Quit")
                            logging.Info.Println("Re-start measurement")

                            expt_no = expt_no - 1 //Decrement measurement no.

                            restart = true //Set restart experiment flag
                        }

                        break loop
                }
            }

        } else {

            var exit string //Continue response

            fmt.Println("Do you want to exit? (Y or N)")
            fmt.Scanf("%s", &exit)

            if exit == "N" || exit == "n" { //If continue with same parameters

                fmt.Println("Enter no. of experiments")
                fmt.Scanf("%d", &no_Expts)

                logging.Info.Println("Continue running", no_Expts, "measurments")

                expt_no = 0 //Reset measurement no.

                ln.Close()

            } else if exit == "Y" || exit == "y" {

                shutdownTS() //Shutdown TS gracefully

                wg.Wait()

                logging.Info.Println("Quit")

                break //End Measurement

            } else {

                logging.Info.Println("Invalid option")
                logging.Info.Println("Quit")

                break //End Measurement
            }
        }
    }

    logging.Info.Println("Finished measurements")
    logging.Info.Println("Exit")
}

//Input: Party (CP/DP) common name, Party (CP/DP) address, Finish flag, Session no.
//Function: Signal next party
func signalParty(party_cname, party_addr string, fin bool, sno uint32) {

    sig := new(TSmsg.Signal) //TS signal for next broadcast party

    sig.Fflag = proto.Bool(fin) //Set TS signal finish flag

    sig.SNo = proto.Int32(int32(sno)) //Set Session no.

    //Convert to Bytes
    sigb, _ := proto.Marshal(sig)

    //Send signal to next broadcast party
    sendDataToDest(sigb, party_cname, party_addr)
}

//Input: Client socket channel, Client common name
//Function: Handle client connection
func handleClients(clientconn chan net.Conn, com_name string) {

    defer wg.Done() //Decrement counter when goroutine completes

    //Wait for next client connection to come off queue.
    conn := <-clientconn

    //Receive Data
    buf := receiveData(conn)

    conn.Close() //Close connection

    mutex.Lock() //Lock mutex

    if f_flag == false { //Finish flag not set

        //If Data Received from DP
        if contains(dp_cnames, com_name) {

            //Parse signal
            sig := new(TSmsg.Signal)
            proto.Unmarshal(buf, sig)

            //If finish flag not set
            if *sig.Fflag == false {

                //Verify Step No. and Session No.
                if *sig.SNo == int32(dp_step_no) {

                    no_dp_res = no_dp_res + 1 //Increment no. of DP responded

                } else { //Wrong acknowledgement

                    logging.Error.Println("Wrong acknowledgement by DP ", com_name)

                    shutdownTS() //Shutdown TS gracefully

                    return
                }

            } else if *sig.Fflag == true {//Error

                logging.Error.Println("DP ", com_name, "sent quit")

                shutdownTS() //Shutdown TS gracefully

                return
            }

            //If all DPs have responded
            if no_dp_res == no_DPs {

                if dp_step_no == ts_s_no { //Step No. 0

                    if config_flag == false {//If config flag unset

                        dp_step_no += 1 //Increment DP step no.

                        //Send signal to DPs to share Symmetric keys with the CPs
                        logging.Info.Println("Signal DPs to send symmetric key shares. Step No.", dp_step_no-ts_s_no)
                        for i := 0; i < no_DPs; i++ {

                            signalParty(dp_cnames[i], dp_addr[i], false, dp_step_no)
                        }
                    }

                    config_flag = false //Set config flag

                } else if dp_step_no == ts_s_no + 1 { //Step No. 1

                    dp_step_no += 1 //Increment DP step no.

                    //Send signal to DPs to start data collection
                    logging.Info.Println("Signal DPs to collect data. Step No.", dp_step_no-ts_s_no)
                    for i := 0; i < no_DPs; i++ {

                        signalParty(dp_cnames[i], dp_addr[i], false, dp_step_no)
                    }

                    start = time.Now() //Data collection start time

                } else if dp_step_no == ts_s_no + 2 { //Step No. 2

                    end := time.Since(start).Hours()

                    if end >= 24.0 * float64(epoch) {//If data collected for an epoch

                        if data_flag == true {//If data flag set

                            dp_step_no += 1 //Increment DP step no.

                            //Signal DPs to send data to CPs
                            logging.Info.Println("Signal DPs to send masked data shares. Step No.", dp_step_no-ts_s_no)
                            for i := 0; i < no_DPs; i++ {

                                signalParty(dp_cnames[i], dp_addr[i], false, dp_step_no)
                            }
                        }

                        data_flag = true //Set data flag

                    } else if end < 24.0 * float64(epoch) { //Data not collected for an epoch - error

                        logging.Error.Println("Data not collected for an epoch")

                        shutdownTS() //Shutdown TS gracefully

                        return
                    }

                } else if dp_step_no == ts_s_no + 3 { //Step No. 3

                    dp_step_no += 1 //Increment DP step no.

                    //Send finish signal to DPs
                    logging.Info.Println("Signal DPs to finish. Step No.", dp_step_no-ts_s_no)
                    for i := 0; i < no_DPs; i++ {

                        signalParty(dp_cnames[i], dp_addr[i], true, dp_step_no)
                    }
                }

                no_dp_res = 0 //Set no. of DPs responded to zero
            }

        } else if contains(cp_cnames, com_name) { //If Data Received from CP

            if cp_step_no == ts_s_no + 10 && cp_bcast == no_CPs - 1 { //Step No. 10 and last CP has broadcasted

                //Parse result
                result := new(TSmsg.Result)
                proto.Unmarshal(buf, result)

                if no_cp_res != 0 { //Compare aggregate received from previous CP

                    if agg != *result.Agg { //Wrong aggregate

                        logging.Error.Println("Wrong aggregate value by CP ", com_name)

                        shutdownTS() //Shutdown TS gracefully

                        return
                    }

                } else {

                    agg = *result.Agg //Assign aggregate
                }

                no_cp_res = no_cp_res + 1 //Increment no. of CP responded

            } else {

                //Parse signal
                sig := new(TSmsg.Signal)
                proto.Unmarshal(buf, sig)

                //If finish flag not set
                if *sig.Fflag == false {

                    //Verify Step No. and Session No.
                    if *sig.SNo == int32(cp_step_no) {

                        no_cp_res = no_cp_res + 1 //Increment no. of CP responded

                    } else { //Wrong acknowledgement

                        logging.Error.Println("Wrong acknowledgement by CP ", com_name)

                        shutdownTS() //Shutdown TS gracefully

                        return
                    }

                } else if *sig.Fflag == true {//Error

                    logging.Info.Println("CP ", com_name, "sent quit ")

                    shutdownTS() //Shutdown TS gracefully

                    return
                }
            }

            //If all CPs have responded
            if no_cp_res == no_CPs {

                 if cp_step_no == ts_s_no {  //Step No. 0

                    cp_step_no += 1 //Increment CP step no.

                    cp_bcast = -1 //Wait for CPs acknowledgement

                    if config_flag == false {//If config flag unset

                        dp_step_no += 1 //Increment DP step no.

                        //Send signal to DPs to share Symmetric keys with the CPs
                        logging.Info.Println("Signal DPs to send symmetric key shares. Step No.", dp_step_no-ts_s_no)
                        for i := 0; i < no_DPs; i++ {

                            signalParty(dp_cnames[i], dp_addr[i], false, dp_step_no)
                        }
       	       	    }

       	       	    config_flag = false //Set config flag

                } else if cp_step_no == ts_s_no + 1 || cp_step_no == ts_s_no + 2 || cp_step_no == ts_s_no + 6 { //Step No. 1, 2 or 6

                    cp_step_no += 1 //Increment CP step no.

                    cp_bcast = 0 //Set broadcasting CP to 1st CP

                    //Send signal to 1st CP to broadcast
                    logging.Info.Println("Sending signal to", cp_cnames[cp_bcast], "Step No.", cp_step_no-ts_s_no)
                    signalParty(cp_cnames[cp_bcast], cp_addr[cp_bcast], false, cp_step_no)

                } else if cp_step_no == ts_s_no + 3 || cp_step_no == ts_s_no + 4 || cp_step_no == ts_s_no + 7 || cp_step_no == ts_s_no + 8 || cp_step_no == ts_s_no + 9 { //Step No. 2, 3, 4, 7, 8, or 9 (Regular sequential CP broadcast)

                    if cp_bcast == no_CPs - 1 { //If Last CP has broadcasted

                        cp_step_no += 1 //Increment CP step no.

                        cp_bcast = 0 //Set broadcasting CP to 1st CP

                    } else {

                        cp_bcast += 1 //Set broadcasting CP as next CP
                    }

                    //Send signal to next CP to broadcast
                    logging.Info.Println("Sending signal to", cp_cnames[cp_bcast], "Step No.", cp_step_no-ts_s_no)
                    signalParty(cp_cnames[cp_bcast], cp_addr[cp_bcast], false, cp_step_no)

                } else if cp_step_no == ts_s_no + 5 {  //Step No. 5

                    if cp_bcast == no_CPs - 1 { //If Last CP has broadcasted

                        cp_step_no += 1 //Increment CP step no.

                        cp_bcast = -1 //Wait for CPs acknowledgement

                        if data_flag == true {//If data flag set

                            dp_step_no += 1 //Increment DP step no.

                            //Signal DPs to send data to CPs
                            logging.Info.Println("Signal DPs to send masked data shares. Step No.", dp_step_no-ts_s_no)
                            for i := 0; i < no_DPs; i++ {

                                signalParty(dp_cnames[i], dp_addr[i], false, dp_step_no)
                            }
       	       	        }

                        data_flag = true //Set data flag

                    } else {

                        cp_bcast += 1 //Set broadcasting CP as next CP

                        //Send signal to next CP to broadcast
                        logging.Info.Println("Sending signal to", cp_cnames[cp_bcast], "Step No.", cp_step_no-ts_s_no)
                        signalParty(cp_cnames[cp_bcast], cp_addr[cp_bcast], false, cp_step_no)
                    }

                } else if cp_step_no == ts_s_no + 10 {  //Step No. 10

                    if cp_bcast == no_CPs - 1 { //If Last CP has broadcasted

                        result := new(TSmsg.Result)
                        result.Agg = proto.String(agg)

                        //Write to config file
                        out, _ := proto.Marshal(result)
                        ioutil.WriteFile("result/"+qname+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"), out, 0644)

                        cp_step_no += 1 //Increment CP step no.

                        shutdownTS() //Shutdown TS gracefully

                    } else {

                        cp_bcast += 1 //Set broadcasting CP as next CP

                        //Send signal to next CP to broadcast
                        logging.Info.Println("Sending signal to", cp_cnames[cp_bcast], "Step No.", cp_step_no-ts_s_no)
                        signalParty(cp_cnames[cp_bcast], cp_addr[cp_bcast], false, cp_step_no)
                    }
                }

                no_cp_res = 0 //Set no. of CPs responded to zero
            }
        }
    }

    mutex.Unlock() //Unlock mutex
}

//Input: Command-line arguments
//Output: TS port number, Configuration file path
//Function: Parse Command-line arguments
func parseCommandline(arg []string) (string, string, string) {

    var ts_host string //TS hostname
    var ts_port string //TS port number
    var e_flag = false //Exit flag
    var config_file string //Config file path

    flag.StringVar(&ts_host, "h", "", "TS hostname to which to bind")
    flag.StringVar(&ts_cname, "t", "", "TS common name (required)")
    flag.StringVar(&ts_port, "p", "", "TS port number (required)")
    flag.StringVar(&config_file, "c", "config/config.params", "Config file path")
    flag.IntVar(&no_Expts, "e", 1, "No. of experiments")

    flag.Parse()

    if ts_cname == "" || ts_port == "" {

        logging.Error.Println("Argument required:")
        e_flag = true //Set exit flag

        if ts_cname == "" {

            logging.Error.Println("   -c string")
            logging.Error.Println("      TS common name (Required)")
        }

        if ts_port == "" {

            logging.Error.Println("   -p string")
            logging.Error.Println("      TS port number (Required)")
        }
    }

    if e_flag == true {//If exit flag set

        os.Exit(0) //Exit
    }

    return ts_host, ts_port, config_file
}

//Input: Configuration file path
//Function: Assign configuration parameters
func assignConfig(config_file string) {

    //Read configuration file
    in, _ := ioutil.ReadFile(config_file)
    config = &TSmsg.Config{}
    proto.Unmarshal(in, config)

    //Assign configuration parameters
    no_CPs = int(*config.Ncps) //No.of CPs
    no_DPs = int(*config.Ndps) //No. of DPs
    epoch = int(*config.Epoch) //Epoch
    cp_cnames  = make([]string, no_CPs) //CP common names
    cp_addr = make([]string, no_CPs) //CP addresses
    copy(cp_cnames[:], config.CPcnames) //Assign CP common names
    copy(cp_addr[:], config.CPaddr) //Assign CP  addresses
    dp_cnames  = make([]string, no_DPs) //DP common names
    dp_addr = make([]string, no_DPs) //DP addresses
    copy(dp_cnames[:], config.DPcnames) //Assign DP common names
    copy(dp_addr[:], config.DPaddr) //Assign DP addresses
    qname = *config.Q.Name //Assign query name
}

//Function: Initialize variables
func initValues() {

    start = time.Time{} //Data collection start time

    f_flag = false //Finish flag
    config_flag = true //Configuration flag
    data_flag = false //Data flag
    cp_step_no = 0 //CP step no.
    dp_step_no = 0 //DP step no.
    ts_s_no = 0 //TS session No.
    no_dp_res = 0 //No. of DPs responded
    no_cp_res = 0 //No. of CPs responded
    cp_bcast = 0 //Next CP to broadcast
    ln = nil //Server listener
    finish = make(chan bool) //Channel to send finish flag
    agg	= "" //Aggregated result
    clients = make(chan net.Conn) //Channel to handle simultaneous client connections
    mutex = &sync.Mutex{} //Mutex to lock common client variable
    wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown
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

//Input: Data, Destination common name, Destination address
//Function: Send Data to Destination
func sendDataToDest(data []byte, dst_cname string, dst_addr string) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/" + ts_cname + ".cert", "private/" + ts_cname + ".key")
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
    config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, ServerName: dst_cname,}
    con,err := reDial(10, 180, dst_addr)
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

//Input: TS common name
//Output: Socket
//Function: Accept new connections in  Socket
func acceptConnections() {

    defer wg.Done() //Decrement counter when goroutine completes

    for {

        //Create Server Socket
        cert, err1 := tls.LoadX509KeyPair("certs/" + ts_cname + ".cert", "private/" + ts_cname + ".key")
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

//Function: Singnal to all CPs, DPs and shutdown TS gracefully
func shutdownTS() {

    f_flag = true //Set finish flag

    close(finish) //Quit

    ln.Close() //Shutdown TS gracefully
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
