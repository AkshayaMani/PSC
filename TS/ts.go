

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
    //"github.com/dedis/crypto/abstract"
    //"github.com/dedis/crypto/nist"
    "github.com/golang/protobuf/proto"
    "io"
    "io/ioutil"
    "math"
    "math/rand"
    "net"
    "os"
    "PSC/TS/tsmsg"
    "runtime"
    //"strconv"
    "sync"
    "syscall"
    "time"
)

var no_CPs = 5 //No.of CPs
var no_DPs = 20 //No. of DPs
var no_Expts = 3 //No. of measurements
var cp_hname = []string{"CP1", "CP2", "CP3", "CP4", "CP5"} //CP hostnames
var dp_hname = []string{"DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1", "DP1"} //DP hostnames
var cp_ips = []string{"10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17"}; //CP IPs
var dp_ips = []string{"10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17", "10.176.5.17"}; //DP IPs
var epoch int //Epoch
var epsilon float64 //Privacy parameter epsilon
var delta float64 //Privacy parameter delta
var sock net.Listener //Server listener
var finish chan bool //Channel to send finish flag
var f_flag bool //Finish flag
var cp_bcast int //Next CP to broadcast
var cp_step_no uint32 //CP Step Number
var dp_step_no uint32 //DP Step Number
var cp_s_no uint32 //CP session No.
var dp_s_no uint32 //DP session No.
var no_dp_res int = 0 //No. of DPs responded
var no_cp_res int = 0 //No. of CPs responded
var b_flag bool //Broadcast Flag
var mutex = &sync.Mutex{} //Mutex to lock common client variable
var wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown

func main() {

    parseCommandline(os.Args) //Parse epoch and privacy parameters - epsilon and delta

    expt_no := 0 //Set measurement no. to 0
    
    for{

        //Listen to the TCP port
        sock = createServer("5100")

        fmt.Println("Started Tally Server")

        finish = make(chan bool) //Initialise finish channel

        f_flag = false //Set finish flag

        expt_no = expt_no + 1 //Increment measurement no.

        if expt_no < no_Expts { //Continue measurements

            seed := rand.NewSource(time.Now().UnixNano())
            rnd := rand.New(seed)

            //Generate CP session no.
            cp_s_no = 0
            for cp_s_no == 0 {

                cp_s_no = uint32(rnd.Int31()) //Set session no. to non-zero random number
            }

            //Generate DP session no.
            dp_s_no = 0
            for dp_s_no == 0 {
        
                dp_s_no = uint32(rnd.Int31()) //Set session no. to non-Zero random number
            }
     
            //PSC configuration to send to CPs
            config := new(TSmsg.Config)
            config.SNo = proto.Int32(int32(cp_s_no))
            config.Epoch = proto.Int32(int32(epoch))
            config.Epsilon = proto.Float32(float32(epsilon))
            config.Delta = proto.Float32(float32(delta))
            config.Ncps = proto.Int32(int32(no_CPs))
            config.CPhname = make([]string, no_CPs)
            config.CPips = make([]string, no_CPs)
    
            for i := 0; i < no_CPs; i++ {

                config.CPhname[i] = cp_hname[i]
                config.CPips[i] = cp_ips[i]
            }
    
            config.Ndps = proto.Int32(int32(no_DPs))
            config.DPhname = make([]string, no_DPs) 
            config.DPips = make([]string, no_DPs)

            for i := 0; i < no_DPs; i++ {

                config.DPhname[i] = dp_hname[i]
         	config.DPips[i] = dp_ips[i]
            }

            //Convert to Bytes
            configbytes, _ := proto.Marshal(config)

            //Send config to CPs
            for i := 0; i < no_CPs; i++ {

                continue
                //sendDataToDest(configbytes, cp_hname[i], cp_ips[i])
            }
    
            //PSC configuration to send to DPs
            config.SNo = proto.Int32(int32(dp_s_no))

            //Convert to Bytes
            configbytes, _ = proto.Marshal(config)

            //Send config to DPs
            for i := 0; i < no_DPs; i++ {

                continue
     	        //sendDataToDest(configbytes, dp_hname[i], dp_ips[i], false)
            }

            cp_step_no = cp_s_no //Set CP step no.
            dp_step_no = dp_s_no //Set DP step no.

            dp_step_no += 1 //Increment DP step no.
            cp_step_no += 1 //Increment CP step no.

            //Send signal to DPs to share Symmetric keys with the CPs
            for i := 0; i < no_DPs; i++ {

                signalPartytoBcast(dp_hname[i], dp_ips[i], false)
            }

            //Channel to handle simultaneous connections
            clients := make(chan net.Conn)

            fmt.Println(sock, configbytes)

            loop:

            for{

                conn, err := acceptConnections(sock) //Accept connections

                if conn != nil { //If Data is available

                    wg.Add(1)

                    //Handle connections in separate channels
                    go handleClients(clients)

                    fmt.Println("Handle Client No. of goroutines", runtime.NumGoroutine())

                    //Handle each client in separate channel
                    clients <- conn

                } else if err != nil {

                    select {

                        case <-finish:

                            if dp_step_no != dp_s_no + 3 { //If DPs have not finished

                                //Send finish signal to all DPs
                                for i := 0; i < no_DPs; i++ {

                                    signalPartytoBcast(dp_hname[i], dp_ips[i], true)
                                }
                            }

                            if cp_step_no != cp_s_no + 11 { //If CPs have not finished  

                                //Send finish signal to all CPs
                                for i := 0; i < no_CPs; i++ {

                                    signalPartytoBcast(cp_hname[i], cp_ips[i], true)
                                }
                            }

                            wg.Wait()                            

                            if cp_step_no == cp_s_no + 11 { //Finish

                                //Finishing measurement
                                fmt.Println("Finished measurement no. ", expt_no)

                            } else {

                                //Quit and Re-start measurement
                                fmt.Println("Quitting... \n Re-starting measurement...")

                                expt_no = expt_no - 1 //Decrement measurement no.

                            }

                            break loop

                        default:
                    }
                }
            }

        } else {
 
            var exit string //Continue response

            fmt.Println("Do you want to exit? (Y or N)")
            fmt.Scanf("%s", &exit)

            if exit == "N" || exit == "n" { //If continue with same parameters
               
                fmt.Println("Enter no. of experiments")
                fmt.Scanf("%d", &no_Expts) 

                expt_no = 0 //Reset measurement no.

            } else {

                break //End Measurement
            }
        }
    }   

    fmt.Println("Finished measurements. Exiting.")
}

//Input: Party (CP/DP) hostname, Party (CP/DP) IP, Finish flag 
//Function: Signal next Party to broadcast
func signalPartytoBcast(party_hname, party_ip string, fin bool) {

    mutex.Lock() //Lock mutex

    sig := new(TSmsg.Signal) //TS signal for next broadcast party

    sig.Fflag = proto.Bool(fin) //Set TS signal finish flag

    //Set TS signal session no.
    if contains(cp_hname, party_hname) {

        //Set CP session no.
        sig.SNo = proto.Int32(int32(cp_s_no))

    } else if contains(dp_hname, party_hname) {

       	//Set DP session no.
        sig.SNo = proto.Int32(int32(dp_s_no))

    }

    //Convert to Bytes
    sigb, _ := proto.Marshal(sig)

    //Send signal to next broadcast party
    fmt.Println(sigb)
    //sendDataToDest(sigb, party_hname, party_ip)

    mutex.Unlock()
}

//Input: Client Socket Channel
//Function: Handle client connection 
func handleClients(clients chan net.Conn) {

    defer wg.Done()

    //Wait for next client connection to come off queue.
    conn := <-clients

    //Receive Data
    buf := receiveData(conn)

    //Parse Common Name
    com_name := parseCommonName(conn)

    //Parse response
    resp := new(TSmsg.Signal)
    proto.Unmarshal(buf, resp)

    mutex.Lock() //Lock mutex

    if f_flag == false { //Finish flag not set

        //If Data Received from DP
        if contains(dp_hname, com_name) {

            dpsig := new(TSmsg.Signal) //Signal from DP

            //If finish flag not set
            if *dpsig.Fflag == false {

                //Verify Step No. and Session No.
                if *dpsig.SNo == int32(dp_step_no) {

                    no_dp_res = no_dp_res + 1 //Increment no. of DP responded

                } else { //Wrong acknowledgement

                    fmt.Println("Error: Wrong acknowledgement by DP ", com_name)

                    shutdownTS() //Shutdown TS gracefully

                    return
                }

            } else if *dpsig.Fflag == true {//Error

                fmt.Println("Error: DP ", com_name, "sent quit")

                shutdownTS() //Shutdown TS gracefully

                return
            }

            //If all DPs have responded
            if no_dp_res == no_DPs {

                var start time.Time                

                if dp_step_no == dp_s_no + 1 { //Step No. 1

                    dp_step_no += 1 //Increment DP step no.

                    //Send signal to DPs to start data collection
                    for i := 0; i < no_DPs; i++ {

                        signalPartytoBcast(dp_hname[i], dp_ips[i], false)
                    }         
                               
                    start = time.Now() //Data collection start time

                } else if dp_step_no == dp_s_no + 2 { //Step No. 2

                    end := time.Since(start).Hours()

                    if end >= float64(epoch) {//If data collected for an epoch
                          
                        dp_step_no += 1 //Increment DP step no.

                        //Send signal to send data to CPs
                        for i := 0; i < no_DPs; i++ {

                            signalPartytoBcast(dp_hname[i], dp_ips[i], false)
                        }

                    } else { //Data not collected for an epoch - error

                        fmt.Println("Error: Data not collected for an epoch")

                        shutdownTS() //Shutdown TS gracefully

                        return
                    }

                } else if dp_step_no == dp_s_no + 3 { //Step No. 3

                    //Send finish signal to DPs 
                    for i := 0; i < no_DPs; i++ {

                        signalPartytoBcast(dp_hname[i], dp_ips[i], true)
                    }
                }

                no_dp_res = 0 //Set no. of DPs responded to zero
            }
        }

        //If Data Received from CP
        if contains(cp_hname, com_name) {

            cpsig := new(TSmsg.Signal) //Signal from CP

            //If finish flag not set
            if *cpsig.Fflag == false {

                //Verify Step No. and Session No.
                if *cpsig.SNo == int32(cp_step_no) {

                    no_cp_res = no_cp_res + 1 //Increment no. of CP responded

                } else { //Wrong acknowledgement

                    fmt.Println("Error: Wrong acknowledgement by CP ", com_name)

                    shutdownTS() //Shutdown TS gracefully

                    return
                }

            } else if *cpsig.Fflag == true {//Error

                fmt.Println("Error: CP ", com_name, "sent quit")

                shutdownTS() //Shutdown TS gracefully

                return
            }

            //If all CPs have responded
            if no_cp_res == no_CPs {

                if cp_step_no == cp_s_no + 1 || cp_step_no == cp_s_no + 6 { //Step No. 1 or 6 (Acknowledgement from CPs that DPs have sent shared key/data)

                    cp_step_no += 1 //Increment CP step no.

                    cp_bcast = 1 //Set broadcasting CP to 1st CP

                    //Send signal to 1st CP to broadcast
                    signalPartytoBcast(cp_hname[cp_bcast-1], cp_ips[cp_bcast-1], false)
                               
                } else if cp_step_no == cp_s_no + 2 || cp_step_no == cp_s_no + 3 || cp_step_no == cp_s_no + 4 || cp_step_no == cp_s_no + 7 || cp_step_no == cp_s_no + 8 || cp_step_no == cp_s_no + 9 { //Step No. 2, 3, 4, 7, 8, or 9 (Regular sequential CP broadcast)

                    if cp_bcast == no_CPs { //If Last CP has broadcasted

                        cp_step_no += 1 //Increment CP step no.

                        cp_bcast = 1 //Set broadcasting CP to 1st CP

                    } else {

                        cp_bcast += 1 //Set broadcasting CP as next CP
                    } 

                    //Send signal to next CP to broadcast
                    signalPartytoBcast(cp_hname[cp_bcast-1], cp_ips[cp_bcast-1], false)

                } else if cp_step_no == cp_s_no + 5 {  //Step No. 5

                    if cp_bcast == no_CPs { //If Last CP has broadcasted

                        cp_step_no += 1 //Increment CP step no.

                        cp_bcast = 0 //Wait for CPs acknowledgement

                    } else {

                        cp_bcast += 1 //Set broadcasting CP as next CP

                        //Send signal to next CP to broadcast
                        signalPartytoBcast(cp_hname[cp_bcast-1], cp_ips[cp_bcast-1], false)
                    }

                } else if cp_step_no == cp_s_no + 10 {  //Step No. 10

                    if cp_bcast == no_CPs { //If Last CP has broadcasted

                        cp_step_no += 1 //Increment CP step no.

                        shutdownTS() //Shutdown TS gracefully
                        
                    } else {

                        cp_bcast += 1 //Set broadcasting CP as next CP

                        //Send signal to next CP to broadcast
                        signalPartytoBcast(cp_hname[cp_bcast-1], cp_ips[cp_bcast-1], false)
                    }
                }

                no_cp_res = 0 //Set no. of CPs responded to zero
            }
        }
    }

    mutex.Unlock() //Unlock mutex
}

//Input: Command-line arguments
//Function: Parse Command-line arguments
func parseCommandline(arg []string) {

    flag.IntVar(&epoch, "h", 24, "Epoch (in hours)")
    flag.Float64Var(&epsilon, "e", 0.3, "Privacy parameter epsilon")
    flag.Float64Var(&delta, "d", math.Pow(10, -12), "Privacy parameter delta")

    flag.Parse()
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

//Input: Data, Destination hostname, Destination ip
//Function: Send Data to Destination
func sendDataToDest(data []byte, dst_hname string, dst_ip string) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/TS.cert", "private/TS.key")
    checkError(err)

    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    //Dial TCP Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, ServerName: dst_hname,}
    sock := ""
    if (dst_hname == "DP") {

        sock = dst_ip+":7100"

    } else {

        sock = dst_ip+":6100"
    }

    con,err := net.Dial("tcp", sock)
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

//Input: Client common name, Listener
//Output: Socket
//Function: Accept new connections in  Socket
func acceptConnections(listener net.Listener) (*tls.Conn, error) {
    //Create Server Socket
    cert, err1 := tls.LoadX509KeyPair("certs/TS.cert", "private/TS.key")
    checkError(err1)
    
    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    
    //Create TLS Listener and Accept Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caCertPool, ClientAuth: tls.RequireAndVerifyClientCert,}
    conn, err := listener.Accept()
    file, _ := conn.(*net.TCPConn).File()
    err1 = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
    sock := tls.Server(conn, &config)
        
    return sock, err
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

//Input: Port No.
//Output: Server Socket
//Function: Creates Server Socket
func createServer(port string) net.Listener {

    //Create TCP Listener
    listener, _ := net.Listen("tcp", "localhost:" + port)

    return listener
}

//Function: Singnal to all CPs, DPs and shutdown TS gracefully
func shutdownTS() {

    f_flag = true //Set finish flag

    close(finish) //Quit

    sock.Close() //Shutdown TS gracefully
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
