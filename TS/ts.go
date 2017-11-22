
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
    "PSC/TS/tssig"
    "PSC/TS/tsconfig"
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
var cp_bcast int //Next CP to broadcast
var cp_s_no uint32 //CP session No.
var cp_step_no uint32 //Step Number
var dp_step_no uint32 //Step Number
var dp_s_no uint32 //DP session No.
var no_cp_res int = 0 //No. of CPs responded
var b_flag bool //Broadcast Flag
var mutex = &sync.Mutex{} //Mutex to lock common client variable

func main() {

    //Listen to the TCP port
    sock := createServer("5100")

    fmt.Println("Started Tally Server")

    epsilon, delta := parseCommandline(os.Args) //Parse privacy parameters - epsilon and delta

    expt_no := 0 //Set measurement no. to 0
    f_flag := true //Finish Flag

    for{

        expt_no = expt_no + 1 //Increment measurement no.

        if f_flag == true && expt_no < no_Expts { //Continue measurements

            f_flag = false //Set finish flag to false
   
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
            config := new(TSconfig.Config)
            config.SNo = proto.Int32(int32(cp_s_no))
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
     	        //sendDataToDest(configbytes, dp_hname[i], dp_ips[i])
            }

            //Channel to send finish flag
            finish := make(chan bool)

            b_flag = false //Set broadcast flag to false
            dp_s_no = dp_s_no + 1 //Increment DP session no.

            //Send signal to DPs to share Symmetric keys with the CPs
            for i := 0; i < no_CPs; i++ {

                continue
                //signalPartytoBcast(dp_hname[i], dp_ips[i], finish)
            }

            //Channel to handle simultaneous connections
            clients := make(chan net.Conn)

            fmt.Println(sock, configbytes)

            for{

                f_flag = <-finish
    
                if f_flag == true { //If finish flag set
                    
                    fmt.Println("Finished measurement no. ", expt_no)
                    break
                }

                fmt.Println("I am waiting", runtime.NumGoroutine())

                if conn := acceptConnections(sock); conn != nil { //If Data is available

                    //Handle connections in separate channels
                    go handleClients(clients, finish)

                    fmt.Println("Handle Client No. of goroutines", runtime.NumGoroutine())

                    //Handle each client in separate channel
                    clients <- conn        
                }
            }

        } else {
 
            var quit string //Continue response

            fmt.Println("Do you want to quit? (Y or N)")
            fmt.Scanf("%s", &quit)

            if quit == "N" || quit == "n" { //If continue with same parameters
               
                fmt.Println("Enter no. of experiments")
                fmt.Scanf("%d", &no_Expts) 

                expt_no = 0 //Reset measurement no.
            }
        }
    }   
}

//Input: Party (CP/DP) hostname, Party (CP/DP) IP, Finish flag channel
//Function: Signal next Party to broadcast
func signalPartytoBcast(party_hname, party_ip string, finish chan bool) {

    mutex.Lock() //Lock mutex

    sig := new(TSsig.Signal) //TS signal for next broadcast party

    sig.Fflag = proto.Bool(false) //Set TS signal finish flag to false

    //Set TS signal session no.
    if contains(cp_hname, party_hname) {

        sig.SNo = proto.Int32(int32(cp_s_no))
        sig.StepNo = proto.Int32(int32(cp_step_no))
   
    } else if contains(dp_hname, party_hname) {

        sig.SNo = proto.Int32(int32(dp_s_no))
        sig.StepNo = proto.Int32(int32(dp_step_no))

    } else {

        sig.Fflag = proto.Bool(true) //Set TS signal finish flag to true
        finish <- true //Error: Set TS finish flag
    }

    if *sig.Fflag == false {

        //Set TS signal broadcast flag
        sig.Bflag = proto.Bool(true)

        //Convert to Bytes
        sigb, _ := proto.Marshal(sig)

        //Send signal to next broadcast party
        sendDataToDest(sigb, party_hname, party_ip)
     }

    mutex.Unlock() 
}

//Input: Client Socket Channel, Finish flag channel
//Function: Handle client connection 
func handleClients(clients chan net.Conn, finish chan bool) {

    /*//Wait for next client connection to come off queue.
    conn := <-clients

    mutex.Lock() //Lock mutex

    //Receive Data
    buf := receiveData(conn)
    conn.Close()
    
    //Parse Common Name
    com_name := parseCommonName(conn)

    //If Data Received from DP
    if contains(dp_hname, com_name) {

        //Parse DP Response
        resp := new(DPres.Response)
        proto.Unmarshal(buf, resp)

	//Convert Bytes to Data
        for i := 0; i < b; i++ {

            tmp := suite.Scalar().SetBytes(resp.K[i])
            k_j[i] = suite.Scalar().Add(k_j[i], tmp) //Add Key Share
            tmp = suite.Scalar().SetBytes(resp.C[i])
            c_j[i] = suite.Scalar().Add(c_j[i], tmp) //Add Message Share
        } 

        //Increment the number of DPs responded
        dp_no = dp_no + 1

        //If all DPs have Responded
        if dp_no == no_DPs {

            //Add and Compute Share for Each Counter
            for i := 0; i < b; i++ {
                
                c_j[i] = suite.Scalar().Sub(c_j[i], k_j[i]) //Subtract Key Share from Message
            }

            //Set Message Flag
            m_flag = true
        }
             
    } else if com_name[0:len(com_name)-1] == "CP" {
                
        ts_resp := new(TSres.Response) //CP Response

        src,_ := strconv.Atoi(com_name[len(com_name)-1:]) //No. of CP that sent

        
    
        //Verify Step No., CP No. and TS broadcast flag
	if ts_resp.S_no == 0 { //Step No. 0

            //Set CP1 to broadcast and broadcast flag to false
	    cp_bcast = 1
	    b_flag = false

            //Signal next CP to broadcast data
            go broadcastCPData(cp_bcast) 

        } else if ts_resp.S_no == step_no - s_no + 1 && ts_resp.c_no == cp_bcast && ts_resp.f == b_flag {

            //Set broadcast flag to false
            b_flag = false

            //Signal next CP to broadcast data
            go broadcastCPData(cp_bcast)

        } else if ts_resp.s_no == step_no - s_no + 1 && ts_resp.c_no != cp_bcast && ts_resp.f == b_flag {

	    

	} else { //Wrong acknowledgement

            fmt.Print("Wrong Acknowledgement")
            os.Exit(0)
        } 

        //If All CPs have finished Re-Broadcasting
        if no_cp_res == no_CPs - 1 {

            //If Step No. 0
            if step_no == 0 {

                step_no = s_no + 1 //Set Step No.

            } else {

                //If Last CP
                if cp_bcast == no_CPs {

                    if step_no != s_no + 6 { //If Step No. not 6

                        step_no += 1 //Start Next Step Broadcast
                        cp_bcast = 1 //Set CP1 as Broadcasting CP
                    
                    } else {
 
                        f_flag = true //Set Finish Flag
                    }

                } else {

                    cp_bcast += 1 //Set Broadcasting CP as next CP
                }

                //Set Broadcast Flag of Next CP to True
                if cp_no == cp_bcast {

                    b_flag = true

                } else {

                    b_flag = false
                }
            }
                
            no_cp_res = 0 //Set No. of CPs Broadcasted/Re-Broadcasted to 0

            //If Broadcasting CP is Current CP and Broadcast Flag is set
            if cp_bcast == cp_no && b_flag == true {

                //CP1 broadcasts data
                go broadcastCPData(cp_no, x, pub)
                fmt.Println("CP BCast No. of goroutines",  runtime.NumGoroutine())
            }
        }
    }

    mutex.Unlock() //Unlock mutex

    if r_flag == true {
 
        sendDataN_1(step_no, r_cp_bcast, cp_no, b_j[r_index]) //Re-Broadcasting
    }

    fmt.Println("Handle Client Mutex Unlock", runtime.NumGoroutine())*/
}

//Input: Command-line Arguments
//Output: No. of CPs, No. of DPs
//Function: Parse Command-line Arguments
func parseCommandline(arg []string) (float64, float64) {

    var epsilon, delta float64

    flag.Float64Var(&epsilon, "e", 0.3, "Privacy parameter epsilon")
    flag.Float64Var(&delta, "", math.Pow(10, -12), "Privacy parameter delta")

    flag.Parse()

    return epsilon, delta
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
func acceptConnections(listener net.Listener) *tls.Conn {
    //Create Server Socket
    cert, err := tls.LoadX509KeyPair("certs/TS.cert", "private/TS.key")
    checkError(err)
    
    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)
    
    //Create TLS Listener and Accept Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caCertPool, ClientAuth: tls.RequireAndVerifyClientCert,}
    conn, err := listener.Accept()
    file, err := conn.(*net.TCPConn).File()
    err = syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
    sock := tls.Server(conn, &config)
        
    return sock
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
