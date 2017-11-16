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
    //"github.com/golang/protobuf/proto"
    "io"
    "io/ioutil"
    "net"
    "os"
    //"PSC/TS/tsres"
    "strconv"
    //"sync"
    "syscall"
)

var cp_bcast int //CP Number Broadcasting
var step_no uint32 //Step Number
var s_no uint32 //Session No.

func main() {

    //Set Step No.
    step_no = 0

    //Set Broadcasting CP
    cp_bcast = 1

    seed := rand.NewSource(time.Now().UnixNano())
    rnd := rand.New(seed)

    s_no = 0
    for s_no == 0 {
        s_no = uint32(rnd.Int31()) //Set Session No. to Non-Zero Random Number
    }

    no_CPs, no_DPs := parseCommandline(os.Args) //Parse number of CPs and DPs
     
    fmt.Println("Started Tally Server")

    //Listen to the TCP port
    sock := createServer("5100")
    fmt.Println("No. of CPs, DPs", no_CPs, no_DPs, sock)

    //Signal CP1 to broadcast data
    go broadcastCPData(cp_bcast)
    fmt.Println("CP BCast No. of goroutines",  runtime.NumGoroutine())

    for{

        /*mutex.Lock() //Lock mutex

        if f_flag == true { //If finish flag set

            fmt.Println("finish")
            break

        }

        mutex.Unlock() //Unlock mutex

        fmt.Println("I am waiting", runtime.NumGoroutine())

        if conn := acceptConnections(cp_no, sock); conn != nil { //If Data is available

            //Handle connections in separate channels
            go handleClients(clients, cp_no, x, pub)

            fmt.Println("Handle Client No. of goroutines",  runtime.NumGoroutine())

            //Handle each client in separate channel
            clients <- conn
        
        }*/
    }
}

//Input: CP number
//Function: Signal next CP to broadcast
func broadcastCPData(cp_no int) {

    var tb bytes.Buffer //Temporary Buffer
    resp := new(TSres.Response)

    //Set TS response step no.
    resp.s_no = step_no - s_no

    //Set TS response CP no.
    resp.c_no = cp_no

    //Set TS response broadcast flag
    resp.c_no = true

    //Convert to Bytes
    resp1, _ := proto.Marshal(resp)

    sendDataToDest(resp1, cp_no) 
}

/*//Input: Client Socket Channel, CP number, CP private key, CP public key
//Function: Handle client connection 
func handleClients(clients chan net.Conn, cp_no int, x abstract.Scalar, pub *Schnorrkey.Pub) {

    //Wait for next client connection to come off queue.
    conn := <-clients

    mutex.Lock() //Lock mutex

    //Receive Data
    buf := receiveData(conn)
    conn.Close()
    
    //Parse Common Name
    com_name := parseCommonName(conn)

    //If Data Received from DP
    if com_name[0:len(com_name)-1] == "DP" {

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

        src,_ := strconv.Atoi(com_name[len(com_name)-1:]) //No. of CP that sent
    
        //Verify Sign
        l, f := verifyCPSign(suite, src, buf)

        //Step No. in Message
        t := binary.BigEndian.Uint32(buf[1:5])

        fmt.Println("Handle Client Inside CP", runtime.NumGoroutine(), com_name, step_no-s_no, t==step_no, b_flag, cp_bcast)

        //If Step No. and Signature Verified
        if t == step_no && f == true {

            //If Broadcast Flag Set
            if uint8(buf[0]) == 1 {

                if no_cp_res != 0 { //If not the 1st broadcasted message

                    //Compare Signatures
                    if bytes.Compare(buf[9:9+l], b_j[no_cp_res - 1]) != 0 { //If signatures don't match

                        fmt.Print("Signatures Not Matching")
                        os.Exit(0)
                    }
                }
                             
	        b_j[no_cp_res] = buf[9:9+l] //Store Signed Message
                proto.Unmarshal(buf[9+l:], cp_resp) //Store Message

                r_index = no_cp_res
                r_cp_bcast = cp_bcast
                r_flag = true

            } else if uint8(buf[0]) == 0 { //If Broadcast Flag not Set

                if no_cp_res != 0 { //If not the 1st broadcasted message

                    //Compare Signatures      
                    if bytes.Compare(buf[9+l:], b_j[no_cp_res - 1]) != 0 { //If signatures don't match

                        fmt.Print("Signatures Not Matching")
                        os.Exit(0)
                    }
                }

                b_j[no_cp_res] = buf[9+l:] //Store Signed Message
            }

            no_cp_res += 1 //Increment No. of CP Responses

        } else if f != true { //If Signature not verified

            fmt.Print("Signature Not Verified")
            os.Exit(0)
        } 

        //If All CPs have finished Broadcasting/Re-Broadcasting
        if no_cp_res == no_CPs - 1 {

            //If Step No. is 0
            if step_no == 0 {

                s_no = binary.BigEndian.Uint32(cp_resp.R[0]) //Set Session No.

            } else if step_no == s_no + 1 { //If Step No. is 1

                tmp := bytes.NewReader(cp_resp.R[0]) //Temporary
                y[cp_bcast - 1] = suite.Point()
                y[cp_bcast - 1].UnmarshalFrom(tmp)

                //Verify Proof
                rep := proof.Rep("X", "x", "B")
                public := map[string]abstract.Point{"B": suite.Point().Base(), "X": y[cp_bcast - 1]}
                verifier := rep.Verifier(suite, public)
                err := proof.HashVerify(suite, strconv.Itoa(int(step_no)), verifier, cp_resp.Proof[0])

                //If Error in Verifying
                if err != nil {
		    fmt.Println("Step 1 Proof Not Verified")
                    os.Exit(0)
                }

                //Multiply to create Compound Public Key
                Y.Add(Y, y[cp_bcast - 1])

            } else if step_no == s_no + 2 { //If Step No. 2

                //Convert Bytes to Data
                for i := 0; i < n; i++ {

                    tmp := bytes.NewReader(cp_resp.R[2*i]) //Temporary
                    nr_o[i][0] = suite.Point()
                    nr_o[i][0].UnmarshalFrom(tmp) //Assign Shuffled Noise Elgamal Blinding Factors

                    tmp = bytes.NewReader(cp_resp.R[(2*i)+1]) //Temporary
                    nr_o[i][1] = suite.Point()
                    nr_o[i][1].UnmarshalFrom(tmp) //Assign Shuffled Noise Elgamal Blinding Factors

                    tmp = bytes.NewReader(cp_resp.C[2*i]) //Temporary
                    nc_o[i][0] = suite.Point()
                    nc_o[i][0].UnmarshalFrom(tmp) //Assign Shuffled Noise Elgamal Ciphers

                    tmp = bytes.NewReader(cp_resp.C[(2*i)+1]) //Temporary
                    nc_o[i][1] = suite.Point()
                    nc_o[i][1].UnmarshalFrom(tmp) //Assign Shuffled Noise Elgamal Ciphers

                    //Verify Proof
                    verifier := shuffle.BiffleVerifier(suite, nil, Y, nr[i], nc[i], nr_o[i], nc_o[i])
                    err := proof.HashVerify(suite, strconv.Itoa(int(step_no))+strconv.Itoa(i), verifier, cp_resp.Proof[i])

                    //If Not Verified
                    if err != nil {
                        fmt.Println("Step 2 Proof Not Verified")
                        os.Exit(0)
                    }
                }
                                
                //Iterate over all Noise Counters
                for i := 0; i < n; i++ {

                    //Swap Current Output as Input
                    nr[i][0] = suite.Point().Set(nr_o[i][0])
                    nr[i][1] = suite.Point().Set(nr_o[i][1])
                    nc[i][0] = suite.Point().Set(nc_o[i][0])
                    nc[i][1] = suite.Point().Set(nc_o[i][1])
                }

                //If Last CP has Broadcasted
                if cp_bcast == no_CPs {

                    //Iterate Over all Noise Counters
                    for i := b; i < b+n; i++ {

                        //Select 1st Coin as Noise
                        R[i] = suite.Point().Set(nr[i-b][0])
                        C[i] = suite.Point().Set(nc[i-b][0])
                    }
                }

            } else if step_no == s_no + 3 { //If Step No. 3

                //Convert Bytes to Data
                for i := 0; i < b; i++ {

                    tmp := bytes.NewReader(cp_resp.R[i]) //Temporary
                    tp := suite.Point() //Temporary
                    tp.UnmarshalFrom(tmp)
                    R[i].Add(R[i], tp) //Multiply Elgamal Blinding Factors

                    //Verify Proof
                    rep := proof.Rep("X", "x", "B")
                    public := map[string]abstract.Point{"B": suite.Point().Base(), "X": tp}
                    verifier := rep.Verifier(suite, public)
                    err := proof.HashVerify(suite, strconv.Itoa(int(step_no))+strconv.Itoa(i), verifier, cp_resp.Proof[i])

                    //If Error in Verifying
                    if err != nil {
                        fmt.Println("Step 3 Proof Not Verified")
                        os.Exit(0)
                    }

                    tmp = bytes.NewReader(cp_resp.C[i])
                    tp = suite.Point()
                    tp.UnmarshalFrom(tmp)
                    C[i].Add(C[i], tp) //Multiply Elgamal Ciphers
                }

            } else if step_no == s_no + 4 { //If Step No. 4

                //Convert Bytes to Data
                for i := 0; i < b+n; i++ {

                    tmp := bytes.NewReader(cp_resp.R[i]) //Temporary
                    R_O[i] = suite.Point()
                    R_O[i].UnmarshalFrom(tmp) //Assign Shuffled Elgamal Blinding Factors

                    tmp = bytes.NewReader(cp_resp.C[i]) //Temporary
                    C_O[i] = suite.Point()
                    C_O[i].UnmarshalFrom(tmp) //Assign Shuffled Elgamal Ciphers
                }

                //Verify Proof
                verifier := shuffle.Verifier(suite, nil, Y, R, C, R_O, C_O)
                err := proof.HashVerify(suite, strconv.Itoa(int(step_no)), verifier, cp_resp.Proof[0][:])

                //If not verified
                if err != nil {
                    fmt.Println("Step 4 Proof Not Verified")
                    os.Exit(0)
                }

                //Iterate over all Counters
                for i := 0; i < b+n; i++ {

                    //Swap Current Output as Input
                    R[i] = suite.Point().Set(R_O[i])
                    C[i] = suite.Point().Set(C_O[i])
                }
                    
            } else if step_no == s_no + 5 { //If Step No. 5

                prf := make([]*ReRandomizeProof, b+n)
                tmp := bytes.NewReader(cp_resp.Proof[0])
                suite.Read(tmp, prf)

                //Convert Bytes to Data
                for i := 0; i < b+n; i++ {

                    tmp = bytes.NewReader(cp_resp.R[i]) //Temporary
                    R_O[i] = suite.Point()
                    R_O[i].UnmarshalFrom(tmp) //Assign Re-Randomized Elgamal Blinding Factors

                    tmp = bytes.NewReader(cp_resp.C[i]) //Temporary
                    C_O[i] = suite.Point()
                    C_O[i].UnmarshalFrom(tmp) //Assign Re-Randomized Elgamal Ciphers

                    //Verify Proof
                    err := prf[i].Verify(suite, R[i], C[i], nil, Y, R_O[i], C_O[i])

                    //If not verified
                    if err != nil || R_O[i].Equal(suite.Point().Base()) == true || C_O[i].Equal(suite.Point().Base()) == true {
                        fmt.Println("Step 5 Proof Not Verified")
                        os.Exit(0)
                    }
                }

                //Iterate over all Counters
                for i := 0; i < b+n; i++ {

                    //Swap Current Output as Input
                    R[i] = R_O[i]
                    C[i] = C_O[i]
                }

            } else if step_no == s_no + 6 { //If Step No. 6

                prf := make([]*proof.DLEQProof, b+n)
                tmp := bytes.NewReader(cp_resp.Proof[0])
                suite.Read(tmp, prf)

                //Convert Bytes to Data
                for i := 0; i < b+n; i++ {

                    tmp := bytes.NewReader(cp_resp.R[i]) //Temporary
                    R_O[i] = suite.Point()
                    R_O[i].UnmarshalFrom(tmp) //Assign Re-Randomized Elgamal Blinding Factors

                    tmp = bytes.NewReader(cp_resp.C[i])  //Temporary
                    C_O[i] = suite.Point()
                    C_O[i].UnmarshalFrom(tmp) //Assign Re-Randomized Elgamal Ciphers

                    //Verify Proof
                    err := prf[i].Verify(suite, nil, R[i], y[cp_bcast - 1], suite.Point().Sub(C[i], C_O[i]))

                    //If not verified
                    if err != nil {
                        fmt.Println("Step 6 Proof Not Verified")
                        os.Exit(0)
                    }
                }
                                
                //Iterate over all Counters
                for i := 0; i < b+n; i++ {

                    //Swap Current Output as Input
                    C[i] = C_O[i]
                }
            }

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

    fmt.Println("Handle Client Mutex Unlock", runtime.NumGoroutine())
}*/

//Input: Command-line Arguments
//Output: No. of CPs, No. of DPs
//Function: Parse Command-line Arguments
func parseCommandline(arg []string) (int, int) {

    var no_CPs, no_DPs int

    flag.IntVar(&no_CPs, "c", 5, "Number of CPs")
    flag.IntVar(&no_DPs, "d", 20, "Number of DPs")
    flag.Parse()

    return no_CPs, no_DPs
}

//Input: Data, Destination
//Function: Send Data to Destination
func sendDataToDest(data []byte, dst string) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/TS.cert", "private/TS.key")
    checkError(err)

    //Add CA certificate to pool
    caCert, _ := ioutil.ReadFile("../CA/certs/ca.cert")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    //Dial TCP Connection
    config := tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: caCertPool, InsecureSkipVerify: true} //ServerName: dst,}
    if (dst == "DP") {

        con,err := net.Dial("tcp", "localhost:7100")

    } else {

        con,err := net.Dial("tcp", "localhost:6100")
    }
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
func acceptConnections(cn string, listener net.Listener) *tls.Conn {
    //Create Server Socket
    cert, err := tls.LoadX509KeyPair("certs/"+ cn +".cert", "private/" + cn + ".key")
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

//Input: Error
//Function: Check Error
func checkError(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
        os.Exit(1)
    }
}
