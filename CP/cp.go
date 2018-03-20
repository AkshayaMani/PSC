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
    "errors"
    "flag"
    "fmt"
    "github.com/dedis/kyber"
    "github.com/dedis/kyber/group/edwards25519"
    "github.com/dedis/kyber/proof"
    "github.com/dedis/kyber/proof/dleq"
    "github.com/dedis/kyber/shuffle"
    "github.com/dedis/kyber/sign/schnorr"
    "github.com/golang/protobuf/proto"
    "io"
    "io/ioutil"
    "math/rand"
    "net"
    "os"
    "PSC/DP/dpres"
    "PSC/CP/schnorr/schnorrkey"
    "PSC/CP/cpres"
    "PSC/logging"
    "PSC/par"
    "PSC/TS/tsmsg"
    "runtime/debug"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"
)

// ReRandomizeProof represents a NIZK proof.
type ReRandomizeProof struct {
    C kyber.Scalar //Challenge
    R1 kyber.Scalar //Response 1
    R2 kyber.Scalar //Response 2
    T1 kyber.Point  // public commitment with respect to base point A
    T2 kyber.Point  // public commitment with respect to base point B
}

var suite = edwards25519.NewBlakeSHA256Ed25519() //Cipher suite
var pseudorand = suite.RandomStream() //For Randomness
var no_CPs int32 //No.of CPs
var no_DPs int32 //No. of DPs
var b int64 //Hash table size
var n int64 //No. of noise bins

var ts_cname string //TS common name
var ts_addr string //TS address
var cp_cnames []string //CP common names
var dp_cnames []string //DP common names
var cp_addr []string //CP addresses
var dp_addr []string //DP addresses
var cp_cname string //CP common name
var cp_no int32 //CP number
var no_dp_res int32 //No. of DPs Responded so far
var no_cp_res int32 //No. of CPs Broadcasted/Re-Broadcasted
var f_flag bool //Finish Flag
var cp_bcast int32 //CP Number Broadcasting
var step_no uint32 //CP Step Number
var cp_s_no uint32 //CP Session No.
var ts_s_no uint32 //TS Session No.
var ts_config_flag bool //TS configuration flag
var cp_session_flag bool //CP session flag
var ln net.Listener //Server listener
var finish chan bool //Channel to send finish flag
var clients chan net.Conn //Channel to handle simultaneous client connections
var x kyber.Scalar //CP private key
var y []kyber.Point //CP ElGamal public key list
var pub = new(Schnorrkey.Pub) //CP ElGamal public key in bytes
var Y = suite.Point().Null() //Compound public key
var k_j []kyber.Scalar //Key Share
var c_j []kyber.Scalar //Message Share
var b_j [][]byte //Broadcasted Message List
var nr [][2]kyber.Point //Noise ElGamal Blinding Factors
var nc [][2]kyber.Point //Noise ElGamal Ciphers
var nr_o [][2]kyber.Point //Shuffled Noise ElGamal Blinding Factors
var nc_o [][2]kyber.Point //Shuffled Noise ElGamal Ciphers
var R []kyber.Point //Product of all CP ElGamal Blinding Factors
var C []kyber.Point //Product of all CP ElGamal Ciphers
var R_O []kyber.Point //Shuffled ElGamal Blinding Factors
var C_O []kyber.Point //Shuffled ElGamal Ciphers
var cp_res_byte []byte //CP Response in bytes
var mutex = &sync.Mutex{} //Mutex to lock common client variable
var wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown
var start time.Time

func main() {

    debug.SetGCPercent(5) //Set garbage collection parameter

    logging.LogToFile("logs/Connection"+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"))

    cp_host, cp_port, tsinfo_file := parseCommandline(os.Args) //Parse CP hostname, common name & port, and TS information file path

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

    for{

        //Initialize global variables
        initValues()

        //Listen to the TCP port
        var err error
        ln, err = net.Listen("tcp", cp_host+":"+cp_port)
        checkError(err)

        logging.LogToFile("logs/"+cp_cname+time.Now().Local().Format("2006-01-02")+"_"+time.Now().Local().Format("15:04:05"))
        logging.Info.Println("PSC is a free, open-source software, available for download at https://github.com/AkshayaMani/PSC")
        logging.Info.Println("PSC uses https://github.com/postfix/goControlTor library to connect to Tor control port")
        logging.Info.Println("Started Computation Party")

        //Channel to handle simultaneous DP connections
        dpconn := make(chan net.Conn)

        //Channel to handle simultaneous CP connections
        cpconn := make(chan net.Conn)

        wg.Add(1) //Increment WaitGroup counter

        go acceptConnections() //Accept connections

        loop:

        for{

            select {

                case conn := <- clients:

                    //Parse Common Name
                    com_name := parseCommonName(conn)

                    if contains(dp_cnames, com_name) {//If data received from DP

                        wg.Add(1) //Increment WaitGroup counter

                        //Handle DPs in separate channels
                        go handleDPs(dpconn)

                        //Add DPconnection to channel
                        dpconn <- conn

                    } else if contains(cp_cnames, com_name) {//If data received from CP

                        wg.Add(1) //Increment WaitGroup counter

                        //Handle CPs in separate channels
                        go handleCPs(cpconn, com_name)

                        //Add CPconnection to channel
                        cpconn <- conn

                    } else if ts_cname == com_name {//If data received from TS

                        //Receive Data
                        buf := receiveData(conn)

                        conn.Close() //Close connection

                        if ts_config_flag == true { //If TS configuration flag set

                            start = time.Now()

                            ts_config_flag = false //Set configuration flag to false

                            config := new(TSmsg.Config) //TS configuration
                            proto.Unmarshal(buf, config) //Parse TS configuration

                            assignConfig(config) //Assign configuration

                            logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                            sendTSSignal(ts_s_no+step_no) //Send signal to TS

                            step_no = 1 //TS step no.

                        } else { //If TS configuration flag is false

                            sig := new(TSmsg.Signal) //TS signal
                            proto.Unmarshal(buf, sig) //Parse TS signal

                            if *sig.Fflag == true { //If finish flag set

                                logging.Info.Println("Shutting down ", cp_cname)
                                shutdownCP() //Shutdown CP gracefully

                            } else { //Finish flag not set

                                mutex.Lock() //Lock mutex

                                if *sig.SNo == int32(ts_s_no+step_no) && cp_bcast == cp_no { //Check TS step no. a$

                                    broadcastCPData() //Broadcast CP data

                                } else { //Wrong signal from TS

                                    logging.Error.Println("Wrong signal from TS")

                                    f_flag = true //Set finish flag

                                    sendTSSignal(ts_s_no+step_no) //Send finish signal to TS
                                }

                                mutex.Unlock() //Unlock mutex
                            }
                        }

                    } else { //If not CPs, DPs or TS

                        conn.Close() //Close connection
                    }

                case <-finish:

                    wg.Wait()

                    if step_no == 11 { //Finish

                        //Finishing measurement
                        logging.Info.Println("Finished measurement")

                        logging.Info.Println("Total measurement time", time.Since(start))

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

    sig.Fflag = proto.Bool(f_flag) //Set finish flag

    //Set TS session no.
    sig.SNo = proto.Int32(int32(sno))

    //Convert to Bytes
    sigb, _ := proto.Marshal(sig)

    //Send signal to TS
    sendDataToDest(sigb, ts_cname, ts_addr)
}

//Input: DP socket channel
//Function: Handle DP connections
func handleDPs(dpconn chan net.Conn) {

    defer wg.Done() //Decrement counter when goroutine completes

    //Wait for next DP connection to come off queue.
    conn := <-dpconn

    //Receive Data
    buf := receiveData(conn)

    conn.Close() //Close connection

    //Parse DP Response
    resp := new(DPres.Response)
    proto.Unmarshal(buf, resp)

    mutex.Lock() //Lock mutex

    if f_flag == false { //Finish flag not set

        if uint32(*resp.TSsno) == ts_s_no + step_no { //If step no. 1

            //Convert bytes to key
            for i := int64(0); i < b; i++ {

                tmp := suite.Scalar().SetBytes(resp.M[i])
                k_j[i] = suite.Scalar().Add(k_j[i], tmp) //Add key share
            }

        } else if uint32(*resp.TSsno) == ts_s_no + step_no - 3 {

            //Convert bytes to masked data
            for i := int64(0); i < b; i++ {

                tmp := suite.Scalar().SetBytes(resp.M[i])
                c_j[i] = suite.Scalar().Add(c_j[i], tmp) //Add masked data share
            }

        } else { //DP session no. not verified

            logging.Error.Println("DP session no. not verified")

            f_flag = true //Set finish flag

            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

            return
        }

        //Increment the number of DPs responded
        no_dp_res = no_dp_res + 1

        //If all DPs have Responded
        if no_dp_res == no_DPs {

            if step_no == 6 { //Masked data sent by all DPs

                //Add and Compute Share for Each Counter
                for i := int64(0); i < b; i++ {

                    c_j[i] = suite.Scalar().Sub(c_j[i], k_j[i]) //Subtract Key Share from masked data share
                }
            }

            logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
            sendTSSignal(ts_s_no+step_no) //Send signal to TS

            step_no += 1 //Increment step no.

            no_dp_res = 0 //Set no. of DPs responded to zero
        }
    }

    mutex.Unlock() //Unlock mutex
}

//Input: CP socket channel, CP common name
//Function: Handle CP connections
func handleCPs(cpconn chan net.Conn, com_name string) {

    defer wg.Done() //Decrement counter when goroutine completes

    //Wait for next CP connection to come off queue.
    conn := <-cpconn

    //Receive Data
    buf := receiveData(conn)

    conn.Close() //Close connection

    mutex.Lock() //Lock mutex

    if f_flag == false { //Finish flag not set

        if cp_session_flag == true { //If CP session flag set

            //Parse CP Response
            cp_resp := new(CPres.Response)
            proto.Unmarshal(buf, cp_resp)

            //If Step No. is 2
            if step_no == 2 {

                cp_s_no = binary.BigEndian.Uint32(cp_resp.R[0]) //Set Session No.

                logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                sendTSSignal(ts_s_no+step_no) //Send signal to TS

                cp_bcast = 0 //Set CP0 as Broadcasting CP

                step_no += 1 //Increment step no.

            } else if step_no == 3 { //If Step No. is 3

                tmp := bytes.NewReader(cp_resp.R[0]) //Temporary
                schnorr_pub := suite.Point() //CP Schnorr public key
                schnorr_pub.UnmarshalFrom(tmp) //Parse CP Schnorr public key

                //Verify Proof
                rep := proof.Rep("X", "x", "B")
                public := map[string]kyber.Point{"B": suite.Point().Base(), "X": schnorr_pub}
                verifier := rep.Verifier(suite, public)
                err := proof.HashVerify(suite, strconv.Itoa(int(cp_s_no+step_no-2)), verifier, cp_resp.Proof[0])

                //If Error in Verifying
                if err != nil {

                    logging.Error.Println("CP Schnorr public key proof not verified \n", err)

                    f_flag = true //Set finish flag

                    sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                    return
                }

                schnorrpub := new(Schnorrkey.Pub) //CP Schnorr public key

                //Convert to bytes
                var tb bytes.Buffer //Temporary buffer
                _,_ = schnorr_pub.MarshalTo(&tb)
                schnorrpub.Y = tb.Bytes()

                //Write to file
                out, _ := proto.Marshal(schnorrpub)
                ioutil.WriteFile("schnorr/public/" + com_name + ".pub", out, 0644)

                no_cp_res += 1 //Increment no. of CP public keys received

                logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                sendTSSignal(ts_s_no+step_no) //Send signal to TS

                //If All CP public keys received
                if no_cp_res == no_CPs - 1 {

                    cp_session_flag = false //Set CP session flag to false

                    no_cp_res = 0 //Set No. of CPs broadcasted to 0
                }

                //If last CP broadcasted
                if cp_bcast == no_CPs - 1 {

                    cp_bcast = 0 //Set CP0 as Broadcasting CP

                    step_no += 1 //Increment step no.

                } else {

                    cp_bcast += 1 //Set Broadcasting CP as next CP
                }
            }

        } else {

            //Verify Sign
            l, f := verifyCPSign(suite, com_name, buf)

            //Step No. in Message
            t := binary.BigEndian.Uint32(buf[1:5])

            //If Step No. and Signature Verified
            if t == cp_s_no+step_no-2 && f == true {

                //If Broadcast Flag Set
                if uint8(buf[0]) == 1 {

                    if no_cp_res != 0 { //If not the 1st broadcasted message

                        //Compare Signatures
                        if bytes.Compare(buf[9:9+l], b_j[no_cp_res - 1]) != 0 { //If re-broadcast data doesn't match

                            logging.Error.Println("Re-broadcast data does not match")

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }
                    }

	            b_j[no_cp_res] = buf[9:9+l] //Store Signed Message
                    //Store response
                    cp_res_byte = buf[9+l:]

                    logging.Info.Println("Rebroadcasting msg sent by CP", int(cp_bcast))
                    sendDataN_1(cp_s_no+step_no-2, int(cp_bcast), b_j[no_cp_res]) //Re-Broadcasting

                } else if uint8(buf[0]) == 0 { //If Broadcast Flag not Set

                    if no_cp_res != 0 { //If not the 1st broadcasted message

                        //Compare Signatures
                        if bytes.Compare(buf[9+l:], b_j[no_cp_res - 1]) != 0 { //If re-broadcast data doesn't match

                            logging.Error.Println("Re-broadcast data does not match")

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }
                    }

                    b_j[no_cp_res] = buf[9+l:] //Store Signed Message
                }

                no_cp_res += 1 //Increment No. of CP Responses

            } else if f != true { //If CP Schnorr signature not verified

                logging.Error.Println("CP Schnorr signature not verified", step_no)

                f_flag = true //Set finish flag

                sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                return
            }

            //If All CPs have finished Broadcasting/Re-Broadcasting
            if no_cp_res == no_CPs - 1 {

                //Parse CP Response
                cp_resp := new(CPres.Response)
                proto.Unmarshal(cp_res_byte, cp_resp)

                if step_no == 4 { //If Step No. is 4

                    tmp := bytes.NewReader(cp_resp.R[0]) //Temporary
                    y[cp_bcast] = suite.Point()
                    y[cp_bcast].UnmarshalFrom(tmp)

                    //Verify Proof
                    rep := proof.Rep("X", "x", "B")
                    public := map[string]kyber.Point{"B": suite.Point().Base(), "X": y[cp_bcast]}
                    verifier := rep.Verifier(suite, public)
                    err := proof.HashVerify(suite, strconv.Itoa(int(cp_s_no+step_no-2)), verifier, cp_resp.Proof[0])

                    //If Error in Verifying
                    if err != nil {

                        logging.Error.Println("CP ElGamal public key proof not verified \n", err)

                        f_flag = true //Set finish flag

                        sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                        return
                    }

                    //Multiply to create Compound Public Key
                    Y.Add(Y, y[cp_bcast])

                } else if step_no == 5 { //If Step No. 5

                    //Convert Bytes to Data
                    for i := int64(0); i < n; i++ {

                        tmp := bytes.NewReader(cp_resp.R[2*i]) //Temporary
                        nr_o[i][0] = suite.Point()
                        nr_o[i][0].UnmarshalFrom(tmp) //Assign Shuffled Noise ElGamal Blinding Factors

                        tmp1 := bytes.NewReader(cp_resp.R[(2*i)+1]) //Temporary
                        nr_o[i][1] = suite.Point()
                        nr_o[i][1].UnmarshalFrom(tmp1) //Assign Shuffled Noise ElGamal Blinding Factors

                        tmp2 := bytes.NewReader(cp_resp.C[2*i]) //Temporary
                        nc_o[i][0] = suite.Point()
                        nc_o[i][0].UnmarshalFrom(tmp2) //Assign Shuffled Noise ElGamal Ciphers

                        tmp3 := bytes.NewReader(cp_resp.C[(2*i)+1]) //Temporary
                        nc_o[i][1] = suite.Point()
                        nc_o[i][1].UnmarshalFrom(tmp3) //Assign Shuffled Noise ElGamal Ciphers

                        //Verify Proof
                        verifier := shuffle.BiffleVerifier(suite, nil, Y, nr[i], nc[i], nr_o[i], nc_o[i])
                        err := proof.HashVerify(suite, strconv.Itoa(int(cp_s_no+step_no-2))+strconv.Itoa(int(i)), verifier, cp_resp.Proof[i])

                        //If Error in Verifying
                        if err != nil {

                            logging.Error.Println("Noise generation proof", i, "not verified \n", err)

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }
                    }

                    //Iterate over all Noise Counters
                    for i := int64(0); i < n; i++ {

                        //Swap Current Output as Input
                        nr[i][0] = suite.Point().Set(nr_o[i][0])
                        nr[i][1] = suite.Point().Set(nr_o[i][1])
                        nc[i][0] = suite.Point().Set(nc_o[i][0])
                        nc[i][1] = suite.Point().Set(nc_o[i][1])
                    }

                    //If Last CP has Broadcasted
                    if cp_bcast == no_CPs - 1 {

                        //Iterate Over all Noise Counters
                        for i := b; i < b+n; i++ {

                            //Select 1st Coin as Noise
                            R[i] = suite.Point().Set(nr[i-b][0])
                            C[i] = suite.Point().Set(nc[i-b][0])
                        }

                        //Free noise variables
                        nr = nil //Noise ElGamal blinding factors
                        nc = nil //Noise ElGamal ciphers
                        nr_o = nil //Shuffled noise elGamal blinding factors
                        nc_o = nil //Shuffled noise ElGamal ciphers
                    }

                } else if step_no == 7 { //If Step No. 7

                    //Convert Bytes to Data
                    for i := int64(0); i < b; i++ {

                        tmp := bytes.NewReader(cp_resp.R[i]) //Temporary
                        tp := suite.Point() //Temporary
                        tp.UnmarshalFrom(tmp)
                        R[i].Add(R[i], tp) //Multiply ElGamal Blinding Factors

                        //Verify Proof
                        rep := proof.Rep("X", "x", "B")
                        public := map[string]kyber.Point{"B": suite.Point().Base(), "X": tp}
                        verifier := rep.Verifier(suite, public)
                        err := proof.HashVerify(suite, strconv.Itoa(int(cp_s_no+step_no-2))+strconv.Itoa(int(i)), verifier, cp_resp.Proof[i])

                        //If Error in Verifying
                        if err != nil {

                            logging.Error.Println("ElGamal ciphertext computation proof", i, "not verified \n", err)

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }

                        tmp1 := bytes.NewReader(cp_resp.C[i])
                        tp = suite.Point()
                        tp.UnmarshalFrom(tmp1)
                        C[i].Add(C[i], tp) //Multiply ElGamal Ciphers
                    }

                } else if step_no == 8 { //If Step No. 8

                    R_O = make([]kyber.Point, b+n) //Shuffled ElGamal Blinding Factors
                    C_O = make([]kyber.Point, b+n) //Shuffled ElGamal Ciphers

                    //Convert Bytes to Data
                    for i := int64(0); i < b+n; i++ {

                        tmp := bytes.NewReader(cp_resp.R[i]) //Temporary
                        R_O[i] = suite.Point()
                        R_O[i].UnmarshalFrom(tmp) //Assign Shuffled ElGamal Blinding Factors

                        tmp1 := bytes.NewReader(cp_resp.C[i]) //Temporary
                        C_O[i] = suite.Point()
                        C_O[i].UnmarshalFrom(tmp1) //Assign Shuffled ElGamal Ciphers
                    }

                    //Verify Proof
                    verifier := shuffle.Verifier(suite, nil, Y, R, C, R_O, C_O)
                    err := proof.HashVerify(suite, strconv.Itoa(int(cp_s_no+step_no-2)), verifier, cp_resp.Proof[0][:])

       	            //If Error in Verifying
                    if err != nil {

                        logging.Error.Println("Verifiable shuffle proof not verified \n", err)

                        f_flag = true //Set finish flag

                        sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                        return
                    }

                    //Iterate over all Counters
                    for i := int64(0); i < b+n; i++ {

                        //Swap Current Output as Input
                        R[i] = suite.Point().Set(R_O[i])
                        C[i] = suite.Point().Set(C_O[i])
                    }

                    //Free output variables
                    R_O = nil //Shuffled ElGamal Blinding Factors
                    C_O = nil  //Shuffled ElGamal Ciphers

                } else if step_no == 9 { //If Step No. 9

                    prf := make([]*ReRandomizeProof, b+n)
                    tmp := bytes.NewReader(cp_resp.Proof[0])
                    suite.Read(tmp, prf)

                    R_O = make([]kyber.Point, b+n) //Shuffled ElGamal Blinding Factors
                    C_O = make([]kyber.Point, b+n) //Shuffled ElGamal Ciphers

                    //Convert Bytes to Data
                    for i := int64(0); i < b+n; i++ {

                        tmp1 := bytes.NewReader(cp_resp.R[i]) //Temporary
                        R_O[i] = suite.Point()
                        R_O[i].UnmarshalFrom(tmp1) //Assign Re-Randomized ElGamal Blinding Factors

                        tmp2 := bytes.NewReader(cp_resp.C[i]) //Temporary
                        C_O[i] = suite.Point()
                        C_O[i].UnmarshalFrom(tmp2) //Assign Re-Randomized ElGamal Ciphers

                        //Verify Proof
                        err := prf[i].Verify(suite, R[i], C[i], nil, Y, R_O[i], C_O[i])

       	               	//If Error in Verifying
                        if err != nil {

                            logging.Error.Println("Re-randomization re-encryption proof", i, "not verified \n", err)

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }

                        //If Re-randomization re-encryption output is generator
                        if R_O[i].Equal(suite.Point().Base()) == true || C_O[i].Equal(suite.Point().Base()) == true {

                            logging.Error.Println("Re-randomization re-encryption output is generator")

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }
                    }

                    //Iterate over all Counters
                    for i := int64(0); i < b+n; i++ {

                        //Swap Current Output as Input
                        R[i] = suite.Point().Set(R_O[i])
                        C[i] = suite.Point().Set(C_O[i])
                    }

                    //Free output variables
                    R_O = nil //Shuffled ElGamal Blinding Factors
                    C_O = nil  //Shuffled ElGamal Ciphers

                } else if step_no == 10 { //If Step No. 10

                    prf := make([]*dleq.Proof, b+n)
                    tmp := bytes.NewReader(cp_resp.Proof[0])
                    suite.Read(tmp, prf)

                    R_O = make([]kyber.Point, b+n) //Shuffled ElGamal Blinding Factors
                    C_O = make([]kyber.Point, b+n) //Shuffled ElGamal Ciphers

                    //Convert Bytes to Data
                    for i := int64(0); i < b+n; i++ {

                        tmp1 := bytes.NewReader(cp_resp.R[i]) //Temporary
                        R_O[i] = suite.Point()
                        R_O[i].UnmarshalFrom(tmp1) //Assign Re-Randomized ElGamal Blinding Factors

                        tmp2 := bytes.NewReader(cp_resp.C[i])  //Temporary
                        C_O[i] = suite.Point()
                        C_O[i].UnmarshalFrom(tmp2) //Assign Re-Randomized ElGamal Ciphers

                        //Verify Proof
                        err := prf[i].Verify(suite, nil, R[i], y[cp_bcast], suite.Point().Sub(C[i], C_O[i]))

                        //If Error in Verifying
                        if err != nil {

                            logging.Error.Println("Decryption proof", i, "not verified \n", err)

                            f_flag = true //Set finish flag

                            sendTSSignal(ts_s_no+step_no) //Send finish signal to TS

                            return
                        }
                    }

                    //Iterate over all Counters
                    for i := int64(0); i < b+n; i++ {

                        //Swap Current Output as Input
                        C[i] = suite.Point().Set(C_O[i])
                    }

                    //Free unused variables
                    R_O = nil //Shuffled ElGamal Blinding Factors
                    C_O = nil  //Shuffled ElGamal Ciphers
                }

                cp_resp = nil
                buf = nil

                //If Last CP
                if cp_bcast == no_CPs - 1 {

                    if step_no != 10 {

                        logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                        sendTSSignal(ts_s_no+step_no) //Send signal to TS

                    } else {

                        var agg int64 //Aggregate
                        agg = 0

                        //Iterate over all Counters
                        for i := int64(0); i < b+n; i++ {

                            //If not g^0
                            if e_f := C[i].Equal(suite.Point().Null()); e_f == false {

                                //Add 1 to Aggregate
                                agg += 1
                            }
                        }

                        agg -= int64(n/2)

                        logging.Info.Println("Aggregate =", agg)

                        //Assign aggregated result
                        result := new(TSmsg.Result)
                        result.Agg = proto.String(strconv.Itoa(int(agg)))

                        //Convert to Bytes
                        resultb, _ := proto.Marshal(result)

                        //Send signal to TS
                        sendDataToDest(resultb, ts_cname, ts_addr)
                    }

                    cp_bcast = 0 //Set CP0 as Broadcasting CP

                    step_no += 1 //Increment step no.

                } else {

                    logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                    sendTSSignal(ts_s_no+step_no) //Send signal to TS

                    cp_bcast += 1 //Set Broadcasting CP as next CP
                }

                no_cp_res = 0 //Set No. of CPs Broadcasted/Re-Broadcasted to 0
            }
        }
    }

    mutex.Unlock() //Unlock mutex
}

//Function: Broadcasts data of broadcasting CP to other CPs
func broadcastCPData() {

    resp := new(CPres.Response)

    if f_flag == false { //Finish flag not set

        if step_no == 2 { //If Step Number is 2

            seed := rand.NewSource(time.Now().UnixNano())
            rnd := rand.New(seed)

            //Set CP session no.
            if cp_no == 0 {

                for cp_s_no == 0 {

                    cp_s_no = uint32(rnd.Int31()) //Set CP session no. to non-zero random number
                }
	    }

            //Set CP Response to session no.
            resp.R = make([][]byte, 1)

            resp.R[0] = make([]byte, 4) //Session No. in Bytes
            binary.BigEndian.PutUint32(resp.R[0], uint32(cp_s_no)) //Convert to Bytes

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast session no. to other CPs
            for i := int32(0); i < no_CPs; i++ {

                if i != cp_no {

                    sendDataToDest(resp1, cp_cnames[i], cp_addr[i])
                }
            }

        } else if step_no == 3 { //If Step Number is 3

            //Generate Schnorr public key pair
            schnorr_priv := suite.Scalar().Pick(pseudorand) //CP Schnorr private key
            schnorr_pub := suite.Point().Mul(schnorr_priv, nil) //CP Schnorr public key

            //Schnorr key pair in bytes
            priv_bytes := new(Schnorrkey.Priv)
            pub_bytes := new(Schnorrkey.Pub)

            //Convert to private key to bytes
            var tb bytes.Buffer //Temporary buffer
            _,_ = schnorr_priv.MarshalTo(&tb)
            priv_bytes.X = tb.Bytes()

            //Write Schnorr private key to file
            out, _ := proto.Marshal(priv_bytes)
            ioutil.WriteFile("schnorr/private/" + cp_cname + ".priv", out, 0644)

            //Convert to public key to bytes
            tb.Reset() //Buffer Reset
            _,_ = schnorr_pub.MarshalTo(&tb)
            pub_bytes.Y = tb.Bytes()

            //Write Schnorr public key to file
            out, _ = proto.Marshal(pub_bytes)
            ioutil.WriteFile("schnorr/public/" + cp_cname + ".pub", out, 0644)

            //Set CP response to Schnorr public key
            resp.R = make([][]byte, 1)
            resp.Proof = make([][]byte, 1)
            resp.R[0] = tb.Bytes()

            //Create Proof
            rep := proof.Rep("X", "x", "B")
            secret := map[string]kyber.Scalar{"x": schnorr_priv}
            public := map[string]kyber.Point{"B": suite.Point().Base(), "X": schnorr_pub}
            prover := rep.Prover(suite, secret, public, nil)
            resp.Proof[0], _ = proof.HashProve(suite, strconv.Itoa(int(cp_s_no+step_no-2)), prover)

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast public key to other CPs
            for i := int32(0); i < no_CPs; i++ {

                if i != cp_no {

                    sendDataToDest(resp1, cp_cnames[i], cp_addr[i])
                }
            }

        } else if step_no == 4 { //If Step Number is 4

            //Set CP response to ElGamal public key
            resp.R = make([][]byte, 1)
            resp.Proof = make([][]byte, 1)
            resp.R[0] = pub.Y

            //Create Proof
            rep := proof.Rep("X", "x", "B")
            secret := map[string]kyber.Scalar{"x": x}
            public := map[string]kyber.Point{"B": suite.Point().Base(), "X": y[cp_no]}
            prover := rep.Prover(suite, secret, public, nil)
            resp.Proof[0], _ = proof.HashProve(suite, strconv.Itoa(int(cp_s_no+step_no-2)), prover)

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast Public Key
            broadcastData(cp_s_no+step_no-2, resp1)

        } else if step_no == 5 { //If Step Number is 5

            resp.R = make([][]byte, 2 * n)
            resp.C = make([][]byte, 2 * n)
            resp.Proof = make([][]byte, n)

            xbar, ybar, prover := par.MapElgamalCiphersChunked(shuffleNoise, nr, nc, Y, int(n)) //Parallel Shuffle n Noise Coins

            //Iterate over all Noise Counters
            for i := int64(0); i < n; i++ {

                //Change its input as Shuffled Output for Next Verification
                nr[i][0] = suite.Point().Set(xbar[i][0])
                nr[i][1] = suite.Point().Set(xbar[i][1])
                nc[i][0] = suite.Point().Set(ybar[i][0])
                nc[i][1] = suite.Point().Set(ybar[i][1])

                //Set CP Response to Broadcast Noise
                {
                    var tb bytes.Buffer //Temporary buffer
                    xbar[i][0].MarshalTo(&tb)
                    resp.R[2*i] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    xbar[i][1].MarshalTo(&tb)
                    resp.R[(2*i)+1] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    ybar[i][0].MarshalTo(&tb)
                    resp.C[2*i] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    ybar[i][1].MarshalTo(&tb)
                    resp.C[(2*i)+1] = tb.Bytes() //Convert to bytes
                }

                resp.Proof[i], _ = proof.HashProve(suite, strconv.Itoa(int(cp_s_no+step_no-2))+strconv.Itoa(int(i)), prover[i])
            }

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast Shuffled Noise
            broadcastData(cp_s_no+step_no-2, resp1)

            //If Last CP has Broadcasted
            if cp_bcast == no_CPs - 1 {

                //Iterate Over all Noise Counters
                for i := b; i < b+n; i++ {

                    //Select 1st Coin as Noise
                    R[i] = suite.Point().Set(nr[i-b][0])
                    C[i] = suite.Point().Set(nc[i-b][0])
                }

                //Free noise variables
                nr = nil //Noise ElGamal blinding factors
                nc = nil //Noise ElGamal ciphers
            }

        } else if step_no == 7 { //If Step Number is 7

            tmp := suite.Scalar() //temporary
            resp.R = make([][]byte, b)
            resp.C = make([][]byte, b)
            resp.Proof = make([][]byte, b)

            r := make([]kyber.Point, b) //List of ElGamal Blinding Factors
            c := make([]kyber.Point, b) //List of ElGamal Ciphers

            //Iterate over all Counters
            for i := int64(0); i < b; i++ {

                //Set CP Response to Broadcast ElGamal Ciphertext of Message Shares
                {
                    var tb bytes.Buffer //Temporary buffer
                    tmp.Pick(pseudorand)
                    r[i] = suite.Point().Mul(tmp, nil)
                    R[i].Add(R[i], r[i]) //Multiply ElGamal Bllinding Factors
                    r[i].MarshalTo(&tb)
                    resp.R[i] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    c[i] = suite.Point().Mul(tmp, Y)
                    c[i].Add(c[i], suite.Point().Mul(c_j[i], nil))
                    C[i].Add(C[i], c[i]) //Multiply ElGamal Ciphers
                    c[i].MarshalTo(&tb)
                    resp.C[i] = tb.Bytes() //Convert to bytes
                }

                //Create Proof
                rep := proof.Rep("X", "x", "B")
                secret := map[string]kyber.Scalar{"x": tmp}
                public := map[string]kyber.Point{"B": suite.Point().Base(), "X": r[i]}
                prover := rep.Prover(suite, secret, public, nil)
                resp.Proof[i], _ = proof.HashProve(suite, strconv.Itoa(int(cp_s_no+step_no-2))+strconv.Itoa(int(i)), prover)
            }

            //Free cipher shares
            c_j = nil

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast ElGamal Ciphertexts
            broadcastData(cp_s_no+step_no-2, resp1)

        } else if step_no == 8 { //If Step Number is 8

            Xbar, Ybar, prover := shuffle.Shuffle(suite, nil, Y, R, C, pseudorand) //Shuffle Counters

            //Assign to Output Vector and Convert to Bytes
            resp.R = make([][]byte, b+n)
            resp.C = make([][]byte, b+n)
            resp.Proof = make([][]byte, 1)

            resp.Proof[0], _ = proof.HashProve(suite, strconv.Itoa(int(cp_s_no+step_no-2)), prover)

            //Iterate over all Counters
            for i := int64(0); i < b+n; i++ {

                //Change its input as Shuffled Output for Next Verification
                R[i] = suite.Point().Set(Xbar[i])
                C[i] = suite.Point().Set(Ybar[i])

                //Set CP Response to shuffled ciphertexts
                {
                    var tb bytes.Buffer //Temporary buffer
                    Xbar[i].MarshalTo(&tb)
                    resp.R[i] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    Ybar[i].MarshalTo(&tb)
                    resp.C[i] = tb.Bytes() //Convert to bytes
                }
            }

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast Shuffled Counters
            broadcastData(cp_s_no+step_no-2, resp1)

        } else if step_no == 9 { //If Step Number is 9

            s := make([]kyber.Scalar, b+n) //Randomness for Re-Encryption
            q := make([]kyber.Scalar, b+n) //Randomness for Re-Randomization

            //Iterate over all Counters
            for i := int64(0); i < b+n; i++ {

                s[i] = suite.Scalar().Pick(pseudorand) //Pick a Random Scalar
                q[i] = suite.Scalar().Zero()

                for q[i].Equal(suite.Scalar().Zero()) == true {
                    q[i] = suite.Scalar().Pick(pseudorand) //Set Exponent to Non-Zero Random Scalar
                }
            }

            prf, Xbar, Ybar, _ := rerandomizeProofBatch(suite, R, C, nil, Y, s, q) //Re-Randomization

            //Assign to Output Vector and Convert to Bytes
            resp.R = make([][]byte, b+n)
            resp.C = make([][]byte, b+n)
            resp.Proof = make([][]byte, 1)

            //Iterate over all Counters
            for i := int64(0); i < b+n; i++ {

                //Change its input as rerandomized Output for Next Verification
                R[i] = suite.Point().Set(Xbar[i])
                C[i] = suite.Point().Set(Ybar[i])

                //Set CP Response to rerandomized ciphertexts
                {
                    var tb bytes.Buffer //Temporary buffer
                    Xbar[i].MarshalTo(&tb)
                    resp.R[i] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    Ybar[i].MarshalTo(&tb)
                    resp.C[i] = tb.Bytes() //Convert to bytes
                }
            }

            //Convert Proof to Bytes
            var tb bytes.Buffer //Temporary buffer
            suite.Write(&tb, prf)
            resp.Proof[0] = tb.Bytes() //Convert to bytes

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast Re-randomized Counters
            broadcastData(cp_s_no+step_no-2, resp1)

        }  else if step_no == 10 { //If Step Number is 10

            u := make([]kyber.Scalar, b+n) //Secret for Decryption
            p := make([]kyber.Point, b+n) //Base Vector

            //Iterate over all Counters
            for i := int64(0); i < b+n; i++ {

                u[i] = suite.Scalar().Set(x) //Set Secret for Decryption
                p[i] = suite.Point().Base()
            }

            prf, _, Ybar, _ := dleq.NewDLEQProofBatch(suite, p, R, u) //Decryption

            //Assign to Output Vector and Convert to Bytes
            resp.R = make([][]byte, b+n)
            resp.C = make([][]byte, b+n)
            resp.Proof = make([][]byte, 1)

            //Iterate over all Counters
            for i := int64(0); i < b+n; i++ {

                //Change its input as Decrypted Output for Next Verification
                C[i].Sub(C[i], Ybar[i])

                //Set CP Response to decrypted bins
                {
                    var tb bytes.Buffer //Temporary buffer
                    R[i].MarshalTo(&tb)
                    resp.R[i] = tb.Bytes() //Convert to bytes
                }

                {
                    var tb bytes.Buffer //Temporary buffer
                    C[i].MarshalTo(&tb)
                    resp.C[i] = tb.Bytes() //Convert to bytes
                }
            }

            //Convert Proof to Bytes
            var tb bytes.Buffer //Temporary buffer
            suite.Write(&tb, prf)
            resp.Proof[0] = tb.Bytes() //Convert to bytes

            //Convert to Bytes
            resp1, _ := proto.Marshal(resp)

            //Broadcast Decrypted Counters
            broadcastData(cp_s_no+step_no-2, resp1)
        }

        //If Step No. 2
        if step_no == 2 {

            logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
            sendTSSignal(ts_s_no+step_no) //Send signal to TS

            cp_bcast = 0 //Set CP0 as Broadcasting CP

            step_no += 1 //Increment step no.

        } else {

            //If Last CP
            if cp_bcast == no_CPs - 1 {

                if step_no != 10 {

                    logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                    sendTSSignal(ts_s_no+step_no) //Send signal to TS

                } else {

                    var agg int64 //Aggregate
                    agg = 0

                    //Iterate over all Counters
                    for i := int64(0); i < b+n; i++ {

                        //If not g^0
                        if e_f := C[i].Equal(suite.Point().Null()); e_f == false {

                            //Add 1 to Aggregate
                            agg += 1
                        }
                    }

                    agg -= int64(n/2)

                    logging.Info.Println("Aggregate =", agg)

                    //Assign aggregated result
                    result := new(TSmsg.Result)
                    result.Agg = proto.String(strconv.Itoa(int(agg)))

                    //Convert to Bytes
                    resultb, _ := proto.Marshal(result)

                    //Send signal to TS
                    sendDataToDest(resultb, ts_cname, ts_addr)
                }

                cp_bcast = 0 //Set CP0 as Broadcasting CP

                step_no += 1 //Increment step no.

            } else {

                logging.Info.Println("Sending TS signal. Bcast CP", cp_bcast, "Step No.", step_no)
                sendTSSignal(ts_s_no+step_no) //Send signal to TS

                cp_bcast += 1 //Set Broadcasting CP as next CP
            }
        }
    }
}

//Input: Command-line Arguments
//Output: CP port number, TS information file path
//Function: Parse Command-line Arguments
func parseCommandline(arg []string) (string, string, string) {

    var cp_host string //CP hostname
    var tsinfo_file string //TS information file path
    var cp_port string //CP port no.
    var e_flag = false //Exit flag

    flag.StringVar(&cp_host, "h", "", "CP hostname to which to bind")
    flag.StringVar(&cp_cname, "c", "", "CP common name (required)")
    flag.StringVar(&cp_port, "p", "", "CP port number (required)")
    flag.StringVar(&tsinfo_file, "t", "ts.info", "TS information file path")
    flag.Parse()

    if cp_cname == "" || cp_port == "" {

        logging.Error.Println("Argument required:")
        e_flag = true //Set exit flag

        if cp_port == "" {

            logging.Error.Println("   -p string")
            logging.Error.Println("      CP port number (Required)")
        }

        if cp_cname == "" {

            logging.Error.Println("   -c string")
            logging.Error.Println("      CP common name (Required)")
        }
    }
    if e_flag == true {//If exit flag set

        os.Exit(0) //Exit
    }

    return cp_host, cp_port, tsinfo_file
}

//Function: Initialize variables
func initValues() {

    suite = edwards25519.NewBlakeSHA256Ed25519() //Cipher suite
    pseudorand = suite.RandomStream() //For Randomness
    no_CPs = 0 //No.of CPs
    no_DPs = 0 //No. of DPs
    b = 0 //Hash table size
    n = 0 //No. of noise vectors

    cp_cnames = nil //CP common names
    dp_cnames = nil //DP common names
    cp_addr = nil //CP addresses
    dp_addr = nil //DP addresses
    cp_no = 0 //CP number
    no_dp_res = 0 //No. of DPs responded so far
    no_cp_res = 0 //No. of CPs broadcasted/re-broadcasted
    f_flag = false //Finish flag
    cp_bcast = 0 //CP Number broadcasting
    step_no = 0 //CP step no.
    cp_s_no = 0 //CP session no.
    ts_s_no = 0 //TS session no.
    ts_config_flag = true //TS configuration flag
    cp_session_flag = true //CP session flag
    ln = nil //Server listener
    finish = make(chan bool) //Channel to send finish flag
    clients = make(chan net.Conn) //Channel to handle simultaneous client connections
    x = suite.Scalar().Zero() //CP private key
    y = nil //CP ElGamal public key list
    pub = new(Schnorrkey.Pub) //CP ElGamal public key in bytes
    Y = suite.Point().Null() //Compound public key
    k_j = nil //Key share
    c_j = nil //Message share
    b_j = nil //Broadcasted message list
    nr = nil //Noise ElGamal blinding factors
    nc = nil //Noise ElGamal ciphers
    nr_o = nil //Shuffled noise elGamal blinding factors
    nc_o = nil //Shuffled noise ElGamal ciphers
    R = nil //Product of all CP ElGamal blinding factors
    C = nil //Product of all CP ElGamal ciphers
    R_O = nil //Shuffled ElGamal blinding factors
    C_O = nil //Shuffled ElGamal ciphers
    cp_res_byte = nil //CP Response
    mutex = &sync.Mutex{} //Mutex to lock common client variable
    wg = &sync.WaitGroup{} //WaitGroup to wait for all goroutines to shutdown
}

//Input: Configuration from TS
//Output: Assign configuration
func assignConfig(config *TSmsg.Config) {

    ts_s_no = uint32(*config.SNo) //TS session no.
    n = *config.Noise //No. of Noise bins

    no_CPs = *config.Ncps //No. of CPs
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

    y = make([]kyber.Point, no_CPs) //Public Key List
    k_j = make([]kyber.Scalar, b) //Key Share
    c_j = make([]kyber.Scalar, b) //Message Share
    b_j = make([][]byte, no_CPs - 1) //Broadcasted Message List
    nr = make([][2]kyber.Point, n) //Noise ElGamal Blinding Factors
    nc = make([][2]kyber.Point, n) //Noise ElGamal Ciphers
    nr_o = make([][2]kyber.Point, n) //Shuffled Noise ElGamal Blinding Factors
    nc_o = make([][2]kyber.Point, n) //Shuffled Noise ElGamal Ciphers
    R = make([]kyber.Point, b+n) //Product of all CP ElGamal Blinding Factors
    C = make([]kyber.Point, b+n) //Product of all CP ElGamal Ciphers
    R_O = make([]kyber.Point, b+n) //Shuffled ElGamal Blinding Factors
    C_O = make([]kyber.Point, b+n) //Shuffled ElGamal Ciphers

    cp_no = 0 //CP Number

    for _, cp := range cp_cnames {

        if cp_cname == cp {

            break
        }

        cp_no += 1 //Increment CP number
    }

    x = suite.Scalar().Pick(pseudorand) //CP private key
    y[cp_no] = suite.Point().Mul(x, nil) //CP ElGamal public key
    Y = Y.Mul(x, nil) //Compound Public Key

    //Convert CP ElGamal key pair to bytes
    var tb bytes.Buffer //Temporary Buffer
    y[cp_no].MarshalTo(&tb)

    pub.Y = tb.Bytes() //CP ElGamal public key in bytes

    //Iterate over the hashtable
    for j := int64(0); j < b; j++ {

        k_j[j] = suite.Scalar().Zero() //Initialize with zero
        c_j[j] = suite.Scalar().Zero() //Initialize with zero
    }

    //Iterate over the noise counters
    for j := int64(0); j < n; j++ {

        //Initialize 0 & 1 Ciphers
        nr[j][0] = suite.Point().Null() //Initialize with identity element
        nr[j][1] = suite.Point().Null() //Initialize with identity element
        nc[j][0] = suite.Point().Null() //Initialize with identity element
        nc[j][1] = suite.Point().Base() //Initialize with Base Point
    }

    //Iterate over all counters
    for j := int64(0); j < b+n; j++ {

        R[j] = suite.Point().Null() //Initialize with identity element
        C[j] = suite.Point().Null() //Initialize with identity element
    }
}

//Input: Data, Destination common name, Destination address
//Function: Send Data to Destination
func sendDataToDest(data []byte, dst_cname string, dst_addr string) {

    //Load Private Key and Certificate
    cert, err := tls.LoadX509KeyPair("certs/" + cp_cname + ".cert", "private/" + cp_cname + ".key")
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

//Input: CP common name
//Output: Socket
//Function: Accept new connections in  Socket
func acceptConnections() {

    defer wg.Done() //Decrement counter when goroutine completes

    for {

        //Create Server Socket
        cert, err1 := tls.LoadX509KeyPair("certs/"+ cp_cname +".cert", "private/" + cp_cname + ".key")
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

//Input: Step No., Data
//Function: Broadcast Data to All CPs
func broadcastData(step_no uint32, data []byte) {

    //Read Private Key from file
    in, _ := ioutil.ReadFile("schnorr/private/" + cp_cname + ".priv")
    priv := &Schnorrkey.Priv{}
    proto.Unmarshal(in, priv)

    //Convert Bytes to Private Key
    x := suite.Scalar().SetBytes(priv.X)

    //Add Header
    b_s := make([]byte, 5)
    b_s[0] = byte(1) //Set Broadcast Flag
    binary.BigEndian.PutUint32(b_s[1:], step_no) //Set Step Number

    //Sign Message
    sign_msg, _ := schnorr.Sign(suite, x, data)
    l := make([]byte, 4) //Length of Signature
    binary.BigEndian.PutUint32(l, uint32(len(sign_msg))) //Set Length of Signature
    sign_msg = append(b_s, append(l, append(sign_msg, data...)...)...) //Add header and signature length

    //Iterate over all CPs
    for i := 0; i < int(no_CPs); i++ {

        //Send to all other CPs
        if i != int(cp_no) {

            sendDataToDest(sign_msg, cp_cnames[i], cp_addr[i])
        }
    }
}

//Input: Step No., Source CP, Data
//Function: Send to All CPs but the Source
func sendDataN_1(step_no uint32, src int, data []byte) {

    //Read Private Key from file
    in, _ := ioutil.ReadFile("schnorr/private/" + cp_cname + ".priv")
    priv := &Schnorrkey.Priv{}
    proto.Unmarshal(in, priv)

    //Convert Bytes to Private Key
    x := suite.Scalar().SetBytes(priv.X)

    //Add Header
    b_s := make([]byte, 5)
    b_s[0] = byte(0) //Set Broadcast Flag to 0
    binary.BigEndian.PutUint32(b_s[1:], step_no) //Set Step Number

    //Sign Message
    sign_msg, _ := schnorr.Sign(suite, x, data)
    l := make([]byte, 4) //Length of Signature
    binary.BigEndian.PutUint32(l, uint32(len(sign_msg))) //Set Length of Signature
    sign_msg = append(b_s, append(l, append(sign_msg, data...)...)...) //Add header, step no. and signature length

    //Iterate over all CPs
    for i := 0; i < int(no_CPs); i++ {

        //Send to other n-1 CPs
        if i != int(cp_no) && i != src {

            sendDataToDest(sign_msg, cp_cnames[i], cp_addr[i])
        }
    }
}

//Input: Cipher Suite, CP that is sending, Data, Broadcast Flag
//Output: Length of Signed Message and Bool(Verified / Not)
//Function: Verrify Sign
func verifyCPSign(suite proof.Suite, src_cname string, data []byte) (uint32, bool) {

    //Read Source Public Key from file
    in, _ := ioutil.ReadFile("schnorr/public/" + src_cname + ".pub")
    buf := &Schnorrkey.Pub{}
    proto.Unmarshal(in, buf)

    y := bytes.NewReader(buf.Y) //Source public key in bytes
    src_pub := suite.Point() //Source public key
    src_pub.UnmarshalFrom(y)

    //Parse Source CP Signed Message
    ls := binary.BigEndian.Uint32(data[5:9]) //Length of Signed Message
    msg := data[9:9+ls] //Signed Message

    //Verify Signed Message
    err := schnorr.Verify(suite, src_pub, data[9+ls:], msg)

    var f bool //Flag to be returned

    if err == nil {

        f = true

    } else {

        f = false
    }

    return ls, f
}

//Input: Points, Points
//Output: Shuffled Noise
//Function: Shuffle Noise
func shuffleNoise(x, y [2]kyber.Point, Y kyber.Point) ([2]kyber.Point, [2]kyber.Point, proof.Prover) {

    suite := edwards25519.NewBlakeSHA256Ed25519() //Cipher suite
    rand := suite.RandomStream() //For Randomness

    xbar, ybar, proof := shuffle.Biffle(suite, nil, Y, x, y, rand) //Shuffle Noise Vectors

    return xbar, ybar, proof
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

//rerandomizeProof computes a new NIZK proof for the scalars s and q with
//respect to base points A and B and publicly known points G and H. It therefore randomly selects commitments t1 and t2
//and then computes the challenge c = H(q(sG+A),q(sH+B),t1A+t2G,t1B+t2H) and responses r1 = qc+t1 and r2 = sqc + t2.
//Besides the proof, this function also returns the re-randomized and re-encrypted base points A1 = q(sG+A)
//and B1 = q(sG+B).
func rerandomizeProof(suite proof.Suite, A, B, G, H kyber.Point, s, q kyber.Scalar) (proof *ReRandomizeProof, A1 kyber.Point, B1 kyber.Point, err error) {

    // Re-Encrypt Base Points
    A1 = suite.Point().Add(A, suite.Point().Mul(s, G))
    B1 = suite.Point().Add(B, suite.Point().Mul(s, H))

    // Re-Randomize Base Points
    A1.Mul(q, A1)
    B1.Mul(q, B1)

    // Commitment
    t1 := suite.Scalar().Pick(suite.RandomStream())
    t2 := suite.Scalar().Pick(suite.RandomStream())
    T1 := suite.Point().Mul(t1, A)
    T2 := suite.Point().Mul(t1, B)
    T1.Add(T1, suite.Point().Mul(t2, G))
    T2.Add(T2, suite.Point().Mul(t2, H))

    // Challenge
    h := suite.Hash()
    A1.MarshalTo(h)
    B1.MarshalTo(h)
    T1.MarshalTo(h)
    T2.MarshalTo(h)
    cb := h.Sum(nil)
    c := suite.Scalar().Pick(suite.XOF(cb))

    // Response
    r1 := suite.Scalar().Mul(q, c)
    r2 := suite.Scalar().Mul(s, r1)
    r1 = r1.Add(r1, t1)
    r2 = r2.Add(r2, t2)

    return &ReRandomizeProof{c, r1, r2, T1, T2}, A1, B1, nil
}

// ReRandomizeProofBatch computes lists of NIZK re-randomize proofs and of
// encrypted base points A1 and B1. Note that the challenge is computed over all
// input values.
func rerandomizeProofBatch(suite proof.Suite, A, B []kyber.Point, G, H kyber.Point, s, q []kyber.Scalar) (proof []*ReRandomizeProof, A1 []kyber.Point, B1 []kyber.Point, err error) {
    if len(A) != len(B) || len(q) != len(s) || len(A) != len(s) {
        return nil, nil, nil, errors.New("inputs of different lengths")
    }

    n := len(s)
    proofs := make([]*ReRandomizeProof, n)
    t1 := make([]kyber.Scalar, n)
    t2 := make([]kyber.Scalar, n)
    T1 := make([]kyber.Point, n)
    T2 := make([]kyber.Point, n)
    A1 = make([]kyber.Point, n)
    B1 = make([]kyber.Point, n)

    for i := 0; i < n; i++ {

         // Re-Encrypt Base Points
         A1[i] = suite.Point().Add(A[i], suite.Point().Mul(s[i], G))
         B1[i] = suite.Point().Add(B[i], suite.Point().Mul(s[i], H))

         // Re-Randomize Base Points
         A1[i].Mul(q[i], A1[i])
         B1[i].Mul(q[i], B1[i])

         // Commitment
         t1[i] = suite.Scalar().Pick(suite.RandomStream())
         t2[i] = suite.Scalar().Pick(suite.RandomStream())
         T1[i] = suite.Point().Mul(t1[i], A[i])
         T2[i] = suite.Point().Mul(t1[i], B[i])
         T1[i].Add(T1[i], suite.Point().Mul(t2[i], G))
         T2[i].Add(T2[i], suite.Point().Mul(t2[i], H))
    }

    // Challenge
    h := suite.Hash()
    for _, i := range A1 {
        i.MarshalTo(h)
    }
    for _, i := range B1 {
        i.MarshalTo(h)
    }
    for _, i := range T1 {
        i.MarshalTo(h)
    }
    for _, i := range T2 {
        i.MarshalTo(h)
    }
    cb := h.Sum(nil)
    c := suite.Scalar().Pick(suite.XOF(cb))

    // Responses
    for i := 0; i < n; i++ {
        r1 := suite.Scalar().Mul(q[i], c)
        r2 := suite.Scalar().Mul(s[i], r1)
        r1 = r1.Add(r1, t1[i])
        r2 = r2.Add(r2, t2[i])
        proofs[i] = &ReRandomizeProof{c, r1, r2, T1[i], T2[i]}
    }

    return proofs, A1, B1, nil
}


// Verify examines the validity of the NIZK re-randomize proof.
// The proof is valid if the following two conditions hold:
//   r1A + r2G == cA1 + T1
//   r1B + r2H == cB1 + T2
func (p *ReRandomizeProof) Verify(suite proof.Suite, A, B, G, H kyber.Point, A1, B1 kyber.Point) error {
    r1A := suite.Point().Mul(p.R1, A)
    r1B := suite.Point().Mul(p.R1, B)
    r2G := suite.Point().Mul(p.R2, G)
    r2H := suite.Point().Mul(p.R2, H)
    cA1 := suite.Point().Mul(p.C, A1)
    cB1 := suite.Point().Mul(p.C, B1)
    a := suite.Point().Add(r1A, r2G)
    b := suite.Point().Add(cA1, p.T1)
    c := suite.Point().Add(r1B, r2H)
    d := suite.Point().Add(cB1, p.T2)

    if !(a.Equal(b) && c.Equal(d)) {
        return errors.New("invalid proof")
    }

    return nil
}

//Function: Shutdown CP gracefully
func shutdownCP() {

    close(finish) //Quit

    ln.Close() //Shutdown CP gracefully
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
