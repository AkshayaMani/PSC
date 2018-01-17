/*
 * controller.go - goControlTor
 * Copyright (C) 2014  Yawning Angel, David Stainton
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package goControlTor

import (
    "bufio"
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io/ioutil"
    "net"
    "net/textproto"
    "strings"
)

const (
    cmdOK = 250
    authNonceLength = 32
    authServerHashKey = "Tor safe cookie authentication server-to-controller hash"
    authClientHashKey = "Tor safe cookie authentication controller-to-server hash"
)

type TorControl struct {

    controlConn net.Conn
    textprotoReader *textproto.Reader
    state string
    auth_methods []string
    cookie_file  string
    passwd_file string
    server_nonce []byte
    client_nonce []byte
    event string
    has_received_event bool
}

// Dial Tor control port
func (t *TorControl) Dial(network, addr, passwd_file string) error {

    var err error = nil

    t.controlConn, err = net.Dial(network, addr)

    if err != nil {

        return err
    }

    reader := bufio.NewReader(t.controlConn)
    t.textprotoReader = textproto.NewReader(reader)
    t.passwd_file = passwd_file
    t.state = "protocolinfo"
    t.has_received_event = false

    return nil
}

func (t *TorControl) ReceiveCommand() (string, error) {

    command, err := t.textprotoReader.ReadLine()

    if err != nil {

        return "", fmt.Errorf("Reading from tor control port: %s", err)
    }

    return command, nil
}

func (t *TorControl) SendCommand(command string) error {

    _, err := t.controlConn.Write([]byte(command))

    if err != nil {

        return fmt.Errorf("Writing to tor control port: %s", err)
    }

    return nil
}


func (t *TorControl) CommandParse(message string) ([]string, string, error) {

    if t.state == "protocolinfo" {

        if strings.HasPrefix(message, "250-PROTOCOLINFO") || strings.HasPrefix(message, "250-VERSION") {

            //pass

        } else if strings.HasPrefix(message, "250-AUTH") {

            suffix := strings.SplitN(message, "METHODS=", 2)
            cookie_file := strings.SplitN(suffix[1], "COOKIEFILE=", 2)

            methods := strings.Split(strings.TrimSpace(cookie_file[0]), ",") //Save the supported authentication methods
            t.auth_methods = make([]string, len(methods))
            copy(t.auth_methods[:], methods)

            if contains(t.auth_methods, "NULL") { //Warn about security

                fmt.Println("Your Tor control port has no authentication. Please configure CookieAuthentication or HashedControlPassword.")
            }

            if len(cookie_file) == 2 { //If cookie file is present

                if len(cookie_file[1]) > 2 {  //If cookie file that is not a quoted empty string

                    t.cookie_file = strings.Trim(strings.TrimSpace(cookie_file[1]), "\"") //Save the cookie file, stripping off trailing spaces and quotes

                }
            }

        } else if message == "250 OK" {

            if contains(t.auth_methods, "SAFECOOKIE") && t.cookie_file != ""  { 

                err := t.SafeCookieAuthChallenge()

                if err != nil {

                    return nil, "", err
                }

                t.state = "authchallenge"

            } else if contains(t.auth_methods, "HASHEDPASSWORD") {

                err := t.PasswordAuthenticate()

                if err != nil {

                    return nil, "", err
                }

                t.state = "authenticating"

            } else if contains(t.auth_methods, "NULL") {

                fmt.Println("Authenticating with NULL method")

                err := t.SendCommand("AUTHENTICATE\r\n")

                if err != nil {

                    return nil, "", err
                }

                t.state = "authenticating"

            } else {

                return nil, "", fmt.Errorf("Authentication methods not implemented")
            }

        } else {

            return nil, "", fmt.Errorf("%s", message)
        }

    } else if t.state == "authchallenge" && strings.HasPrefix(message, "250 AUTHCHALLENGE SERVERHASH=") {

        err := t.SafeCookieAuthenticate(message)

        if err != nil {

            fmt.Println(err)

            return nil, "", err
        }

        t.state = "authenticating"

    } else if t.state == "authenticating" && message == "250 OK" {

        t.state = "waiting"

    } else if t.state == "waiting" && strings.HasPrefix(message, "2") {

        fmt.Println("OK response")

    } else if t.state == "processing" && strings.HasPrefix(message, "650 PRIVCOUNT_") {

        parts := strings.Split(message, " ")
        t.has_received_event = true

        if parts[1] != t.event {

            fmt.Println("Unwanted event type", parts[1])

        } else if len(parts) <= 2 {

            fmt.Println("Event with no data", message)

        } else {

            return parts[1:], t.state, nil
        }
    }

    return nil, t.state, nil
}

func (t *TorControl) SafeCookieAuthChallenge() error {

    //Generating challenge nonce
    clientNonce := make([]byte, authNonceLength)

    if _, err := rand.Read(clientNonce); err != nil {

        return fmt.Errorf("Generating AUTHCHALLENGE nonce: %s", err)
    }

    //Store client nonce
    t.client_nonce = make([]byte, authNonceLength)
    copy(t.client_nonce[:], clientNonce)

    //Encode to hex string
    clientNonceStr := hex.EncodeToString(clientNonce)

    // Send the AUTHCHALLENGE.
    err := t.SendCommand(fmt.Sprintf("%s %s %s\r\n", "AUTHCHALLENGE", "SAFECOOKIE", clientNonceStr))

    if err != nil {

        return fmt.Errorf("Sending AUTHCHALLENGE request: %s", err)
    }

    return err
}

func (t *TorControl) SafeCookieAuthenticate(message string) error {

    //Reading cookie file
    cookie, err := ioutil.ReadFile(t.cookie_file)

    if err != nil {

        return fmt.Errorf("Reading cookie file: %s", err)
    }

    lineStr := strings.TrimSpace(message)
    respStr := strings.TrimPrefix(lineStr, "250 AUTHCHALLENGE ")

    if respStr == lineStr {

        return fmt.Errorf("Parsing AUTHCHALLENGE response")
    }

    splitResp := strings.SplitN(respStr, " ", 2)

    if len(splitResp) != 2 {

        return fmt.Errorf("Parsing AUTHCHALLENGE response")
    }

    hashStr := strings.TrimPrefix(splitResp[0], "SERVERHASH=")
    serverHash, err := hex.DecodeString(hashStr)

    if err != nil {

        return fmt.Errorf("Decoding AUTHCHALLENGE ServerHash: %s", err)
    }

    serverNonceStr := strings.TrimPrefix(splitResp[1], "SERVERNONCE=")
    serverNonce, err := hex.DecodeString(serverNonceStr)

    if err != nil {

        return fmt.Errorf("Decoding AUTHCHALLENGE ServerNonce: %s", err)
    }

    //Store server nonce
    t.server_nonce = make([]byte, len(serverNonce))
    copy(t.server_nonce[:], serverNonce)

    // Validate the ServerHash.
    m := hmac.New(sha256.New, []byte(authServerHashKey))
    m.Write([]byte(cookie))
    m.Write([]byte(t.client_nonce))
    m.Write([]byte(t.server_nonce))
    dervServerHash := m.Sum(nil)

    if !hmac.Equal(serverHash, dervServerHash) {

        return fmt.Errorf("AUTHCHALLENGE ServerHash is invalid")
    }

    // Calculate the ClientHash.
    m = hmac.New(sha256.New, []byte(authClientHashKey))
    m.Write([]byte(cookie))
    m.Write([]byte(t.client_nonce))
    m.Write([]byte(t.server_nonce))

    cookie = make([]byte, len(m.Sum(nil)))
    copy(cookie[:], m.Sum(nil))

    cookieStr := hex.EncodeToString(cookie)
    authReq := fmt.Sprintf("%s %s\r\n", "AUTHENTICATE", cookieStr)

    err = t.SendCommand(authReq)

    if err != nil {

        return fmt.Errorf("Safe Cookie Authentication fail: %s", err)
    }

    return nil
}

func (t *TorControl) PasswordAuthenticate() error {

    //Reading password file
    passwd, err := ioutil.ReadFile(t.passwd_file)

    if err != nil {

        return fmt.Errorf("Reading password file: %s", err)
    }

    passwdStr := string(passwd)

    authCmd := fmt.Sprintf("%s \"%s\"\r\n", "AUTHENTICATE", passwdStr)

    err = t.SendCommand(authCmd)

    if err != nil {

        return fmt.Errorf("Sending password AUTHENTICATE request: %s", err)
    }

    return err
}

func (t *TorControl) StartCollection(event string) error {

    if t.has_received_event == true {

        fmt.Println("StartCollection called multiple times without StopCollection")
        t.has_received_event = false
    }

    t.event = event //Registered Tor event

    if t.state == "waiting" {

        err := t.SendCommand("SETCONF __ReloadTorrcOnSIGHUP=0\r\n")

        if err != nil {

            return err
        }

        err = t.SendCommand("SETCONF EnablePrivCount=1\r\n")

        if err != nil {

            return err
        }

        err = t.SendCommand("SETEVENTS " + t.event + "\r\n")

        if err != nil {

            return err
        }

        t.state = "processing"

    } else {

        fmt.Println("Not enabling event")
    }

    return nil
}

func (t *TorControl) StopCollection() error {

    t.has_received_event = false

    t.event = ""

    err := t.SendCommand("SETEVENTS\r\n")

    if err != nil {

        return err
    }

    err = t.SendCommand("SETCONF EnablePrivCount=0\r\n")

    if err != nil {

        return err
    }

    err = t.SendCommand("SETCONF __ReloadTorrcOnSIGHUP=1\r\n")

    if err != nil {

        return err
    }

    t.state = "waiting"

    return nil
}

//Input: List, Element
//Output: Boolean output
//Function: Check if element in list
func contains(l []string, e string) bool {

    for _, ele := range l {

        if ele == e {

            return true
        }
    }

    return false
}
