/*
Created on Apr 18, 2017

@author: Akshaya Mani, Georgetown University

See LICENSE for licensing information
*/

package asn

import (
    "bufio"
    "encoding/binary"
    "fmt"
    "math/rand"
    "net"
    "os"
    "strings"
    "strconv"
    //"time"
)

/*func main() {

    ipv4map := CreateIPASNMap("../as-ipv4-coalesced-20171126.ipasn", 4)
    ipv6map := CreateIPASNMap("../as-ipv6-20171127.ipasn", 6)

    for i := 0; i < 8000; i++ {

        ipv4 := get_random_load_entry(ipv4map, 4)
        asn4 := FindASN(ipv4map, 4, ipv4)
        fmt.Println(ipv4, asn4)
        nonipv4 := get_random_load_nonentry(4)
        nonasn4 := FindASN(ipv4map, 4, nonipv4)
        if nonasn4 != "" {

            fmt.Println(nonipv4, "is not a non-entry")
        }

        ipv6 := get_random_load_entry(ipv6map, 6)
        asn6 := FindASN(ipv6map, 6, ipv6)
        fmt.Println(ipv6, asn6)
        nonipv6 := get_random_load_nonentry(6)
        nonasn6 := FindASN(ipv6map, 6, ipv6)
        if nonasn6 != "" {

            fmt.Println(nonipv6, "is not a non-entry")
        }
    }
}*/

//Input: File Path, IP version (4 or 6)
//Output: IP network to ASN mapping
//Function: Create IP network to ASN map from file
func CreateIPASNMap(file_path string, ipver int) (map[string]map[string]string) {

    ipasnmap := map[string]map[string]string{} //Map

    var dprefix string //Default prefix length

    if ipver == 4 {

        dprefix = "32" //Set default prefix length to 32

    } else if ipver == 6 {

        dprefix = "128" //Set default prefix length to 128

    } else {

        checkError(fmt.Errorf("Invalid IP version")) //Invalid IP version error
    }

    //Open file
    file, err := os.Open(file_path)
    checkError(err)
    defer file.Close()

    //Read line by line
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {

        ipasn := strings.Fields(scanner.Text())

        ipnet := strings.Split(ipasn[0], "/")

        if len(ipnet) == 2 { //If prefix length exists

            if len(ipasnmap[ipnet[1]]) == 0 { //Map is empty

                ipasnmap[ipnet[1]] = map[string]string{} //Initialize map
            }

            ipasnmap[ipnet[1]][ipnet[0]] = ipasn[1] //Use prefix length to map

        } else if len(ipnet) == 1 { //If prefix length does not exist

            if len(ipasnmap[dprefix]) == 0 { //Map is empty

                ipasnmap[dprefix] = map[string]string{} //Initialize map
            }

            ipasnmap[dprefix][ipnet[0]] = ipasn[1] //Use default prefix length to map
        }
    }

    checkError(scanner.Err()) //Check for scanner error

    return ipasnmap
}

//Input: IP network to ASN map, IP version, IP
//Output: ASN
//Function: Find the ASN for the given IP
func FindASN(ipasnmap map[string]map[string]string, ipver int, ip string) (string) {

    var prefix int //Prefix length

    if ipver == 4 {

        prefix = 32 //Set prefix length to 32

    } else if ipver == 6 {

        prefix = 128 //Set prefix length to 128

    } else {

        checkError(fmt.Errorf("Invalid IP version")) //Invalid IP version error
    }

    for prefix >= 1 { //Check for all prefixes starting from the longest

        sprefix := strconv.Itoa(prefix) //Convert to string

        if _, ok1 := ipasnmap[sprefix]; ok1 { //If prefix exists in map

            _, ipnet, err := net.ParseCIDR(ip + "/" + sprefix) //Parse IP network

            if err == nil {//No error

                if asn, ok2 := ipasnmap[sprefix][ipnet.IP.String()]; ok2 { //If IP network exists in map

                    return asn //Return ASN
                }
            }
        }

        prefix = prefix - 1 //Decrement prefix length
    }

    return "" //ASN not found
}

//Input: IP network to ASN map, IP version, IP
//Output: Random entry
//Function: Choose a random IP from map
func get_random_load_entry(ipasnmap map[string]map[string]string, ipver int) (string) {

    var dprefix int //Default prefix length

    if ipver == 4 {

        dprefix = 32 //Set default prefix length to 32

    } else if ipver == 6 {

        dprefix = 128 //Set default prefix length to 128

    } else {

        checkError(fmt.Errorf("Invalid IP version")) //Invalid IP version error
    }

    //Choose random prefix
    prefix := rand.Intn(dprefix)
    sprefix := strconv.Itoa(prefix)
    _, ok := ipasnmap[sprefix]

    for !ok { //If prefix does not exist in map

        //Choose random prefix
        prefix = rand.Intn(dprefix)
        sprefix = strconv.Itoa(prefix)
        _, ok = ipasnmap[sprefix]
    }

    for ipnet := range ipasnmap[sprefix] {

        //Choose a random IP from the IP network
        nbyte := make([]byte, dprefix/8)
        binary.BigEndian.PutUint32(nbyte, uint32(rand.Intn(dprefix - prefix))) //Just an appoximation as 2^(dprefix - prefix) > dprefix - prefix.
        ip := make([]byte, dprefix/8)
        ipnetbyte := make([]byte, dprefix/8)

        if ipver == 4 {

            ipnetbyte = []byte(net.ParseIP(ipnet).To4())

        } else if ipver == 6 {

            ipnetbyte = []byte(net.ParseIP(ipnet).To16())
        }

        for i := 0; i < ipver; i++ {

            ip[i] = ipnetbyte[i] | nbyte[i]
        }

        return net.IP(ip).String() //Return IP
    }

    return ""
}

//Input: IP version
//Output: Random non-entry
//Function: Return a random IP not in map
func get_random_load_nonentry(ipver int) string {

    var dprefix int //Default prefix length

    if ipver == 4 {

        dprefix = 32 //Set default prefix length to 32

    } else if ipver == 6 {

        dprefix = 128 //Set default prefix length to 128

    } else {

        checkError(fmt.Errorf("Invalid IP version")) //Invalid IP version error
    }

    //Generate random IP
    ipbyte := make([]byte, dprefix/8)
    rand.Read(ipbyte)
    ip := (net.IP(ipbyte)).String()

    return ip
}

//Input: Error
//Function: Check Error
func checkError(err error) {
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
}
