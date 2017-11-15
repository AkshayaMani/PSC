package main

import (
        "bytes"
        //"fmt"
        "github.com/dedis/crypto/abstract"
        "github.com/dedis/crypto/nist"
        "github.com/golang/protobuf/proto"
        "io/ioutil"
        "privcardinality/schnorr/schnorrkey"
        "strconv"
)

func main() {
    
    for i := 0; i < 10; i++ {

        suite := nist.NewAES128SHA256P256()
        rand := suite.Cipher(abstract.RandomKey)
        
        x := suite.Scalar().Pick(rand)
	y := suite.Point().Mul(nil, x)        

        priv := new(Schnorrkey.Priv)
        pub := new(Schnorrkey.Pub)
        
        priv.X = x.Bytes()
        var b bytes.Buffer
        _,_ = y.MarshalTo(&b)
        
        pub.Y = b.Bytes()
     
        out, err := proto.Marshal(priv)
        check(err)
        err = ioutil.WriteFile("private/sk" + strconv.Itoa(i + 1) + ".priv", out, 0644)
        check(err)
        //fmt.Printf("%q \n",x.String())

        /*in, err := ioutil.ReadFile("private/sk" + strconv.Itoa(i + 1) + ".priv")
        check(err)
        priv1 := &Schnorrkey.Priv{}
        err = proto.Unmarshal(in, priv1)
        check(err)
        x1 := suite.Scalar()
        x1.SetBytes(priv1.X)
        fmt.Printf("%q \n",x1.String())*/
        

        out, err = proto.Marshal(pub)
        check(err)
        err = ioutil.WriteFile("public/sk" + strconv.Itoa(i + 1) + ".pub", out, 0644)
        check(err)
        //fmt.Printf("%q \n",y.String())

        /*in, err = ioutil.ReadFile("public/sk" + strconv.Itoa(i + 1) + ".pub")
        check(err)
        pub1 := &Schnorrkey.Pub{}
        err = proto.Unmarshal(in, pub1)
        check(err)
        y1 := bytes.NewReader(pub1.Y)
        y2 := suite.Point()
        y2.UnmarshalFrom(y1)
        fmt.Printf("%q \n",y2.String())*/
    }
}

//Check Error
func check(e error) {
    if e != nil {
        panic(e)
    }
}


