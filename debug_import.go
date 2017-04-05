package main

import (
    "bytes"
    "fmt"
    "io/ioutil"
    "os"

    "github.com/zapu/go-crypto-printf/openpgp"
)

func main() {
    keybytes, _ := ioutil.ReadAll(os.Stdin)

    keys, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(keybytes))
    if err != nil {
        fmt.Printf("Error while opening keyring: %v", err)
        return
    }

    entity := keys[0]
    fmt.Printf("Primary KeyId: %x (dec: %v)\n", entity.PrimaryKey.KeyId, entity.PrimaryKey.KeyId)
}
