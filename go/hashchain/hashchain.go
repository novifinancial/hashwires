package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/blake2b"
)

var HashLen = 5

func main() {
	app := &cli.App{
		Name:    "hashchain",
		Version: "v0.0.1",
		Commands: []*cli.Command{
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "create a proof. Args: create seed1 seed2 value actualvalue",
				Action: func(c *cli.Context) error {
					return create(c)
				},
			},
			{
				Name:    "verify",
				Aliases: []string{"v"},
				Usage:   "verify a proof that the value is in the proved range. Args: verify value seed sig pubkey [leaves...]",
				Action: func(c *cli.Context) error {
					return verify(c)
				},
			},
			{
				Name:    "genkey",
				Aliases: []string{"g"},
				Usage:   "generate a key",
				Action: func(c *cli.Context) error {
					return genKey()
				},
			},
			{
				Name:    "sign",
				Aliases: []string{"s"},
				Usage:   "sign a root for a value. Args: sign value sk",
				Action: func(c *cli.Context) error {
					return signing(c)
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func signing(c *cli.Context) error {
	fmt.Println("Creating a HW...")
	if c.NArg() < 2 {
		return errors.New("Incorrect usage")
	}
	val, err := strconv.Atoi(c.Args().Get(0))
	if err != nil {
		panic(err)
	}

	sk:=c.Args().Get(1)

	sd1 := make([]byte, HashLen)
	sd2 := make([]byte, HashLen)
	_, err = rand.Reader.Read(sd1)
	if err != nil {
		panic(err)
	}
	_, err =  rand.Reader.Read(sd2)
	if err != nil {
		panic(err)
	}

	seed1 := encode(sd1)
	seed2 := encode(sd2)

	if c.NArg() == 4 {
		fmt.Println("using provided seeds")
		seed1 = c.Args().Get(2)
		seed2 = c.Args().Get(3)
	}

	fmt.Println("Seeds:", seed1, seed2)

	HW := HashwiresInRange(seed1, seed2, val, 0, 160, "age")

	fmt.Println(HW[0][len(HW[0])-1], HW[0][0])
	fmt.Println(HW[1][len(HW[1])-1], HW[1][0])
	fmt.Println("root:", HW[0][len(HW[0])-2], HW[1][len(HW[1])-2])
	fmt.Println("labels:", HW[0][len(HW[0])-3], HW[1][len(HW[1])-3])

	fmt.Println("sign:",sign(HW[0][len(HW[0])-2], decode(sk)))

	fmt.Println(HW)

	return nil
}

func create(c *cli.Context) error {
	fmt.Println("Creating a proof...")
	if c.NArg() != 3 {
		return errors.New("Incorrect usage")
	}
	// seed1 seed2 value
	seed1:=c.Args().Get(0)
	//seed2:=c.Args().Get(1)
	val, err := strconv.Atoi(c.Args().Get(1))
	if err != nil {
		panic(err)
	}
	actual, err := strconv.Atoi(c.Args().Get(2))
	if err != nil {
		panic(err)
	}

	fmt.Println("age:", proveValue(seed1, actual-val))


	return nil
}

func verify(c *cli.Context) error {
	fmt.Println("Verifying a proof...")
	fmt.Println(c.Args())

	if c.NArg() < 4 {
		return errors.New("Incorrect usage")
	}

	//verify value seed sig pubkey [leaves]
	val, err := strconv.Atoi(c.Args().Get(0))
	if err != nil {
		panic(err)
	}
	seed:= c.Args().Get(1)
	sig:= c.Args().Get(2)
	pk:=c.Args().Get(3)
	var lv []string
	if c.NArg() > 3 {
		lv = c.Args().Slice()[4:]
	}

	fmt.Println("Verified:", verifyValue(val, seed, "age",lv, sig, decode(pk)))

	return nil
}

func Hash(seed string) string {
	h, err := blake2b.New(HashLen, nil)
	if err != nil {
		panic(err)
	}
	dec := decode(seed)
	_, err = h.Write(dec)
	if err != nil {
		panic(err)
	}
	ret := h.Sum(nil)
	return encode(ret)
}

func PowerHash(seed string, pow int) string {
	for i := 0; i < pow; i++ {
		seed = Hash(seed)
	}
	return seed
}

func LabelHash(seed, label string) string {
	if len([]byte(label)) > 64 {
		panic("invalid label size, bigger than 64 bytes")
	}
	h, err := blake2b.New(HashLen, []byte(label))
	if err != nil {
		panic(err)
	}

	_, err = h.Write(decode(seed))
	if err != nil {
		panic(err)
	}
	ret := h.Sum(nil)
	return encode(ret)
}

func encode(b []byte) string {
	return hex.EncodeToString(b)
}

func decode(s string) []byte {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return decoded
}

func ChainHashes(seed string, iter int) (ret []string) {
	ret = append(ret, seed)
	for i := 0; i < iter; i++ {
		seed = Hash(seed)
		ret = append(ret, seed)
	}
	return
}

func LabelChain(hashes []string, label string) (ret []string) {
	if len(hashes) < 1 {
		panic("invalid chain length")
	}
	ret = hashes
	ret = append(ret, LabelHash(hashes[len(hashes)-1], label))

	return
}

func GetRoot(chains [][]string) string {
	var concat string
	for _, v := range chains {
		if len(v[len(v)-1]) != len(chains[0][len(chains[0])-1]) {
			fmt.Println( len(v[len(v)-1]), len(chains[0][len(chains[0])-1]))
			panic("invalid final hash length in provided chains.")
		}
		// we combine the last elements of the chains
		concat += v[len(v)-1]
	}
	// and hash them
	return Hash(concat)
}

func HashwiresInRange(seed1, seed2 string, value, min, max int, label string) (ret [][]string) {
	labChain := ChainHashes(seed1, value-min)
	compChain := ChainHashes(seed2, max-min-value)

	// we label each chain
	labChain = LabelChain(labChain,label)
	compChain = LabelChain(compChain,label+"-complement")
	ret = append(ret, labChain)
	ret = append(ret, compChain)

	// we attach the root to each chain
	root := GetRoot(ret)
	labChain = append(labChain, root, label)
	compChain = append(compChain, root,label+"-complement")

	ret = nil
	ret = append(ret, labChain)
	ret = append(ret, compChain)
	return
}

func proveValue(seed string, value int) string {
	return PowerHash(seed, value)
}


func sign(msg string, key ed25519.PrivateKey) string {
	sig, err := key.Sign(rand.Reader, decode(msg),crypto.Hash(0))
	if err != nil {
		panic(err)
	}
	return encode(sig)
}

func genKey() error {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Println("Public key:", encode(pk))
	fmt.Println("Secret key:", encode(sk))
	return nil
}

func verifyValue(value int, seed, label string, leaves []string, sig string, authkey ed25519.PublicKey) bool {
	rs := PowerHash(seed, value)
	rs = LabelHash(rs, label)
	var merklebase [][]string
	merklebase = append(merklebase,[]string{rs})
	for _, e:=range leaves {
		merklebase = append(merklebase,[]string{e})
	}

	root := GetRoot(merklebase)
	fmt.Println("Got root:", root, "from:", merklebase)

	return ed25519.Verify(authkey,decode(root),decode(sig))
}