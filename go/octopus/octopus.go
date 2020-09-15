package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"log"
	"math/big"
	"sort"
)

var (
	zero      = big.NewInt(0)
	one       = big.NewInt(1)
	HashLen   = 5
	SecretKey = "DEADC0DEC0FFEE"
	pubKey    = "4527a831cad70eb686537b0e2c117c3359e7222beca1a88fb0695d0705b21f76"
	signKey   = "0c54a972f66e5081a72b1d07a228668a8e0db3abc443ce1695f46286f076a0f34527a831cad70eb686537b0e2c117c3359e7222beca1a88fb0695d0705b21f76"
)

func main() {
	// use this to generate new keys that can be set as global variables above
	//	genKey()

	// Testing the algo to find complete numsBasis
	fmt.Println("Finding minimal nums basis:", findComplete(big.NewInt(3413), 10),
		findComplete(big.NewInt(2999), 10),
		findComplete(big.NewInt(181), 10),
		findComplete(big.NewInt(1979), 10),
		findComplete(big.NewInt(1992), 10),
		findComplete(big.NewInt(1799), 10),
		findComplete(big.NewInt(1000), 10))
	fmt.Println("")

	pk := signTree("3413", 10)
	fmt.Printf("Using the following Proving Kit: %+v\n", pk)

	pm := proveValue("3109", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))
	pm = proveValue("3190", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))
	pm = proveValue("1000", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))

	fmt.Println("")

	pk = signTree("1000", 10)
	fmt.Printf("Using the following Proving Kit: %+v\n", pk)

	pm = proveValue("1000", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))
	pm = proveValue("500", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))
	pm = proveValue("5", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))
	pm = proveValue("0", pk)
	fmt.Printf("Proving %s: %+v\n", pm.value, pm)
	fmt.Printf("Does the kit verify for %s? %v\n\n", pm.value, verifyKit(pm))
}

type provingKit struct {
	proofs     []string
	otherRoots []string
	numsBasis  []string
	value      string
	sig        string
	base       int
}

// signTree is producing the proving kit as the gov would do it, so that one can use it to prove values.
func signTree(value string, base int) provingKit {
	fmt.Println("Signing Tree for value", value)
	val := toInt(value, base)
	numsBasis := findComplete(val, base)
	sort.Strings(numsBasis)
	var subRoots []string
	leaves := getSeedChain(len(value))
	for _, e := range numsBasis {
		_, numRoot := DigitsHashes(e, leaves, base)
		subRoots = append(subRoots, GetRoot(numRoot))
	}
	fmt.Println("Using numsRoots:", subRoots)
	root := GetRoot(subRoots)
	fmt.Println("Testing root:", root)

	sig := sign(root, decode(signKey))
	return provingKit{proofs: leaves, numsBasis: numsBasis, value: value, sig: sig, base: base}
}

// verifyKit is verifying a given provingKit using the global public key.
func verifyKit(kit provingKit) bool {
	val := toInt(kit.value, kit.base)
	digits := splitNumber(val, kit.base, len(kit.proofs))

	var subRoots []string
	for i, e := range kit.proofs {
		subRoots = append(subRoots, PowerHash(e, digits[i]))
	}

	root := GetRoot(subRoots)

	mainRoots := append(kit.otherRoots, root)
	root = GetRoot(mainRoots)

	ok := verify(root, kit.sig, decode(pubKey))
	return ok
}

// proveValue is producing a provingKit from the issued main proving kit allowing to prove the provided value is <=.
func proveValue(value string, kit provingKit) provingKit {
	val := toInt(value, kit.base)
	if val.Cmp(zero) < 0 {
		log.Fatalln("Cannot  prove a negative value")
	}
	sort.Strings(kit.numsBasis)
	num := new(big.Int)
	ok := false
	digits := splitNumber(val, kit.base, len(kit.proofs))

	var numDigits []int

	var otherRoots []string
	var eLen int
	// let us select the first nums to prove that value
	for _, e := range kit.numsBasis {
		elem := toInt(e, kit.base)
		if elem.Cmp(val) >= 0 && !ok {
			num.Set(elem)
			numDigits = splitNumber(num, kit.base, len(kit.proofs))
			if hasSmallerDigits(digits, numDigits) {
				eLen = len(e)
				ok = true
			} else {
				_, numsRoot := DigitsHashes(e, kit.proofs, kit.base)
				otherRoots = append(otherRoots, GetRoot(numsRoot))
			}
		} else {
			_, numsRoot := DigitsHashes(e, kit.proofs, kit.base)
			otherRoots = append(otherRoots, GetRoot(numsRoot))
		}
	}

	if !ok {
		log.Fatalln("Unable to prove the value", value, "using this kit with the numsBasis:", kit.numsBasis)
	}

	for len(digits) < eLen {
		digits = append(digits, 0)
	}

	//fmt.Println("Proving digits:", digits, "using nums", numDigits)

	var newLeaves []string

	for i, e := range kit.proofs {
		newLeaves = append(newLeaves, PowerHash(e, numDigits[i]-digits[i]))
	}

	fmt.Println("Proving the value", value, "using nums", num.Text(kit.base))

	return provingKit{
		proofs:     newLeaves,
		otherRoots: otherRoots,
		numsBasis:  nil,
		value:      value,
		sig:        kit.sig,
		base:       kit.base,
	}
}

func hasSmallerDigits(a, b []int) bool {
	//fmt.Println("Comparing", a,b)
	if len(a) != len(b) {
		return false
	}
	ok := true
	for i, _ := range a {
		if a[i] > b[i] {
			ok = false
		}
	}
	return ok
}

func SetHashLen(l int) {
	HashLen = l
}

func findComplete(val *big.Int, base int) (ret []string) {
	checkBase(base)
	keys := make(map[string]bool)
	keys[val.Text(base)] = true
	ret = append(ret, val.Text(base))

	b := new(big.Int).SetInt64(int64(base))
	e := new(big.Int).Set(b)
	for e.Cmp(val) < 1 {
		prev := new(big.Int).Set(val)
		// optimizing out the unneeded values
		if prev.Add(prev, one).Mod(prev, e).Cmp(zero) != 0 {
			//  (x//b^i - 1) * b^i + (b-1)
			prev.Div(val, e).Sub(prev, one).Mul(prev, e).Add(prev, new(big.Int).Sub(e, one))
			// we avoid duplicates
			if _, value := keys[prev.Text(base)]; !value {
				keys[prev.Text(base)] = true
				ret = append(ret, prev.Text(base))
			}
		}
		e.Mul(e, b)
	}
	return
}

func checkBase(base int) {
	if base < 2 || base > 62 {
		log.Fatalln("We only supports bases between 2 and 62.")
	}
}

// DigitsHashes returns the hash chains from the last digit to the first
func DigitsHashes(val string, seeds []string, base int) (digits []int, topHashes []string) {
	// we take its length (including leading zeros)
	l := len(val)
	if len(seeds) < l {
		log.Fatalf("Invalid seeds len %d for given values %v on value %v\n", l, seeds, val)
	}

	// we convert the value to a big int
	a := toInt(val, base)

	// we get its digits from last to first
	digits = splitNumber(a, base, len(seeds))

	//we hash the digits
	for i := 0; i < len(seeds); i++ {
		topHashes = append(topHashes, PowerHash(seeds[i], digits[i]))
	}

	return
}

func getSeed(pos int) string {
	sc := getSeedChain(pos + 1)
	return sc[len(sc)-1]
}

func getSeedChain(size int) (ret []string) {
	seed := KeyedHash("FEED", SecretKey)
	if size < 1 {
		log.Fatalln("Size/position must be positive")
	}
	for i := 0; i < size; i++ {
		ret = append(ret, seed)
		seed = KeyedHash(seed, SecretKey)
	}
	return
}

// splitNumber will return an array of integer representing the digits in the given base,
// from the least significant one to the most. i.e. 3413 --> [3,1,4,3]
func splitNumber(val *big.Int, base, totLen int) (ret []int) {
	checkBase(base)
	b := new(big.Int).SetInt64(int64(base))
	prev := new(big.Int).Set(val)
	digit := new(big.Int)
	for prev.Cmp(b) >= 0 {
		prev.DivMod(prev, b, digit)
		ret = append(ret, int(digit.Int64()))
	}
	ret = append(ret, int(prev.Int64()))

	for totLen > len(ret) {
		ret = append(ret, 0)
	}
	return ret
}

func GetRoot(subnodes []string) string {
	var concat string
	if len(subnodes) < 1 {
		log.Fatalln("Tried to get the root of an empty tree.")
	}

	// sorting the hashes to have a canonical hashing
	sort.Strings(subnodes)

	for _, e := range subnodes {
		if len(e) != 2*HashLen {
			log.Fatalln("Invalid hash length in Merkle root computation", e, len(e))
		}
		concat += e
	}
	return Hash(concat)
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

func KeyedHash(seed, key string) string {
	k := decode(key)
	if len(k) > 64 {
		log.Fatalln("Invalid key length for keyed hash")
	}
	h, err := blake2b.New(HashLen, k)
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
	hc := HashChain(seed, pow)
	return hc[len(hc)-1]
}

func HashChain(seed string, pow int) (ret []string) {
	for i := 0; i < pow; i++ {
		ret = append(ret, seed)
		seed = Hash(seed)
	}
	ret = append(ret, seed)
	return
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

func toInt(val string, base int) *big.Int {
	a, ok := new(big.Int).SetString(val, base)
	if ok != true {
		log.Fatalln("error decoding string", val, "from base", base)
	}
	return a
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

func sign(root string, key ed25519.PrivateKey) string {
	sig, err := key.Sign(rand.Reader, decode(root), crypto.Hash(0))
	if err != nil {
		panic(err)
	}
	return encode(sig)
}

func verify(root string, sig string, authkey ed25519.PublicKey) bool {
	return ed25519.Verify(authkey, decode(root), decode(sig))
}
