package main

import	(
	"flag"
	"fmt"
	"strings"
	"strconv"

	"github.com/ernestosuarez/itertools"
)


func main()  {

	passwordLength := flag.String("pl", "1,2,4", "Length of the password")
	characters := flag.String("ch", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()+-./", "characters to make wordlist")

	passwordLengths := strings.Split(*passwordLength, ",")
	charactersList := strings.Split(*characters, "")

	for _, passLen := range passwordLengths {
	
		passLenInt, err := strconv.Atoi(passLen)
		if err != nil {
			panic(err)
		}

		for v := range itertools.PermutationsStr(charactersList, passLenInt) {
			fmt.Println(strings.Join(v, ""))
		}
		
	}
}
