package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Define some constants for colors and formatting
const (
	BOLD     = "\033[1m"
	GOLD     = "\033[38;5;226m"
	GREY     = "\033[0;37m"
	CYAN     = "\033[0;36m"
	PEACH    = "\033[38;5;216m"
	GREEN    = "\033[38;5;149m"
	ORANGE   = "\033[38;5;202m"
	MAGENTA  = "\033[0;95m"
	PINK     = "\033[38;5;204m"
	YELLOW   = "\033[38;5;227m"
	OFFWHITE = "\033[38;5;157m"
	RED      = "\033[38;5;196m"
	RESET    = "\033[0m"
)

// Define some variables for flags and arguments
var (
	new      bool   // new flag
	dis      bool   // disable flag
	append   bool   // append flag
	flags    string // ffuf flags
	domain   string // target domain name
	subfile  string // subdomains file
	wordfile string // wordlist file
)

// Define a function to print the usage message
func usage() {
	fmt.Printf("%s\n[+] Usage:\n\t./lazyFuzzZ  <target-domain name> <subdomains_http/https_URLs_to_fuzz.txt> <common wordlist file>%s\n", PINK, RESET)
	fmt.Printf("%s  Eg: ./lazyFuzzZ  example.com   example.com_https_subdomains.txt   common_fuzzing_wordlist.txt\n%s", GREEN, RESET)
	fmt.Printf("%s -f : to use your own ffuf flags. %s(IMPORTANT: This flag should be written before command line arguments)%s\n", GREEN, OFFWHITE, RESET)
	fmt.Printf("%s  Eg: ./lazyFuzzZ -f '-mc 403 -t 200'  example.com   example.com_https_subdomains.txt   common_fuzzing_wordlist.txt\n%s", GREEN, RESET)
	fmt.Printf("%s -a : to append ffuf flags. %s(IMPORTANT: This flag should be written before the command line arguments)%s\n", GREEN, OFFWHITE, RESET)
	fmt.Printf("%s  Eg: ./lazyFuzzZ -a '-H User-Agent:xyz -H X-Forwarded-For:127.0.0.1 -b cookie_1:value;cookie_2:value -replay-proxy http://127.0.0.1:8080' example.com  	example.com_https_subdomains.txt common_fuzzing_wordlist.txt%s\n", GREEN, RESET)
	fmt.Printf("%s\n[+] Tip! If you are going to using the -replay-proxy ffuf flag, use -d flag with lazyFuzzZ.%s\n", YELLOW, RESET)
	fmt.Printf("%s\n -d : to DISABLE bfeed.py %s(IMPORTANT: This flag should be written before command line arguments)%s\n", GREEN, OFFWHITE, RESET)
	fmt.Printf("%s -h : to display usage.%s\n", GREEN, RESET)
	fmt.Printf("%s\n[+] Default ffuf flags used: -mc 200,403 -fs 0 -t 80 -sa -timeout 7%s\n", CYAN, RESET)
	fmt.Printf("%s[-] WARNING: Do not specify 'output flags', -u, and -w for ffuf!%s\n", RED, RESET)
}

// Define a function to parse the flags and arguments
func parseArgs() {
	args := os.Args[1:] // skip the program name
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f":
			new = true
			i++
			if i < len(args) {
				flags = args[i]
			} else {
				usage()
				fmt.Println("Invalid argument!")
				os.Exit(1)
			}
		case "-d":
			dis = true
		case "-h":
			usage()
			os.Exit(1)
		case "-a":
			append = true
			i++
			if i < len(args) {
				flags = args[i]
			} else {
				usage()
				fmt.Println("Invalid argument!")
				os.Exit(1)
			}
		default:
			if domain == "" {
				domain = args[i]
			} else if subfile == "" {
				subfile = args[i]
			} else if wordfile == "" {
				wordfile = args[i]
			} else {
				usage()
				fmt.Println("Invalid argument!")
				os.Exit(1)
			}
		}
	}
	if append && new {
		fmt.Printf("%s\n[-] Don't specify -a and -f flags together!%s\n", RED, RESET)
		os.Exit(1)
	}
	if domain == "" || subfile == "" || wordfile == "" {
		usage()
		fmt.Println("\n[-] Not enough arguments! Check usage.")
		os.Exit(1)
	}
}

// Define a function to run a command and check for errors
func runCommand(cmd *exec.Cmd) {
	err := cmd.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// Define a function to run ffuf and save the output
func runFfuf(url string, subdomain string) {
	cmd := exec.Command("ffuf", "-u", url, "-w", wordfile, "-of", "csv", "-o", "test")
	if new {
		cmd = exec.Command("ffuf", flags, "-u", url, "-w", wordfile, "-of", "csv", "-o", "test")
	} else if append {
		cmd = exec.Command("ffuf", "-mc", "200,403", "-fs", "0", "-t", "80", "-sa", "-timeout", "7", flags, "-u", url, "-w", wordfile, "-of", "csv", "-o", "test")
	}
	runCommand(cmd)
	outFile, err := os.Create(fmt.Sprintf("lazyFuzzZ.output.%s/%s.output", wordfile, subdomain))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer outFile.Close()
	inFile, err := os.Open("test")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.ReplaceAll(line, ",,", " ")
		line = strings.ReplaceAll(line, ",", "                    ")
		line = strings.TrimSuffix(line, ",")
		if strings.HasPrefix(line, "http") {
			outFile.WriteString(line + "\n")
		}
	}
}

// Define a function to remove false positives from the output
func removeFalsePositives(subdomain string) {
	outFile, err := os.Open(fmt.Sprintf("lazyFuzzZ.output.%s/%s.output", wordfile, subdomain))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer outFile.Close()
	sizes := make(map[string]int) // map of sizes and their frequencies
	scanner := bufio.NewScanner(outFile)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) > 1 {
			size := fields[1]
			sizes[size]++
		}
	}
	maxFreq := 0  // maximum frequency of a size
	maxSize := "" // size with maximum frequency
	for size, freq := range sizes {
		if freq > maxFreq {
			maxFreq = freq
			maxSize = size
		}
	}
	if maxFreq > 100 {
		// if there are more than 100 false positives
		fmt.Printf("%s[+] Results obtained with false positives... Removing them...%s\n", MAGENTA, RESET)
		inFile, err := os.Open(fmt.Sprintf("lazyFuzzZ.output.%s/%s.output", wordfile, subdomain))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer inFile.Close()
		outFile, err := os.Create("buff")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer outFile.Close()
		scanner := bufio.NewScanner(inFile)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) > 1 {
				size := fields[1]
				if size != maxSize {
					outFile.WriteString(line + "\n")
				}
			}
		}
		runCommand(exec.Command("mv", "buff", fmt.Sprintf("lazyFuzzZ.output.%s/%s.output", wordfile, subdomain)))
	}
}

func main() {
	parseArgs() // parse the flags and arguments
	fmt.Printf("%s\n[+] Starting Lazy FuzzZ! :D\n%s\n", GREEN, RESET)
	runCommand(exec.Command("mkdir", fmt.Sprintf("lazyFuzzZ.output.%s", wordfile)))
	inFile, err := os.Open(subfile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer inFile.Close()
	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, domain) {
			url := strings.ReplaceAll(line, domain, domain+"/FUZZ")
			fmt.Printf("%s[+]Running on %s%s\n", CYAN, url, RESET)
			subdomain := strings.Split(url, "/")[2]
			runFfuf(url, subdomain)
			if !dis {
				runCommand(exec.Command("python3", "bfeed.py", fmt.Sprintf("lazyFuzzZ.output.%s/%s.output", wordfile, subdomain)))
			}
			removeFalsePositives(subdomain) // remove false positives from the output
		}
	}
}
