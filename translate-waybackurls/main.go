package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"log"
	"os"
	"strings"
)

const fetchURL = "http://web.archive.org/cdx/search/cdx?url=%s.translate.goog/*&output=text&fl=original&collapse=urlkey"

func extractHostname(urlString string) (string, error) {
	u, err := url.Parse(urlString)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}


func main() {

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprintln(os.Stderr, "No urls detected. Hint: cat domains.txt | crawler")
		os.Exit(1)
	}
	
	s := bufio.NewScanner(os.Stdin)
	for s.Scan() {
		url := s.Text()
		hostname, err := extractHostname(url)
		
		if err != nil {
			log.Println("Error parsing URL:", err)
			return
		}
		
		hostname_ := strings.Replace(hostname, ".", "-", -1)
		hostnameTr := hostname_ + ".translate.goog"

		resp, err := http.Get(fmt.Sprintf(fetchURL, hostname_))
		if err != nil {
			panic(err)
		}

		t := bufio.NewScanner(resp.Body)
		for t.Scan() {
			urlTr := t.Text()
			urlExtacted := strings.Replace(urlTr, hostnameTr, hostname, -1)
			fmt.Println(urlExtacted)
		}
	}
}
