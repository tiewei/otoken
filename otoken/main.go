package main

import (
	"fmt"
	"os"

	"github.com/tiewei/gopack/otoken/cmd"
)

func main() {
	if err := cmd.New().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
