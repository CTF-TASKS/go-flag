package main

import (
	"fmt"
	"sync"
)

func check(flag string) {

}

func main() {
	w := make([](sync.WaitGroup), 100)
	w[0].Add(1)
	w[0].Done()
	go func() {
		w[0]
	}()
	fmt.Println("Please input your flag:")
	flag := ""
	fmt.Scanln(&flag)
	fmt.Println("Flag: ", flag)
}
