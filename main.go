package main

import "fmt"

func check(flag string) {
	
}

func main() {
	fmt.Println("Please input your flag:")
	flag := ""
	fmt.Scanln(&flag)
	fmt.Println("Flag: ", flag)
}
