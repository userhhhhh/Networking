package main

import "fmt"

func main() {
	fmt.Println("--------------------------------")
	fmt.Println("This project implements the requested functionality. Press a num to start.")
	fmt.Println("Press 1: basic task")
	fmt.Println("Press 2: client task")
	fmt.Println("Press 3: rules_ip task")
	fmt.Println("Press 4: rules_http task")
	fmt.Println("Press 5: rules_tls task")
	fmt.Println("Press 6: rules_program task")
	fmt.Println("Press 7: replay task")
	fmt.Println("Press 8: hack task")
	fmt.Println("--------------------------------")
	var input int
	_, err := fmt.Scanln(&input)
	if err != nil {
		fmt.Println("输入错误:", err)
		return
	}
	switch input {
	case 1:
		basic()
	case 2:
		client()
	case 3:
		rules_ip()
	case 4:
		rules_http()
	case 5:
		rules_tls()
	case 6:
		rules_program()
	case 7:
		replay()
	case 8:
		hack()
	}
}
