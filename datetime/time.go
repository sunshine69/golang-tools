package playdatetime

import (
	"fmt"
	"log"
	"time"
)

func PlayWithTime() {
	//1,2,3,4,5,6 start month. The PM is a must as it is 15:04. 2 can be single or 02
	layoutBasic := "Mon Jan 2 2006 15:04:05 PM MST"
	t0, e := time.Parse(layoutBasic, "Wed Feb 14 1984 08:00:00 AM AEST")
	if e != nil {
		log.Printf("%v\n", e)
	}
	fmt.Printf("%v\n", t0)
	loc, err := time.LoadLocation("America/Chicago")
	if err != nil {
		log.Printf("%v\n", e)
	}
	t := time.Now().In(loc)
	log.Printf("Zone only: %v\n", t.Format("MST"))
	log.Printf("Format output: %v\n", t.Format("2006 Jan 2 15:04:05 PM MST"))
}
