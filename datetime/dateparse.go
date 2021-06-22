package playdatetime

import (
	"fmt"
	"github.com/araddon/dateparse"
	u "localhost.com/utils"
	"time"
	// "github.com/alexeyco/simpletable"
)

func PlayDateparse() {
	p := fmt.Printf
	tnow := time.Now()
	p("NOW is: %v\n", tnow)
	//Parse ISO date string (including the Z)
	//https://pkg.go.dev/github.com/araddon/dateparse
	t0, e := dateparse.ParseLocal("2021-05-18T08:29:44Z")
	u.CheckErr(e, "PlayDateparse")

	d := tnow.Sub(t0)
	p("DIFF %f\n", d.Hours()/24)

}
