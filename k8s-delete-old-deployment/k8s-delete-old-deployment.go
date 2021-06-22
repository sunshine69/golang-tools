package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/araddon/dateparse"

	jsoniter "github.com/json-iterator/go"
	u "localhost.com/utils"
)

var (
	json      = jsoniter.ConfigCompatibleWithStandardLibrary
	inputFile string
)

func main() {
	l := log.Printf

	flag.StringVar(&inputFile, "f", "", "Input fname. Run 'kubectl -n review get deployments -o json > deployments.json' to get the file")
	flag.Parse()

	data, err := ioutil.ReadFile(inputFile)
	u.CheckErr(err, "")

	o := make(map[string]interface{}, 1)
	u.CheckErr(json.Unmarshal(data, &o), "")
	items := o["items"].([]interface{})
	output := []map[string]string{}
	for _, val := range items {
		_val := val.(map[string]interface{})["metadata"].(map[string]interface{})
		output = append(output, map[string]string{
			"name":      _val["name"].(string),
			"startdate": _val["creationTimestamp"].(string),
		})
	}
	cmdList := []string{}
	for _, val := range output {
		tnow := time.Now()
		tDeploy, err := dateparse.ParseLocal(val["startdate"])
		u.CheckErr(err, "")
		diff := tnow.Sub(tDeploy)
		if diff.Hours()/24 > 7 { //older than 7 days and then to be rm
			if !strings.Contains(val["name"], "nginx") {
				depDate := tDeploy.String()
				cmdList = append(cmdList, fmt.Sprintf("kubectl -n review delete deployment %s - %s", val["name"], depDate))
			}
		}
	}
	l("%v\n", strings.Join(cmdList, "\n"))
}
