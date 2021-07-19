package main

import (
	"os"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/araddon/dateparse"

	jsoniter "github.com/json-iterator/go"
	u "localhost.com/utils"
)

var (
	json      = jsoniter.ConfigCompatibleWithStandardLibrary
	inputFile, k8sNamespace string
    autoExecute bool
)

func main() {

	flag.StringVar(&inputFile, "f", "", "Input fname. Run 'kubectl -n review get deployments -o json > deployments.json' to get the file")
    flag.BoolVar(&autoExecute, "autoexec", false, "Auto exec. This will automatically run kubectl to get deployment and print out the command")
    flag.StringVar(&k8sNamespace, "n", "review", "k8s namespace when automatically run kubectl to get deployment and print out the command")
	flag.Parse()

	tempFile, err := ioutil.TempFile("", "deployments.json"); defer os.Remove(tempFile.Name())

	u.CheckErr(err, "Create temp file")
    if autoExecute {
		u.RunSystemCommand(fmt.Sprintf("kubectl -n %s get deployments -o json > %s", k8sNamespace, tempFile.Name()), false)
		inputFile = tempFile.Name()
    }

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
				//depDate := tDeploy.String()
				//cmdList = append(cmdList, fmt.Sprintf("kubectl -n review delete deployment %s - %s", val["name"], depDate))
				cmdList = append(cmdList, fmt.Sprintf("kubectl -n %s delete deployment %s", k8sNamespace, val["name"]))
			}
		}
	}
	fmt.Printf("%v\n", strings.Join(cmdList, "\n"))
}
