package main

import (
	"os"
	"flag"
	"log"
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
	inputFile, k8sNamespace, objectType string
    autoExecute bool
)

func processCommand(objType, inputFile string) {
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
				cmdList = append(cmdList, fmt.Sprintf("kubectl -n %s delete %s %s", k8sNamespace, objType, val["name"]))
			}
		}
	}
	fmt.Printf("%v\n", strings.Join(cmdList, "\n"))
}

func main() {

	flag.StringVar(&inputFile, "f", "", "Input fname. Run 'kubectl -n review get <object_type> -o json > deployments.json' to get the file. object_type can be: deployment, svc, hpa, ingress")
	flag.StringVar(&objectType, "t", "deployment", "Object type. Can be: deployment, svc, hpa, ingress, all. all is all of them")
    flag.BoolVar(&autoExecute, "autoexec", false, "Auto exec. This will automatically run kubectl to get deployment and print out the command")
    flag.StringVar(&k8sNamespace, "n", "review", "k8s namespace when automatically run kubectl to get deployment and print out the command")
	flag.Parse()

	tempFile, err := ioutil.TempFile("", objectType + ".json"); defer os.Remove(tempFile.Name())

	u.CheckErr(err, "Create temp file")

	supportObjectType := map[string]bool{
		"deployment": true, "service": true, "svc": true, "ingress": true, "ing": true, "hpa": true, "all": true,
	}
	if isSupport, ok := supportObjectType[objectType]; ok {
		if isSupport {
			if autoExecute {
				if objectType == "all" {
					for _, objType := range []string{"deployment","service","ingress", "hpa"} {
						u.RunSystemCommand(fmt.Sprintf("kubectl -n %s get %s -o json > %s", k8sNamespace, objType, tempFile.Name()), false)
						processCommand(objType, tempFile.Name())
					}
				} else {
					u.RunSystemCommand(fmt.Sprintf("kubectl -n %s get %s -o json > %s", k8sNamespace, objectType,tempFile.Name()), false)
					processCommand(objectType, tempFile.Name())
				}
			} else {
				processCommand(objectType, inputFile)
			}
		} else {
			log.Fatalf("[ERROR] Whether the objectType (-t) is not supported")
		}
	} else {
		log.Fatalf("[ERROR] Whether the objectType (-t) does not exist")
	}

}
