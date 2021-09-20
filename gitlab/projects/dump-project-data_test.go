package main
import (
	"fmt"
	"testing"
	_ "github.com/mattn/go-sqlite3"
	u "localhost.com/utils"
)

func TestProject(t *testing.T) {
	p := Project{}
	Logdbpath = "testdb.sqlite3"
	p.GetProject(map[string]string{
		"where": "pid = 2314",
	})
	fmt.Printf("%s\n", u.JsonDump(p, "    "))
	// p.Name = fmt.Sprintf("%s - Updated", p.Name)
	// p.Name = "Devops Playground"
	// p.Update()
	// p1 := Project{}
	// p1.GetProject(map[string]string{
	// 	"where": "name LIKE 'DevOps%'",
	// })
	// fmt.Printf("%s\n", u.JsonDump(p1, "    "))
}
