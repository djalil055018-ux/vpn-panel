// node-adoption inspects or stages held node material. It has no API client,
// service manager, installer, network listener or activation operation.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"vpn-platform/internal/nodeadoption"
	"vpn-platform/internal/remnawave"
)

func execute(args []string, stdout, stderr io.Writer, uid int) int {
	fail := func() int {
		fmt.Fprintln(stderr, "Node material preparation failed; no activation was attempted.")
		return 1
	}
	if uid != 0 || len(args) == 0 {
		return fail()
	}
	modes := map[string]bool{"inspect": true, "stage": true, "plan-inspection": true, "plan-preparation": true, "plan-stage": true}
	if !modes[args[0]] {
		return fail()
	}
	flags := flag.NewFlagSet("node-adoption", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	planPath := flags.String("plan", "", "")
	configPath := flags.String("config", "", "")
	inventoryPath := flags.String("inventory", "", "")
	inspectionPath := flags.String("inspection", "", "")
	preparationPath := flags.String("preparation", "", "")
	certificatesPath := flags.String("certificates", "", "")
	out := flags.String("out", "", "")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return fail()
	}
	allowed := map[string]bool{"plan": true, "out": true}
	if args[0] == "inspect" || args[0] == "stage" {
		allowed["config"] = true
	} else {
		allowed["inventory"] = true
		if args[0] != "plan-inspection" {
			allowed["inspection"] = true
			allowed["certificates"] = true
		}
		if args[0] == "plan-stage" {
			allowed["preparation"] = true
		}
	}
	bad := false
	seen := map[string]bool{}
	flags.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] {
			bad = true
		}
		seen[f.Name] = true
	})
	if bad {
		return fail()
	}
	for name := range allowed {
		if !seen[name] {
			return fail()
		}
	}
	rawPlan, e := nodeadoption.ReadInput(*planPath, 1<<20)
	if e != nil {
		return fail()
	}
	var rawConfig []byte
	if args[0] == "inspect" || args[0] == "stage" {
		rawConfig, e = nodeadoption.ReadInput(*configPath, 4<<20)
		if e != nil {
			return fail()
		}
	}
	var bundle *nodeadoption.Bundle
	if args[0] == "inspect" {
		var plan nodeadoption.InspectionPlan
		if nodeadoption.DecodePlan(rawPlan, &plan) != nil {
			return fail()
		}
		inspection, e := nodeadoption.Inspect(plan, rawConfig)
		if e != nil {
			return fail()
		}
		bundle = inspection.PublicBundle()
	} else if args[0] == "stage" {
		var plan nodeadoption.StagePlan
		if nodeadoption.DecodePlan(rawPlan, &plan) != nil {
			return fail()
		}
		bundle, e = nodeadoption.Stage(plan, rawConfig)
		if e != nil {
			return fail()
		}
	} else {
		var request nodeadoption.PlanningRequest
		if nodeadoption.DecodePlan(rawPlan, &request) != nil {
			return fail()
		}
		inventory, e := nodeadoption.ReadInput(*inventoryPath, remnawave.MaxInventoryBytes)
		if e != nil {
			return fail()
		}
		if args[0] == "plan-inspection" {
			bundle, e = nodeadoption.PlanInspection(request, inventory)
		} else {
			load := func(name string, v any) error {
				raw, e := nodeadoption.ReadInput(name, 1<<20)
				if e != nil {
					return e
				}
				return nodeadoption.DecodePlan(raw, v)
			}
			var inspection nodeadoption.Inspection
			var certificates []nodeadoption.Certificate
			if load(*inspectionPath, &inspection) != nil {
				return fail()
			}
			var certificateBytes []byte
			certificateBytes, e = nodeadoption.ReadInput(*certificatesPath, 1<<20)
			if e != nil {
				return fail()
			}
			certificates, e = nodeadoption.DecodeCertificateResponses(certificateBytes)
			if e != nil {
				return fail()
			}
			if args[0] == "plan-preparation" {
				bundle, e = nodeadoption.PlanPreparation(request, inventory, inspection, certificates)
			} else {
				var preparation nodeadoption.Preparation
				if load(*preparationPath, &preparation) != nil {
					return fail()
				}
				bundle, e = nodeadoption.PlanStage(request, inventory, inspection, preparation, certificates)
			}
		}
		if e != nil {
			return fail()
		}
	}
	result, e := nodeadoption.Publish(*out, bundle)
	if e != nil {
		return fail()
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return fail()
	}
	return 0
}
func main() { os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr, os.Geteuid())) }
