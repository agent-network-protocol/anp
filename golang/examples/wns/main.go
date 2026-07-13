package main

import (
	"fmt"
	"log"

	"github.com/agent-network-protocol/anp/golang/wns"
)

func main() {
	localPart, domain, err := wns.ValidateHandle("Alice.Example.COM")
	if err != nil {
		log.Fatalf("ValidateHandle failed: %v", err)
	}
	fmt.Println("normalized handle:", localPart+"."+domain)
	fmt.Println("resolution url:", wns.BuildResolutionURL(localPart, domain))
	uri := wns.BuildWBAURI(localPart, domain)
	parsed, err := wns.ParseWBAURI(uri)
	if err != nil {
		log.Fatalf("ParseWBAURI failed: %v", err)
	}
	fmt.Println("parsed URI handle:", parsed.Handle)
	service := wns.BuildHandleServiceEntry("did:wba:example.com:user:alice", localPart, domain)
	fmt.Printf("ANPHandleService entry: %+v\n", service)
	previous, err := wns.ParseBindingGeneration("8")
	if err != nil {
		log.Fatalf("ParseBindingGeneration failed: %v", err)
	}
	current, err := wns.ParseBindingGeneration("9")
	if err != nil {
		log.Fatalf("ParseBindingGeneration failed: %v", err)
	}
	fmt.Println("binding generation:", current, "newer than", previous, current.IsNewerThan(previous))
}
