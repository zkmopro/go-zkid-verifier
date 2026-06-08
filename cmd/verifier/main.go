package main

import (
	"fmt"
	"log"
	"os"

	"github.com/privacy-ethereum/go-zkid-verifier/verifier"
)

func main() {
	baseDir := os.Getenv("ZK_BASE_DIR")
	if baseDir == "" {
		var err error
		baseDir, err = os.Getwd()
		if err != nil {
			log.Fatalf("getwd: %v", err)
		}
	}

	certChainType := verifier.CertChainRS2048
	for _, arg := range os.Args[1:] {
		if arg == "--cert-chain-4096" || arg == "-4" {
			certChainType = verifier.CertChainRS4096
		}
	}

	typeName := "cert_chain_rs2048 + user_sig_rs2048"
	if certChainType == verifier.CertChainRS4096 {
		typeName = "cert_chain_rs4096 + user_sig_rs2048"
	}

	fmt.Printf("=== zkID Link Verifier ===\n")
	fmt.Printf("Base directory: %s\n", baseDir)
	fmt.Printf("Verification type: %s\n", typeName)
	fmt.Printf("Reading artifacts from: %s/keys/\n\n", baseDir)

	valid, signals, err := verifier.LinkVerify(baseDir, certChainType)
	if err != nil {
		log.Fatalf("Link-verify failed: %v", err)
	}

	if valid {
		fmt.Println("Link verification PASSED: pk_commit_A == pk_commit_B")
		if signals != nil {
			fmt.Printf("Cert-chain public values: %v\n", signals.CertChain)
			fmt.Printf("User-sig public values: %v\n", signals.UserSig)
		}
	} else {
		fmt.Println("Link verification FAILED: pk_commit mismatch")
		os.Exit(1)
	}
}
