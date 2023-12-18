// Original copyright:
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server.
// Writes to 'cert.pem' and 'key.pem', and overwrites existing files.

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
	"fmt"
)

// ALL variables are pointers ! 
var (
	host = flag.String("host", "",
	     "Comma-sep'd hostnames & IPs to generate cert for")
	validFrom = flag.String("start-date", "",
		  "Creation date formatted as Jan 1 15:04:05 2011")
	validFor  = flag.Duration("duration", 365*24*time.Hour, // 1 year 
		  "Duration that certificate is valid for")
	isCA = flag.Bool("ca", false,
	     "whether this cert should be its own Certificate Authority")
	rsaBits = flag.Int("rsa-bits", 2048,
		"Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "",
		   "ECDSA curve to use to generate a key. Valid values " +
		   "are P224, P256 (recommended), P384, P521")
	ed25519Key = flag.Bool("ed25519", false, "Generate an Ed25519 key")
)

func barfs(s string) {
     println(s)
     os.Exit(1)
}

func barfe(s string, e error) {
     fmt.Printf(s + ": " + e.Error())
     os.Exit(1)
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func main() {
    if len(os.Args) < 2 {
     		flag.Usage()
		os.Exit(0)
	}
	flag.Parse()

	if len(*host) == 0 {
		barfs("Missing required --host parameter")
	}

	fmt.Printf("Inputs: " +
		"host:%s valid:%s:%v CA:%t nrRsa:%d ecdsa:%s ed25519:%t \n",
		*host, *validFrom, *validFor, *isCA, *rsaBits,
		*ecdsaCurve, *ed25519Key)

	var priv any
	var err error
	switch *ecdsaCurve {
	case "":
		if *ed25519Key {
			_, priv, err = ed25519.GenerateKey(rand.Reader)
		} else {
		        fmt.Printf("Using defaults: rsa.GenKey(%d) \n", *rsaBits)
			priv, err = rsa.GenerateKey(rand.Reader, *rsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		barfs(fmt.Sprintf("Unrecognized elliptic curve: %q", *ecdsaCurve))
	}
	if err != nil {
		barfe("Cannot generate private key", err) 
	}
	println("Generated private key OK")

	// ECDSA, ED25519, and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature
	
	// Only RSA subject keys should have the KeyEncipherment KeyUsage 
	// bits set. In the context of TLS this KeyUsage is particular to 
	// RSA key exchange and authentication.
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
	      	println("Setting bits for x509.KeyUsageKeyEncipherment")
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2006", *validFrom)
		if err != nil {
			barfe("Bad creation date", err) 
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		barfe("Cannot generate serial number", err) 
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:    keyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{
			       x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(*host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if *isCA {
		template.IsCA = true
	      	println("Is CA, so setting bit for x509.KeyUsageCertSign")
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(
		  rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		barfe("Cannot create certificate", err) 
	}

	certOut, err := os.Create("cert.pem")
	if err != nil {
		barfe("Cannot open cert.pem for writing", err) 
	}
	if err := pem.Encode(certOut, &pem.Block{
	   Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		barfe("Cannot write to cert.pem", err) 
	}
	if err := certOut.Close(); err != nil {
		barfe("Error closing cert.pem", err)
	}
	println("Wrote cert.pem")

	keyOut, err := os.OpenFile("key.pem",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		barfe("Cannot open key.pem for writing", err) 
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		barfe("Cannot marshal private key", err) 
	}
	if err := pem.Encode(keyOut, &pem.Block{
	   Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		barfe("Cannot write to key.pem", err) 
	}
	if err := keyOut.Close(); err != nil {
		barfe("Error closing key.pem", err) 
	}
	println("Wrote key.pem\n")
}
