// Original copyright:
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Generate a self-signed X.509 certificate for a TLS server.
// Writes to 'cert.pem' and 'key.pem', and overwrites existing files.
//
// THIS version uses defaults: RSA 2048-bit, self-signed,
// for three months, for "localhost,127.0.0.1, ::1". 

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
	"fmt"
)

// NONE of these are pointers (unlike in the code it is adapted from) 
var (
	host = "localhost,127.0.0.1,::1"
	validFrom string 
	validFor time.Duration = 91*24*time.Hour // 3 months
	isCA = true
	rsaBits = 2048
)

func barfs(s string) {
     println(s)
     os.Exit(1)
}

func barfe(s string, e error) {
     fmt.Printf(s + ": " + e.Error())
     os.Exit(1)
}

func main() {
	var priv *rsa.PrivateKey
	var err error
	fmt.Printf("Using defaults: rsa.GenKey(%d) \n", rsaBits)
	priv, err = rsa.GenerateKey(rand.Reader, rsaBits)
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
	println("Setting bits for x509.KeyUsageKeyEncipherment")
	keyUsage |= x509.KeyUsageKeyEncipherment

	var notBefore = time.Now()
	notAfter := notBefore.Add(validFor)

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

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	if isCA {
		template.IsCA = true
	      	println("Is CA, so setting bit for x509.KeyUsageCertSign")
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	derBytes, err := x509.CreateCertificate(
		  rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		barfe("Cannot create certificate", err)
	}

	certOut, err := os.Create("simpleSScert.pem")
	if err != nil {
		barfe("Cannot open simpleSScert.pem for writing", err)
	}
	if err := pem.Encode(certOut, &pem.Block{
	   Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		barfe("Cannot write to simpleSScert.pem", err)
	}
	if err := certOut.Close(); err != nil {
		barfe("Error closing simpleSScert.pem", err)
	}
	println("Wrote simpleSScert.pem")

	keyOut, err := os.OpenFile("simpleSSkey.pem",
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		barfe("Cannot open simpleSSkey.pem for writing", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		barfe("Cannot marshal private key", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		barfe("Cannot write to simpleSSkey.pem", err)
	}
	if err := keyOut.Close(); err != nil {
		barfe("Error closing simpleSSkey.pem", err)
	}
	println("Wrote simpleSSkey.pem")
}
