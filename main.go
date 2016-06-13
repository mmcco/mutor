/*
 * Copyright (c) 2016 Michael McConville <mmcco@mykolab.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
)

// the length of the stream cipher's key, in bytes
const KEY_LEN = 16

// the length of a public-key encrypted message, in bytes
const PK_ENC_LEN = 128

// the number of bytes added in padding for public-key encryption, in bytes
const PK_PAD_LEN = 42

// the largest number of bytes that can be encrypted in a single public-key
// operation is therefore PK_ENC_LEN-PK_PAD_LEN
const PK_MAX_BUF = PK_ENC_LEN - PK_PAD_LEN

// the number of bytes used to represent a member of the Diffie-Hellman group
const DH_LEN = 128

// the number of bytes used in a Diffie-Hellman private key (x)
const DH_SEC_LEN = 40

// the length of the hash function's output, in bytes
const HASH_LEN = 20

// the longest allowable cell payload, in bytes
const PAYLOAD_LEN = 509

// TODO: struct of relay keys

// Per the spec, we don't use client certificates and therefore don't support
// v1 handshakes. Because we are client-focused, we only support v3 handshakes.

// the length of a Tor cell, in bytes, for link protocol version v
func CELL_LEN(v int) uint64 {
	if v < 4 {
		return 512
	} else {
		return 514
	}
}

func hybrid_encrypt(m []byte, pk crypto.PublicKey) []byte {
	if len(m) < PK_ENC_LEN-PK_PAD_LEN {
		// pad and encrypt M with PK
		return []byte{0}
	} else {
		// generate a KEY_LEN byte random key K
		return []byte{1}
	}
}

func intSliceEq(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func connect(addr net.TCPAddr) (*tls.Conn, error) {
	conn, err := tls.Dial("tcp", addr.String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	selfSigned := len(certs) == 1 &&
		bytes.Equal(certs[0].SubjectKeyId, certs[0].AuthorityKeyId)

	/*
		for _, cert := range(certs) {
			for _, av := range(cert.Subject.Names) {
				t := av.Type
				fmt.Printf("%s\t", t.String())
				if intSliceEq(t, []int{2, 5, 4, 3}) {
					fmt.Print("TRUE!\t")
				}
				print(av.Value)
				fmt.Print("\n")
			}
		}
	*/
	otherNameField := false
	for _, av := range certs[0].Subject.Names {
		if intSliceEq(av.Type, []int{2, 5, 4, 3}) {
			otherNameField = true
		}
	}

	subjName := []byte(certs[0].Subject.CommonName)
	issuerName := []byte(certs[0].Issuer.CommonName)
	nonNet := bytes.HasSuffix(subjName, []byte(".net")) ||
		bytes.HasSuffix(issuerName, []byte(".net"))

	bigKey := false
	switch pk := certs[0].PublicKey.(type) {
	case rsa.PublicKey:
		bigKey = pk.N.BitLen() > 1024
	default:
		// XXX: log warning
	}

	if !selfSigned && !otherNameField && !bigKey && !nonNet {
		return nil, errors.New("none of initial cert requirements met")
	} else {
		return conn, nil
	}
}

func main() {
	// XXX: IPv6?
	//ip, err := net.ResolveIPAddr("ip4", "tor.exit-no.de")
	ip, err := net.ResolveIPAddr("ip4", "www.sccs.swarthmore.edu")
	if err != nil {
		log.Fatalln("failed to resolve IP addr")
	}
	addr := net.TCPAddr{ip.IP, 443, ""}

	_, err = connect(addr)
	if err != nil {
		log.Fatalln(err)
	} else {
		fmt.Println("worked")
	}
}
