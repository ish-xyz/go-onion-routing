package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

var (
	nodesDB = map[string]string{}
	iv      = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
)

const (
	directory = "./nodes.db"
)

func main() {
	msg, jumphosts := initMsg("node12", "hello")

	fmt.Printf("Sending encrypted message %s\n\n\n", msg)
	simulation(msg, jumphosts)

	return
}

func initMsg(dst, msg string) (string, int) {
	nodes := getRandomNodes(9, dst)
	nodes[0] = dst
	var encMsg string
	encMsg = msg

	for i, node := range nodes {
		key := nodesDB[node]
		if i > 0 {
			encMsg = fmt.Sprintf("%s:%s", nodes[i-1], encMsg)
		}
		encMsg = encrypt(key, encMsg)
	}
	return nodes[len(nodes)-1] + ":" + encMsg, len(nodes)
}

func simulation(msg string, jumphosts int) {

	fmt.Printf("Starting onion simulation...\n\n")
	time.Sleep(2 * time.Second)
	plainMsg := msg
	for i := 0; i != jumphosts; i++ {

		node := strings.Split(plainMsg, ":")[0]
		text := strings.Split(plainMsg, ":")[1]

		fmt.Printf("Passing encrypted message to %s\n\n", node)
		time.Sleep(2 * time.Second)

		fmt.Printf("Decrypting message: %s\n\n", text)
		time.Sleep(2 * time.Second)
		plainMsg = decrypt(nodesDB[node], text)
	}

	fmt.Printf("Message received: %s\n\n", plainMsg)
	return
}

func getRandomNodes(minNodes int, dstNode string) []string {
	//Get random nodes from DB
	selectedNodes := []string{""}
	_ = loadNodes()
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	// Loop until it gets to 9 nodes
	for len(selectedNodes) <= minNodes {
		randomNumber := r1.Intn(300)
		selnode := "node" + fmt.Sprintf("%d", randomNumber)
		if dstNode != selnode {
			selectedNodes = append(selectedNodes, selnode)
		}
	}

	return selectedNodes

}

func loadNodes() map[string]string {

	file, err := os.Open(directory)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		nodeInfo := strings.Split(string(scanner.Text()), " ")
		nodesDB[nodeInfo[0]] = nodeInfo[1]
	}
	return nodesDB
}

func decrypt(key, text string) string {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	ciphertext := decodeBase64(text)
	cfb := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return string(plaintext)
}

func encrypt(key, text string) string {

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	plaintext := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)
	return encodeBase64(ciphertext)
}

func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}
