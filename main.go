package main

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	dgoogauth "github.com/dgryski/dgoogauth"
	"github.com/gorilla/mux"
	"rsc.io/qr"
)

// QrCode struct
type QrCode struct {
	Account      string `json:"account"`
	Issuer       string `json:"issuer"`
	CodeFileName string `json:"-"`
	Token        string `json:"token" validate:"numeric"`
}

var secret = []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF}
var secretBase32 = base32.StdEncoding.EncodeToString(secret)
var account = "user@example.com"
var issuer = "NameOfMyService"

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/", homeHandler).Methods(http.MethodPost)
	r.HandleFunc("/create", generateCodeHandler).Methods(http.MethodPost)
	r.HandleFunc("/check", checkHandler).Methods(http.MethodPost)
	http.ListenAndServe(":80", r)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hello from QR 2fa.")
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		log.Fatal("Unable to read request data")
		panic(err)
	}

	var qrCode QrCode
	if err = json.Unmarshal(body, &qrCode); err != nil {
		panic(err)
	}

	otpc := &dgoogauth.OTPConfig{
		Secret:      secretBase32,
		WindowSize:  3,
		HotpCounter: 0,
		UTC:         true,
	}

	val, err := otpc.Authenticate(qrCode.Token)
	if err != nil {
		fmt.Println(err)
		jsonResponse(w, []byte(`{"error":`+err.Error()), http.StatusOK)
		return
	}

	if !val {
		jsonResponse(w, []byte(`{"error":"Sorry, Not Authenticated"}`), http.StatusOK)
		return
	}

	jsonResponse(w, []byte(`"ok":"Authenticated!"`), http.StatusOK)
}

func generateCodeHandler(w http.ResponseWriter, r *http.Request) {
	const (
		qrFilename = "./build/qr-code.png"
	)
	// Example secret from here:
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format

	// secret := []byte{'H', 'e', 'l', 'l', 'o', '!', 0xDE, 0xAD, 0xBE, 0xEF}

	// Generate random secret instead of using the test value above.
	// secret := make([]byte, 10)
	// _, err := rand.Read(secret)

	// if err != nil {
	// 	panic(err)
	// }

	URL, err := url.Parse("otpauth://totp")
	if err != nil {
		panic(err)
	}

	URL.Path += "/" + url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Add("secret", secretBase32)
	params.Add("issuer", issuer)

	URL.RawQuery = params.Encode()
	fmt.Printf("URL is %s\n", URL.String())

	code, err := qr.Encode(URL.String(), qr.Q)
	if err != nil {
		panic(err)
	}
	b := code.PNG()
	err = ioutil.WriteFile(qrFilename, b, 0600)
	if err != nil {
		panic(err)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "QR code has been generated in %s. Please scan it into Google Authenticator app.\n", qrFilename)
}

func jsonResponse(w http.ResponseWriter, content []byte, status int) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	w.Write(content)
}
