package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type RSAKeys struct {
	DecKey userlib.PKEDecKey
	SigKey userlib.DSSignKey
}

type User struct {
	Username      string
	keychainUUID  uuid.UUID
	passkey       []byte
	fileAccessKey []byte
	mac           []byte
	keychain      RSAKeys
}

type SignedData struct {
	Data      []byte
	Signature []byte
}

type KeyStoreType int8

const (
	KeyTypeEnc KeyStoreType = 0
	KeyTypeVer KeyStoreType = 1
)

func _DeriveKeyInfoFromUserdata(username string, password string) (userdataptr *User, err error) {
	var userdata User

	var entropy []byte = userlib.Argon2Key([]byte(password), []byte(username), 16)

	var hashSeed []byte = userlib.SymEnc(entropy, userlib.Hash([]byte(username))[:16], userlib.Hash([]byte(password)))
	userdata.keychainUUID, err = uuid.FromBytes(userlib.Hash(hashSeed)[:16])
	if err != nil {
		return nil, err
	}

	userdata.passkey, err = userlib.HashKDF(entropy, []byte("Key to encrypt Keychain"))
	if err != nil {
		return nil, err
	}

	userdata.passkey = userdata.passkey[:16]

	userdata.fileAccessKey, err = userlib.HashKDF(entropy, []byte("Key to encrypt file access struct"))
	if err != nil {
		return nil, err
	}

	userdata.fileAccessKey = userdata.fileAccessKey[:16]

	userdata.mac, err = userlib.HashKDF(entropy, []byte("User MAC"))
	if err != nil {
		return nil, err
	}

	userdata.mac = userdata.mac[:16]

	return &userdata, nil
}

func _GetUserKeyStoreEntry(username string, keyType KeyStoreType) (keyLoc string, err error) {
	var keyTypeStr string

	if keyType == KeyTypeEnc {
		keyTypeStr = "Enc"
	} else if keyType == KeyTypeVer {
		keyTypeStr = "Ver"
	}

	var typeHash string = string(userlib.Hash([]byte(keyTypeStr)))
	var usernameHash string = string(userlib.Hash([]byte(username)))

	return string(userlib.Hash([]byte(typeHash + usernameHash))[:16]), nil
}

func _DatastoreSetWithSignature(key uuid.UUID, value []byte, macKey []byte) (err error) {
	var payload SignedData
	payload.Data = value
	payload.Signature, err = userlib.HMACEval(macKey, value)
	if err != nil {
		return err
	}

	var payloadData []byte
	payloadData, err = json.Marshal(payload)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(key, payloadData)

	return nil
}

func _DatastoreGetWithSignature(key uuid.UUID, macKey []byte) (value []byte, ok bool, err error) {
	var payloadData []byte
	payloadData, ok = userlib.DatastoreGet(key)
	if !ok {
		return nil, ok, nil
	}

	var payload SignedData
	err = json.Unmarshal(payloadData, &payload)
	if err != nil {
		return nil, ok, err
	}

	var mySignature []byte
	mySignature, err = userlib.HMACEval(macKey, payload.Data)
	if err != nil {
		return nil, ok, err
	}

	if !userlib.HMACEqual(mySignature, payload.Signature) {
		return nil, ok, errors.New(strings.ToTitle("HMAC Signature mismatch!"))
	}

	return payload.Data, ok, nil
}

func _DatastoreSetSecure(key uuid.UUID, value []byte, macKey []byte, encKey []byte) (err error) {
	return _DatastoreSetWithSignature(
		key,
		userlib.SymEnc(
			encKey,
			userlib.RandomBytes(16),
			value),
		macKey)
}

func _DatastoreGetSecure(key uuid.UUID, macKey []byte, encKey []byte) (value []byte, ok bool, err error) {
	var ciphertext []byte
	ciphertext, ok, err = _DatastoreGetWithSignature(key, macKey)
	if err != nil || !ok {
		return nil, ok, err
	}

	return userlib.SymDec(encKey, ciphertext), ok, nil
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata *User

	userdata, err = _DeriveKeyInfoFromUserdata(username, password)
	if err != nil {
		return nil, err
	}

	var pubEncKey userlib.PKEEncKey
	var pubVerKey userlib.DSVerifyKey

	pubEncKey, userdata.keychain.DecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.keychain.SigKey, pubVerKey, err = userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	var pubEncKeyLoc string
	var pubVerKeyLoc string

	pubEncKeyLoc, err = _GetUserKeyStoreEntry(username, KeyTypeEnc)
	if err != nil {
		return nil, err
	}

	pubVerKeyLoc, err = _GetUserKeyStoreEntry(username, KeyTypeVer)
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(pubEncKeyLoc, pubEncKey)
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet(pubVerKeyLoc, pubVerKey)
	if err != nil {
		return nil, err
	}

	var keychainData []byte
	keychainData, err = json.Marshal(userdata.keychain)
	if err != nil {
		return nil, err
	}

	err = _DatastoreSetSecure(
		userdata.keychainUUID,
		keychainData,
		userdata.mac,
		userdata.passkey)

	if err != nil {
		return nil, err
	}

	return userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata *User

	userdata, err = _DeriveKeyInfoFromUserdata(username, password)
	if err != nil {
		return nil, err
	}

	var keychainData []byte
	var ok bool
	keychainData, ok, err = _DatastoreGetSecure(
		userdata.keychainUUID,
		userdata.mac,
		userdata.passkey)
	if err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("KeyChain file not found")
	}

	err = json.Unmarshal(keychainData, &userdata.keychain)
	return userdata, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	return
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	return nil
}
