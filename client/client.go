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
	Username     string
	keychainUUID uuid.UUID
	entropy      []byte
	keychainKey  []byte
	keychain     RSAKeys
}

type FileInvite struct {
	Access uuid.UUID
	Key    []byte
}

type SharedUser struct {
	Username string
	Access   uuid.UUID
	Key      []byte
}

type FileAccess struct {
	Redirect    bool
	Metadata    uuid.UUID
	SharedUsers []SharedUser
	Key         []byte
}

type FileMetaData struct {
	Size  int
	First uuid.UUID
	Last  uuid.UUID
}

type FileSector struct {
	Size int
	Data []byte
	Next uuid.UUID
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

	userdata.entropy = userlib.Argon2Key([]byte(password), []byte(username), 16)

	var hashSeed []byte = userlib.SymEnc(userdata.entropy, userlib.Hash([]byte(username))[:16], userlib.Hash([]byte(password)))
	userdata.keychainUUID, err = uuid.FromBytes(userlib.Hash(hashSeed)[:16])
	if err != nil {
		return nil, err
	}

	userdata.keychainKey, err = userlib.HashKDF(userdata.entropy, []byte("Key to encrypt and sign Keychain"))
	if err != nil {
		return nil, err
	}

	userdata.keychainKey = userdata.keychainKey[:32]

	return &userdata, nil
}

func __GetKeyForKeyStore(username string, keyType KeyStoreType) (key string) {
	var keyTypeStr string

	if keyType == KeyTypeEnc {
		keyTypeStr = "Enc"
	} else if keyType == KeyTypeVer {
		keyTypeStr = "Ver"
	}

	var typeHash string = string(userlib.Hash([]byte(keyTypeStr)))
	var usernameHash string = string(userlib.Hash([]byte(username)))

	return string(userlib.Hash([]byte(typeHash + usernameHash))[:16])
}

func _KeyStoreSet(username string, keyType KeyStoreType, value userlib.PublicKeyType) (err error) {
	return userlib.KeystoreSet(__GetKeyForKeyStore(username, keyType), value)
}

func _KeyStoreGet(username string, keyType KeyStoreType) (value userlib.PublicKeyType, err error) {
	result, ok := userlib.KeystoreGet(__GetKeyForKeyStore(username, keyType))
	if !ok {
		return userlib.PublicKeyType{}, errors.New("could not find key for user '" + username + "'")
	}

	return result, nil
}

func _DatastoreSetSecure(location uuid.UUID, value any, key []byte) (err error) {
	storeBuff, err := json.Marshal(value)
	if err != nil {
		return err
	}

	var payload SignedData
	payload.Data = userlib.SymEnc(key[0:16], userlib.RandomBytes(16), storeBuff)
	payload.Signature, err = userlib.HMACEval(key[16:32], payload.Data)
	if err != nil {
		return err
	}

	payloadData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	userlib.DatastoreSet(location, payloadData)

	return nil
}

func _DatastoreGetSecure(location uuid.UUID, value any, key []byte) (err error) {
	payloadData, ok := userlib.DatastoreGet(location)
	if !ok {
		return errors.New("entry not found in datastore")
	}

	var payload SignedData
	err = json.Unmarshal(payloadData, &payload)
	if err != nil {
		return err
	}

	mySignature, err := userlib.HMACEval(key[16:32], payload.Data)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(mySignature, payload.Signature) {
		return errors.New(strings.ToTitle("HMAC Signature mismatch!"))
	}

	return json.Unmarshal(userlib.SymDec(key[0:16], payload.Data), value)
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	userdata, err := _DeriveKeyInfoFromUserdata(username, password)
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

	err = _KeyStoreSet(username, KeyTypeEnc, pubEncKey)
	if err != nil {
		return nil, err
	}

	err = _KeyStoreSet(username, KeyTypeVer, pubVerKey)
	if err != nil {
		return nil, err
	}

	return userdata, _DatastoreSetSecure(userdata.keychainUUID, userdata.keychain, userdata.keychainKey)
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	userdata, err := _DeriveKeyInfoFromUserdata(username, password)
	if err != nil {
		return nil, err
	}

	return userdata, _DatastoreGetSecure(userdata.keychainUUID, &userdata.keychain, userdata.keychainKey)
}

func _DeriveFileInfo(userdata *User, filename string) (fileUUID uuid.UUID, accessKey []byte, shareKey []byte, err error) {
	var hashSeed = string(userlib.Hash([]byte(filename))) + string(userlib.Hash([]byte(userdata.Username)))
	fileUUID, err = uuid.FromBytes(userlib.Hash([]byte(hashSeed))[:16])
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	resultKey, err := userlib.HashKDF(userdata.entropy, []byte("Key to encrypt and sign file with hash seed"+hashSeed))
	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	return fileUUID, resultKey[0:32], resultKey[32:64], nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	fileUUID, accessKey, _, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return err
	}

	var access FileAccess
	access.Key = userlib.RandomBytes(32)
	access.Metadata = uuid.New()
	access.Redirect = false

	var metadata FileMetaData
	metadata.First = uuid.New()
	metadata.Last = uuid.New()
	metadata.Size = len(content)

	var sector FileSector
	sector.Data = content
	sector.Next = metadata.Last
	sector.Size = len(content)

	var lastSector FileSector
	lastSector.Data = nil
	lastSector.Next = uuid.Nil
	lastSector.Size = 0

	err = _DatastoreSetSecure(fileUUID, access, accessKey)
	if err != nil {
		return err
	}

	err = _DatastoreSetSecure(access.Metadata, metadata, access.Key)
	if err != nil {
		return err
	}

	err = _DatastoreSetSecure(metadata.First, sector, access.Key)
	if err != nil {
		return err
	}

	return _DatastoreSetSecure(metadata.Last, lastSector, access.Key)
}

func _GetAccess(userdata *User, filename string) (access *FileAccess, share *FileAccess, err error) {
	fileUUID, accessKey, _, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return nil, nil, err
	}

	var rootAccess FileAccess
	err = _DatastoreGetSecure(fileUUID, &rootAccess, accessKey)
	if err != nil {
		return nil, nil, err
	}

	if !rootAccess.Redirect {
		return &rootAccess, nil, nil
	}

	var shareAccess FileAccess
	err = _DatastoreGetSecure(rootAccess.Metadata, &shareAccess, rootAccess.Key)
	if err != nil {
		return nil, nil, err
	}

	return &shareAccess, &rootAccess, nil
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	access, _, err := _GetAccess(userdata, filename)
	if err != nil {
		return err
	}

	var metadata FileMetaData
	err = _DatastoreGetSecure(access.Metadata, &metadata, access.Key)
	if err != nil {
		return err
	}

	var sector FileSector
	sector.Data = content
	sector.Size = len(content)
	sector.Next = uuid.New()

	err = _DatastoreSetSecure(metadata.Last, sector, access.Key)
	if err != nil {
		return err
	}

	metadata.Size = metadata.Size + len(content)
	metadata.Last = sector.Next

	err = _DatastoreSetSecure(access.Metadata, metadata, access.Key)
	if err != nil {
		return err
	}

	var lastSector FileSector
	lastSector.Data = nil
	lastSector.Next = uuid.Nil
	lastSector.Size = 0
	return _DatastoreSetSecure(metadata.Last, lastSector, access.Key)
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	access, _, err := _GetAccess(userdata, filename)
	if err != nil {
		return nil, err
	}

	var metadata FileMetaData
	err = _DatastoreGetSecure(access.Metadata, &metadata, access.Key)
	if err != nil {
		return nil, err
	}

	var currentUUID uuid.UUID = metadata.First

	for currentUUID != uuid.Nil {
		var sector FileSector
		err = _DatastoreGetSecure(currentUUID, &sector, access.Key)
		if err != nil {
			return nil, err
		}

		content = append(content[:], sector.Data...)

		currentUUID = sector.Next
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	var invite FileInvite
	access, share, err := _GetAccess(userdata, filename)
	if err != nil {
		return uuid.Nil, err
	}

	if share == nil {
		invite.Key = userlib.RandomBytes(32)
		invite.Access = uuid.New()

		var shareAccess FileAccess
		shareAccess.Key = access.Key
		shareAccess.Metadata = access.Metadata

		err = _DatastoreSetSecure(invite.Access, shareAccess, invite.Key)
		if err != nil {
			return uuid.Nil, err
		}

		var sharedUser SharedUser
		sharedUser.Access = invite.Access
		sharedUser.Key = invite.Key
		sharedUser.Username = recipientUsername

		access.SharedUsers = append(access.SharedUsers[:], sharedUser)

		fileUUID, accessKey, _, err := _DeriveFileInfo(userdata, filename)
		if err != nil {
			return uuid.Nil, err
		}

		err = _DatastoreSetSecure(fileUUID, access, accessKey)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		invite.Key = share.Key
		invite.Access = share.Metadata
	}

	invitationPtr = uuid.New()

	storeBuff, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, err
	}

	pubEncKey, err := _KeyStoreGet(recipientUsername, KeyTypeEnc)
	if err != nil {
		return uuid.Nil, err
	}

	var payload SignedData

	payload.Data, err = userlib.PKEEnc(pubEncKey, storeBuff)
	if err != nil {
		return uuid.Nil, err
	}

	payload.Signature, err = userlib.DSSign(userdata.keychain.SigKey, payload.Data)
	if err != nil {
		return uuid.Nil, err
	}

	storeBuff, err = json.Marshal(payload)
	if err != nil {
		return uuid.Nil, err
	}

	userlib.DatastoreSet(invitationPtr, storeBuff)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	fileUUID, accessKey, _, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return err
	}

	loadBuff, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invite not found")
	}

	var payload SignedData
	err = json.Unmarshal(loadBuff, &payload)
	if err != nil {
		return err
	}

	pubVerKey, err := _KeyStoreGet(senderUsername, KeyTypeVer)
	if err != nil {
		return err
	}

	err = userlib.DSVerify(pubVerKey, payload.Data, payload.Signature)
	if err != nil {
		return err
	}

	loadBuff, err = userlib.PKEDec(userdata.keychain.DecKey, payload.Data)
	if err != nil {
		return err
	}

	var invite FileInvite
	err = json.Unmarshal(loadBuff, &invite)
	if err != nil {
		return err
	}

	var redirectAccess FileAccess
	redirectAccess.Key = invite.Key
	redirectAccess.Redirect = true
	redirectAccess.Metadata = invite.Access
	return _DatastoreSetSecure(fileUUID, redirectAccess, accessKey)
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	access, _, err := _GetAccess(userdata, filename)
	if err != nil {
		return err
	}

	var oldSharedusers = access.SharedUsers

	userlib.DatastoreSet(access.Metadata, []byte("Nice try nerds"))

	userdata.StoreFile(filename, content)

	access, _, err = _GetAccess(userdata, filename)
	if err != nil {
		return err
	}

	var shareAccess FileAccess
	shareAccess.Key = access.Key
	shareAccess.Redirect = false
	shareAccess.Metadata = access.Metadata

	var i = 0
	for i < len(oldSharedusers) {
		if oldSharedusers[i].Username != recipientUsername {
			err = _DatastoreSetSecure(oldSharedusers[i].Access, shareAccess, oldSharedusers[i].Key)
			if err != nil {
				return err
			}

			access.SharedUsers = append(access.SharedUsers[:], oldSharedusers[i])
		}

		i = i + 1
	}

	fileUUID, accessKey, _, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return err
	}

	err = _DatastoreSetSecure(fileUUID, access, accessKey)
	if err != nil {
		return err
	}

	return nil
}
