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

	// Useful for formatting strings (e.g. `fmt.Sprintf`).

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type RSAKeys struct {
	DecKey userlib.PKEDecKey
	SigKey userlib.DSSignKey
}

type User struct {
	Username string
	entropy  []byte
	rsa      RSAKeys
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
	First uuid.UUID
	Last  uuid.UUID
}

type FileSector struct {
	Data []byte
	Next uuid.UUID
}

type KeyStoreType int8

const (
	KeyTypeEnc KeyStoreType = 0
	KeyTypeVer KeyStoreType = 1
)

func _DeriveEntropyFromUserdata(username string, password string) (userdataptr *User, rsaUUID uuid.UUID, rsaKey []byte, err error) {
	var userdata User

	userdata.Username = username
	userdata.entropy = userlib.Argon2Key([]byte(password), []byte(username), 16)

	var hashSeed []byte = userlib.SymEnc(userdata.entropy, userlib.Hash([]byte(username))[:16], userlib.Hash([]byte(password)))
	rsaUUID, err = uuid.FromBytes(userlib.Hash(hashSeed)[:16])
	if err != nil {
		return nil, uuid.Nil, nil, err
	}

	rsaKey, err = userlib.HashKDF(userdata.entropy, []byte("Key to encrypt and sign Keychain"))
	if err != nil {
		return nil, uuid.Nil, nil, err
	}

	return &userdata, rsaUUID, rsaKey, nil
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

func _DatastoreSet(location uuid.UUID, value interface{}, key []byte) (err error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}

	payload = userlib.SymEnc(key[0:16], userlib.RandomBytes(16), payload)
	hmacSig, err := userlib.HMACEval(key[16:32], payload)
	if err != nil {
		return err
	}

	payload = append(payload, hmacSig...)

	var paddingSize = 1 + int(userlib.RandomBytes(1)[0])%97
	var padding []byte = make([]byte, paddingSize)

	for i := 0; i < paddingSize; i++ {
		padding[i] = byte(paddingSize)
	}

	payload = append(padding, payload...)

	payload = userlib.SymEnc(key[32:48], userlib.RandomBytes(16), payload)

	marshalledPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	marshalledPayload = marshalledPayload[1 : len(marshalledPayload)-1]

	userlib.DatastoreSet(location, marshalledPayload)

	return nil
}

func _DatastoreGet(location uuid.UUID, value interface{}, key []byte) (err error) {
	marshalledPayload, ok := userlib.DatastoreGet(location)
	if !ok {
		return errors.New("entry not found in datastore")
	}

	marshalledPayload = append([]byte("\""), marshalledPayload...)
	marshalledPayload = append(marshalledPayload, []byte("\"")...)

	var payload []byte
	err = json.Unmarshal(marshalledPayload, &payload)
	if err != nil {
		return err
	}

	payload = userlib.SymDec(key[32:48], payload)

	var paddingSize = int(payload[0])

	payload = payload[paddingSize:]

	signature := payload[len(payload)-64:]
	payload = payload[:len(payload)-64]

	mySignature, err := userlib.HMACEval(key[16:32], payload)
	if err != nil {
		return err
	}

	if !userlib.HMACEqual(mySignature, signature) {
		return errors.New("hmac Signature mismatch")
	}

	return json.Unmarshal(userlib.SymDec(key[0:16], payload), value)
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if len(username) == 0 {
		return nil, errors.New("cannot have username of length 0")
	}

	userdata, rsaUUID, rsaKey, err := _DeriveEntropyFromUserdata(username, password)
	if err != nil {
		return nil, err
	}

	var pubEncKey userlib.PKEEncKey
	var pubVerKey userlib.DSVerifyKey

	pubEncKey, userdata.rsa.DecKey, err = userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}

	userdata.rsa.SigKey, pubVerKey, err = userlib.DSKeyGen()
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

	return userdata, _DatastoreSet(rsaUUID, userdata.rsa, rsaKey)
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	userdata, rsaUUID, rsaKey, err := _DeriveEntropyFromUserdata(username, password)
	if err != nil {
		return nil, err
	}

	return userdata, _DatastoreGet(rsaUUID, &userdata.rsa, rsaKey)
}

func _DeriveFileInfo(userdata *User, filename string) (fileUUID uuid.UUID, accessKey []byte, err error) {
	resultKey, err := userlib.HashKDF(userdata.entropy, []byte("Key to encrypt and sign file of "+userdata.Username+" with name "+filename))
	if err != nil {
		return uuid.Nil, nil, err
	}

	var fileHash = userlib.Hash([]byte(filename))
	var userHash = userlib.Hash([]byte(userdata.Username))
	var hashSeed = userlib.SymEnc(resultKey[48:64], userHash[:16], fileHash)
	fileUUID, err = uuid.FromBytes(userlib.Hash(hashSeed)[:16])
	if err != nil {
		return uuid.Nil, nil, err
	}

	return fileUUID, resultKey, nil
}

func _Exists(location uuid.UUID) (ok bool) {
	_, ok = userlib.DatastoreGet(location)
	return ok
}

func _GetAccess(userdata *User, filename string) (access *FileAccess, share *FileAccess, err error) {
	fileUUID, accessKey, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return nil, nil, err
	}

	var rootAccess FileAccess
	err = _DatastoreGet(fileUUID, &rootAccess, accessKey)
	if err != nil {
		return nil, nil, err
	}

	if !rootAccess.Redirect {
		return &rootAccess, nil, nil
	}

	var shareAccess FileAccess
	err = _DatastoreGet(rootAccess.Metadata, &shareAccess, rootAccess.Key)
	if err != nil {
		return nil, nil, err
	}

	return &shareAccess, &rootAccess, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	var access *FileAccess
	var metadata FileMetaData

	fileUUID, accessKey, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return err
	}

	if _Exists(fileUUID) {
		access, _, err = _GetAccess(userdata, filename)
		if err != nil {
			return err
		}

		err = _DatastoreGet(access.Metadata, &metadata, access.Key)
		if err != nil {
			return err
		}

	} else {
		var accessStackMem FileAccess
		access = &accessStackMem

		access.Key = userlib.RandomBytes(64)
		access.Metadata = uuid.New()
		access.Redirect = false

		err = _DatastoreSet(fileUUID, access, accessKey)
		if err != nil {
			return err
		}

		metadata.First = uuid.New()
		metadata.Last = uuid.New()
	}

	var sector FileSector
	sector.Data = content
	sector.Next = metadata.Last

	var lastSector FileSector
	lastSector.Data = nil
	lastSector.Next = uuid.Nil

	err = _DatastoreSet(access.Metadata, metadata, access.Key)
	if err != nil {
		return err
	}

	err = _DatastoreSet(metadata.First, sector, access.Key)
	if err != nil {
		return err
	}

	return _DatastoreSet(metadata.Last, lastSector, access.Key)
}

func (userdata *User) AppendToFile(filename string, content []byte) (err error) {
	access, _, err := _GetAccess(userdata, filename)
	if err != nil {
		return err
	}

	var metadata FileMetaData
	err = _DatastoreGet(access.Metadata, &metadata, access.Key)
	if err != nil {
		return err
	}

	var sector FileSector
	sector.Data = content
	sector.Next = uuid.New()

	err = _DatastoreSet(metadata.Last, sector, access.Key)
	if err != nil {
		return err
	}

	metadata.Last = sector.Next

	err = _DatastoreSet(access.Metadata, metadata, access.Key)
	if err != nil {
		return err
	}

	var lastSector FileSector
	lastSector.Data = nil
	lastSector.Next = uuid.Nil
	return _DatastoreSet(metadata.Last, lastSector, access.Key)
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	access, _, err := _GetAccess(userdata, filename)
	if err != nil {
		return nil, err
	}

	var metadata FileMetaData
	err = _DatastoreGet(access.Metadata, &metadata, access.Key)
	if err != nil {
		return nil, err
	}

	var currentUUID uuid.UUID = metadata.First

	for currentUUID != uuid.Nil {
		var sector FileSector
		err = _DatastoreGet(currentUUID, &sector, access.Key)
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
		invite.Key = userlib.RandomBytes(48)
		invite.Access = uuid.New()

		var shareAccess FileAccess
		shareAccess.Key = access.Key
		shareAccess.Metadata = access.Metadata

		err = _DatastoreSet(invite.Access, shareAccess, invite.Key)
		if err != nil {
			return uuid.Nil, err
		}

		var sharedUser SharedUser
		sharedUser.Access = invite.Access
		sharedUser.Key = invite.Key
		sharedUser.Username = recipientUsername

		access.SharedUsers = append(access.SharedUsers[:], sharedUser)

		fileUUID, accessKey, err := _DeriveFileInfo(userdata, filename)
		if err != nil {
			return uuid.Nil, err
		}

		err = _DatastoreSet(fileUUID, access, accessKey)
		if err != nil {
			return uuid.Nil, err
		}
	} else {
		invite.Key = share.Key
		invite.Access = share.Metadata
	}

	invitationPtr = uuid.New()

	payload, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, err
	}

	var inviteKey []byte = userlib.RandomBytes(32)

	payload = userlib.SymEnc(inviteKey[0:16], userlib.RandomBytes(16), payload)

	signature, err := userlib.DSSign(userdata.rsa.SigKey, payload)
	if err != nil {
		return uuid.Nil, err
	}

	payload = append(payload, signature...)

	var paddingSize = 1 + int(userlib.RandomBytes(1)[0])%97
	var padding []byte = make([]byte, paddingSize)

	for i := 0; i < paddingSize; i++ {
		padding[i] = byte(paddingSize)
	}

	payload = append(padding, payload...)

	payload = userlib.SymEnc(inviteKey[16:32], userlib.RandomBytes(16), payload)

	pubEncKey, err := _KeyStoreGet(recipientUsername, KeyTypeEnc)
	if err != nil {
		return uuid.Nil, err
	}

	encInviteKey, err := userlib.PKEEnc(pubEncKey, inviteKey)
	if err != nil {
		return uuid.Nil, err
	}

	payload = append(encInviteKey, payload...)

	marshalledPayload, err := json.Marshal(payload)
	if err != nil {
		return uuid.Nil, err
	}

	marshalledPayload = marshalledPayload[1 : len(marshalledPayload)-1]

	userlib.DatastoreSet(invitationPtr, marshalledPayload)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) (err error) {
	fileUUID, accessKey, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return err
	}

	if _Exists(fileUUID) {
		return errors.New("accepting invitation with used filename")
	}

	marshalledPayload, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("entry not found in datastore")
	}

	marshalledPayload = append([]byte("\""), marshalledPayload...)
	marshalledPayload = append(marshalledPayload, []byte("\"")...)

	var payload []byte
	err = json.Unmarshal(marshalledPayload, &payload)
	if err != nil {
		return err
	}

	inviteKey, err := userlib.PKEDec(userdata.rsa.DecKey, payload[:256])
	if err != nil {
		return err
	}

	payload = userlib.SymDec(inviteKey[16:32], payload[256:])

	var paddingSize = int(payload[0])

	payload = payload[paddingSize:]

	signature := payload[len(payload)-256:]
	payload = payload[:len(payload)-256]

	pubVerKey, err := _KeyStoreGet(senderUsername, KeyTypeVer)
	if err != nil {
		return err
	}

	err = userlib.DSVerify(pubVerKey, payload, signature)
	if err != nil {
		return err
	}

	loadBuff := userlib.SymDec(inviteKey[:16], payload)

	var invite FileInvite
	err = json.Unmarshal(loadBuff, &invite)
	if err != nil {
		return err
	}

	var redirectAccess FileAccess
	redirectAccess.Key = invite.Key
	redirectAccess.Redirect = true
	redirectAccess.Metadata = invite.Access

	var shareAccess FileAccess
	err = _DatastoreGet(invite.Access, &shareAccess, invite.Key)
	if err != nil {
		return err
	}

	var metadata FileMetaData
	err = _DatastoreGet(shareAccess.Metadata, &metadata, shareAccess.Key)
	if err != nil {
		return err
	}

	return _DatastoreSet(fileUUID, redirectAccess, accessKey)
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) (err error) {
	content, err := userdata.LoadFile(filename)
	if err != nil {
		return err
	}

	access, rootAccess, err := _GetAccess(userdata, filename)
	if err != nil {
		return err
	}

	if rootAccess != nil {
		return errors.New("attempt to revoke file despite not being file owner")
	}

	var oldSharedusers = access.SharedUsers

	fileUUID, accessKey, err := _DeriveFileInfo(userdata, filename)
	if err != nil {
		return err
	}

	userlib.DatastoreDelete(access.Metadata)
	userlib.DatastoreDelete(fileUUID)

	err = userdata.StoreFile(filename, content)
	if err != nil {
		return err
	}

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
			err = _DatastoreSet(oldSharedusers[i].Access, shareAccess, oldSharedusers[i].Key)
			if err != nil {
				return err
			}

			access.SharedUsers = append(access.SharedUsers[:], oldSharedusers[i])
		} else {
			userlib.DatastoreDelete(oldSharedusers[i].Access)
		}

		i = i + 1
	}

	err = _DatastoreSet(fileUUID, access, accessKey)
	if err != nil {
		return err
	}

	return nil
}
