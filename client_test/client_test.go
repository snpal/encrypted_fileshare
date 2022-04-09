package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	"errors"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

var measureBandwidth = func(probe func()) (bandwidth int) {
	before := userlib.DatastoreGetBandwidth()
	probe()
	after := userlib.DatastoreGetBandwidth()
	return after - before
}

func isCompromised(collected []byte, stored []byte) (compromised bool) {
	// even if collected contains more information than stored, collected containing stored compromises our security.
	// stored is chosen to be small in our test case to allow for various implementations storing contents differently
	if len(stored) > len(collected) {
		return false
	}
	for i, x := range stored {
		if x != collected[i] {
			return false
		}
	}
	return true
}

// func getUUIDs() (UUIDs []userlib.UUID) {
// 	// Returns an array of UUIDs currently stored in DataStore.
// 	// As a debugging measure for tests, currently also prints out each UUID in a new line.

// 			keys := make([]userlib.UUID, len(mymap))

// 			i := 0
// 			for k := range mymap {
// 				keys[i] = k
// 				i++
// 				println(k.String())
// 			}
// 	return keys
// }

//func getNewUUID(old map[userlib.UUID][]byte, new map[userlib.UUID][]byte) (UUID userlib.UUID) {
// Checks to find a UUID that exists in the new map but not in the old map.
//	var ans userlib.UUID
//	for k, _ := range new {
//		println("comparisons: key, is it in new, is it in old")
//		println(k.String())
//		_, ok := new[k]
//		println(ok)
//		_, ok = old[k]
//		println(ok)
//		if _, ok = old[k]; !ok {
//			ans = k
//		}
//	}
//	return ans
//}

func getNewUUIDs(probe func()) (newUUIDs []userlib.UUID) {
	var dsMap = userlib.DatastoreGetMap()

	var oldKeys []userlib.UUID

	for k := range dsMap {
		oldKeys = append(oldKeys, k)
		// println("Old: " + k.String())
	}

	probe()

	for k := range dsMap {
		var keyExists = false
		for j := 0; j < len(oldKeys); j++ {
			if oldKeys[j] == k {
				// println("Found Old Key: " + k.String())
				keyExists = true
			}
		}

		if !keyExists {
			newUUIDs = append(newUUIDs, k)
			// println("New Key: " + k.String())
		}
	}

	return newUUIDs
}

var shareWithManyUsers = func(alice *client.User, num int, newname string, filename string) {
	var i = 0
	for i < num {
		var userUID = string(userlib.RandomBytes(32))

		bob, err := client.InitUser(newname+userUID, defaultPassword)
		Expect(err).To(BeNil())

		//userlib.DebugMsg("Alice creating invite for " + newname + userUID)
		invite, err := alice.CreateInvitation(filename, newname+userUID)
		Expect(err).To(BeNil())

		//userlib.DebugMsg(newname+userUID+" accepts invite from Alice under filename %s.", bobFile)
		err = bob.AcceptInvitation("alice", invite, "test.txt")
		Expect(err).To(BeNil())

		i = i + 1
	}
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const secret = "shh"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobPhone *client.User
	var bobLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).To(BeNil())

			err = doris.AcceptInvitation("alice", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Doris can still load the file.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Tes: Do not panic if file does not exist.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Try to get file that does not exist.")
			userlib.DebugMsg("Loading alice file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())
		})

		Specify("Basic Test: Repeat filenames overwrite existing files (not sharing).", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to store file %s with content: %s", aliceFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: No repeat filenames per user, sharing edition.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob attempting to accept shared file as %s", bobFile)

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Functionality: Testing GetUser errors.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice enters the wrong password on her phone")
			alicePhone, err = client.GetUser("alice", "defaultPassword")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice enters the wrong password on her phone again")
			alicePhone, err = client.GetUser("alice", emptyString)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Get a user that has not been initialized")
			bob, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Functionality: Testing AppendToFile errors.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice adding to file %s with content: %s", aliceFile, contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempts adding to file %s with content: %s", bobFile, contentTwo)
			err = alice.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})

		Specify("Basic Functionality: Testing CreateInvitation errors.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to share a file she doesn't own.")
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to share a file with someone who doesn't exist.")
			_, err = alice.CreateInvitation(aliceFile, "doris")
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Functionality: Testing AcceptInvitation errors (cannot accept as a repeat filename).", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob attempting to accept invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Basic Functionality: Testing RevokeAccess errors.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice under filename %s.", aliceFile)
			err = bob.AcceptInvitation("alice", invite, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob attempting to revoke Alice's access from a file he doesn't own")
			err = bob.RevokeAccess(aliceFile, "alice")
			Expect(err).ToNot(BeNil())

		})
	})

	Describe("More Functionality", func() {

		Specify("More Functionality: Testing that repeat usernames are not allowed.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initialize second user with the same username as Alice.")
			doris, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("More Functionality: Testing that usernames must not be empty strings.", func() {
			userlib.DebugMsg("Initializing user with empty string as username.")
			alice, err = client.InitUser(emptyString, defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("More Functionality: Testing that usernames are case-sensitive.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user 'Alice'.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("More Functionality: Testing that two different users can have the same filename without issues.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing bob file data: %s", contentTwo)
			err = bob.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file alice data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading alice file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Loading bob file...")
			data, err = bob.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("More Functionality: Testing multiple users with multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting new instances of Alice - alicePhone, aliceDesktop, aliceLaptop")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceDesktop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting new instances of bob - bobPhone, bobLaptop")
			bobPhone, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("bobLaptop appending to file %s, content: %s", bobFile, contentTwo)
			err = bobLaptop.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice appending to file %s, content: %s", aliceFile, contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees expected file data.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err = aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that bobPhone sees expected file data.")
			data, err = bobPhone.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that bobLaptop sees expected file data.")
			data, err = bobLaptop.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("More Functionality: Testing for persistent non-local state.", func() {
			userlib.DebugMsg("Initializing user 'alice'.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting new instances of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees expected file data.")
			data, err := alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("More Functionality: Testing that shared users can override file contents.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice under filename %s.", aliceFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})

		Specify("More Functionality: Some more sharing tests.", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Charles, Doris, Eve, and Frank.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			frank, err = client.InitUser("frank", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Charles.")
			invite, err = alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles accepts invite from Alice under filename %s.", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentTwo)
			err = bob.StoreFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alice sees expected file data.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that charles sees expected file data.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Bob creating invite for Doris.")
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepts invite from Bob under filename %s.", dorisFile)
			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles creating invite for Eve.")
			invite, err = charles.CreateInvitation(charlesFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepts invite from Charles under filename %s.", eveFile)
			err = eve.AcceptInvitation("charles", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentThree)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that doris sees expected file data.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Bob creating invite for Frank.")
			invite, err = bob.CreateInvitation(bobFile, "frank")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Frank accepts invite from Bob under filename %s.", frankFile)
			err = frank.AcceptInvitation("bob", invite, frankFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Frank apending to file %s with content: %s", frankFile, contentOne)
			err = frank.AppendToFile(frankFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that charles sees expected file data.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + contentOne)))

			userlib.DebugMsg("Alice revokes access from bob.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for test.")
			_, err = bob.CreateInvitation(bobFile, "test")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that charles sees expected file data.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + contentOne)))

			userlib.DebugMsg("Frank apending to file %s with content: %s", frankFile, contentOne)
			err = frank.AppendToFile(frankFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Code Efficiency", func() {
		Specify("Code Efficiency: Testing that sharing files does not create duplicates", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var fileContents = userlib.RandomBytes(1)

			userlib.DebugMsg("Alice storing file %s with small content", aliceFile)
			err = alice.StoreFile(aliceFile, fileContents)
			Expect(err).To(BeNil())

			var bandwidth1 = measureBandwidth(func() {
				shareWithManyUsers(alice, 5, "bob", aliceFile)
			})

			fileContents = userlib.RandomBytes(1024 * 16)

			userlib.DebugMsg("Alice storing file %s with large content", aliceFile)
			err = alice.StoreFile(bobFile, fileContents)
			Expect(err).To(BeNil())

			var bandwidth1M = measureBandwidth(func() {
				shareWithManyUsers(alice, 5, "charles", bobFile)
			})

			// println(bandwidth1)
			// println(bandwidth1M)

			var diff = bandwidth1M - bandwidth1

			if diff > 1024*16 {
				err = errors.New("sharing files uses up too much extra space")
			} else {
				err = nil
			}

			Expect(err).To(BeNil())
		})

		Specify("Code Efficiency: Testing that file storage does not increase the number of keys in keystore.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var beforeStore = len(userlib.KeystoreGetMap())

			userlib.DebugMsg("Alice storing file %s with content %s", aliceFile, contentThree)
			err = alice.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content %s", bobFile, contentThree)
			err = alice.StoreFile(bobFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content %s", charlesFile, contentThree)
			err = alice.StoreFile(charlesFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content %s", dorisFile, contentThree)
			err = alice.StoreFile(dorisFile, []byte(contentThree))
			Expect(err).To(BeNil())

			var afterStore = len(userlib.KeystoreGetMap())

			Expect(beforeStore == afterStore).To(BeTrue())
		})
	})

	Describe("Edge Cases", func() {

		Specify("Edge Cases: Testing that password length = 0 is supported.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("Edge Cases: Really long username.", func() {
			userlib.DebugMsg("Initializing user with reeeeally long username.")
			alice, err = client.InitUser("alicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealice", emptyString)
			Expect(err).To(BeNil())
		})

		Specify("Edge Cases: Really long password.", func() {
			userlib.DebugMsg("Initializing user with reeeeally long username.")
			alice, err = client.InitUser("alice", "alicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealicealice")
			Expect(err).To(BeNil())
		})
		/*
			Specify("Edge Cases: Testing that a (non-revoked) user cannot be invited to the same file twice.", func() {
				userlib.DebugMsg("Initializing user Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("Initializing user Bob.")
				bob, err = client.InitUser("bob", defaultPassword)
				Expect(err).To(BeNil())

				userlib.DebugMsg("alice storing file %s with content: %s", aliceFile, contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())

				userlib.DebugMsg("alice creating invite for bob.")
				invite, err := alice.CreateInvitation(aliceFile, "bob")
				Expect(err).To(BeNil())

				userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
				err = bob.AcceptInvitation("alice", invite, bobFile)
				Expect(err).To(BeNil())

				userlib.DebugMsg("alice creating another invite for bob.")
				_, err = alice.CreateInvitation(aliceFile, "bob")
				Expect(err).ToNot(BeNil())
			})
		*/

		Specify("Edge Cases: Invitation revoked before accepted", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob attempting to accept Alice's old invitation for file %s", aliceFile)

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob cannot load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())
		})

		Specify("Edge Cases: Shared file overwritten by owner.", func() {
			// https://piazza.com/class/ky9e8cq86872u?cid=653_f60
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation as %s", bobFile)

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			alice.StoreFile(aliceFile, []byte(contentTwo))

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))

			userlib.DebugMsg("Checking that Bob can still load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentTwo)))
		})
	})

	Describe("Attacks", func() {

		// Specify("Attacks: Attacker changes bytes of datastore to corrupt a file.", func() {
		// 	// var userUUIDs []userlib.UUID = getNewUUIDs(func() {
		// 	userlib.DebugMsg("Initializing user Alice.")
		// 	alice, err = client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		// 	// })

		// 	var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
		// 		userlib.DebugMsg("Storing file data: %s", contentOne)
		// 		err = alice.StoreFile(aliceFile, []byte(contentOne))
		// 		Expect(err).To(BeNil())
		// 	})

		// 	userlib.DatastoreSet(fileUUIDs[len(fileUUIDs)-1], userlib.RandomBytes(16)) // corrupt file

		// 	userlib.DebugMsg("Loading file...")
		// 	data, err := alice.LoadFile(aliceFile)
		// 	Expect(err).ToNot(BeNil()) // Currently this statement fails because the datastore entries have not been messed with yet
		// 	Expect(data).To(BeNil())

		//var oldmap = userlib.DatastoreGetMap()

		//println("Old Map")
		//printKeys(oldmap)

		//var newmap = userlib.DatastoreGetMap()

		//println("New Map")
		//printKeys(newmap)

		//var fileUUID = getNewUUID(oldmap, newmap)

		//	oldmap = userlib.DatastoreGetMap()

		// userlib.DebugMsg("Storing file data: %s", contentOne)
		// err = alice.StoreFile(aliceFile, []byte(contentOne))
		// Expect(err).To(BeNil())

		//	newmap = userlib.DatastoreGetMap()

		//fileUUID = getNewUUID(oldmap, newmap)

		//println(userlib.DatastoreGet(fileUUID))

		//userlib.DatastoreSet(fileUUID, userlib.RandomBytes(16))

		//println(userlib.DatastoreGet(fileUUID))

		// })

		Specify("Attacks: Revoked user attempts to tamper with previously shared file.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Storing file data: %s", contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Alice inviting Bob to access %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting file as %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AppendToFile(bobFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())

			userlib.DatastoreSet(fileUUIDs[len(fileUUIDs)-1], userlib.RandomBytes(16)) // corrupt file

			// bob's tampering has no effect on alice's file (file should be at diff uuid now)
			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Attacks: Test GetUser error on malicious activity.", func() {
			var userUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Initializing user Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
			})

			userlib.DatastoreSet(userUUIDs[0], userlib.RandomBytes(16))

			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Attacks: Test LoadFile error on malicious activity.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Storing file data: %s", contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DatastoreSet(fileUUIDs[len(fileUUIDs)-1], userlib.RandomBytes(16)) // corrupt file

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())
		})

		Specify("Attacks: Test CreateInvitation error on malicious activity.", func() {
			// this might be out of scope, i can't find a place that says specifically what
			// counts as "malicious activity" for CreateInvitation
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Storing file data: %s", contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DatastoreSet(fileUUIDs[len(fileUUIDs)-1], userlib.RandomBytes(16)) // corrupt file

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Attacks: Test AcceptInvitation error when the shared file is corrupt.", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Storing file data: %s", contentOne)
				err = alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreSet(fileUUIDs[len(fileUUIDs)-1], userlib.RandomBytes(16)) // corrupt file

			userlib.DebugMsg("Bob attempting to accept Alice's invitation as file %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Attacks: Test AcceptInvitation error when the user sharing cannot be authenticated.", func() {
			var userUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Initializing user Alice.")
				alice, err = client.InitUser("alice", defaultPassword)
				Expect(err).To(BeNil())
			})

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreSet(userUUIDs[0], userlib.RandomBytes(16)) // corrupt user

			userlib.DebugMsg("Bob attempting to accept Alice's invitation as file %s", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Attacks: Malicious user attempts to accept an invitation not extended to them.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s", aliceFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles attempting to accept Alice's invitation as file %s", charlesFile)
			err = charles.AcceptInvitation("alice", invite, charlesFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Attacks: Overwrite entire file.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Storing file data: %s", contentOne)
				err = alice.StoreFile(aliceFile, []byte(userlib.RandomBytes(4)))
				Expect(err).To(BeNil())
			})

			userlib.DatastoreSet(fileUUIDs[len(fileUUIDs)-1], userlib.RandomBytes(4)) // corrupt file

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
			Expect(data).To(BeNil())
		})

		Specify("Attacks: Is our file encrypted?", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			var fileUUIDs []userlib.UUID = getNewUUIDs(func() {
				userlib.DebugMsg("Storing file data: %s", secret)
				err = alice.StoreFile(aliceFile, []byte(secret))
				Expect(err).To(BeNil())
			})

			userlib.DebugMsg("Reading stored data from DataStore")

			compromised := false
			for _, uuid := range fileUUIDs {
				data, _ := userlib.DatastoreGet(uuid)
				if isCompromised(data, []byte(secret)) {
					compromised = true
				}
			}

			Expect(compromised).To(BeFalse())

			userlib.DebugMsg("Loading file...")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
		})
	})
})
