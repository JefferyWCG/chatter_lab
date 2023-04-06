// Implementation of a forward-secure, end-to-end encrypted messaging client
// supporting key compromise recovery and out-of-order message delivery.
// Directly inspired by Signal/Double-ratchet protocol but missing a few
// features. No asynchronous handshake support (pre-keys) for example.
//
// SECURITY WARNING: This code is meant for educational purposes and may
// contain vulnerabilities or other bugs. Please do not use it for
// security-critical applications.
//
// GRADING NOTES: This is the only file you need to modify for this assignment.
// You may add additional support files if desired. You should modify this file
// to implement the intended protocol, but preserve the function signatures
// for the following methods to ensure your implementation will work with
// standard test code:
//
// *NewChatter
// *EndSession
// *InitiateHandshake
// *ReturnHandshake
// *FinalizeHandshake
// *SendMessage
// *ReceiveMessage
//
// In addition, you'll need to keep all of the following structs' fields:
//
// *Chatter
// *Session
// *Message
//
// You may add fields if needed (not necessary) but don't rename or delete
// any existing fields.
//
// Original version
// Joseph Bonneau February 2019

package chatterbox

import (
	//	"bytes" //un-comment for helpers like bytes.equal
	"encoding/binary"
	"errors"
	//	"fmt" //un-comment if you want to do any debug printing.
)

// Labels for key derivation

// Label for generating a check key from the initial root.
// Used for verifying the results of a handshake out-of-band.
const HANDSHAKE_CHECK_LABEL byte = 0x11

// Label for ratcheting the root key after deriving a key chain from it
const ROOT_LABEL = 0x22

// Label for ratcheting the main chain of keys
const CHAIN_LABEL = 0x33

// Label for deriving message keys from chain keys
const KEY_LABEL = 0x44

// Chatter represents a chat participant. Each Chatter has a single long-term
// key Identity, and a map of open sessions with other users (indexed by their
// identity keys). You should not need to modify this.
type Chatter struct {
	Identity *KeyPair
	Sessions map[PublicKey]*Session
}

// Session represents an open session between one chatter and another.
// You should not need to modify this, though you can add additional fields
// if you want to.
type Session struct {
	MyDHRatchet       *KeyPair
	PartnerDHRatchet  *PublicKey
	RootChain         *SymmetricKey
	SendChain         *SymmetricKey
	ReceiveChain      *SymmetricKey
	CachedReceiveKeys map[int]*SymmetricKey
	SendCounter       int
	LastUpdate        int
	ReceiveCounter    int
}

// Message represents a message as sent over an untrusted network.
// The first 5 fields are send unencrypted (but should be authenticated).
// The ciphertext contains the (encrypted) communication payload.
// You should not need to modify this.
type Message struct {
	Sender        *PublicKey
	Receiver      *PublicKey
	NextDHRatchet *PublicKey
	Counter       int
	LastUpdate    int
	Ciphertext    []byte
	IV            []byte
}

// EncodeAdditionalData encodes all of the non-ciphertext fields of a message
// into a single byte array, suitable for use as additional authenticated data
// in an AEAD scheme. You should not need to modify this code.
func (m *Message) EncodeAdditionalData() []byte {
	buf := make([]byte, 8+3*FINGERPRINT_LENGTH)

	binary.LittleEndian.PutUint32(buf, uint32(m.Counter))
	binary.LittleEndian.PutUint32(buf[4:], uint32(m.LastUpdate))

	if m.Sender != nil {
		copy(buf[8:], m.Sender.Fingerprint())
	}
	if m.Receiver != nil {
		copy(buf[8+FINGERPRINT_LENGTH:], m.Receiver.Fingerprint())
	}
	if m.NextDHRatchet != nil {
		copy(buf[8+2*FINGERPRINT_LENGTH:], m.NextDHRatchet.Fingerprint())
	}

	return buf
}

// NewChatter creates and initializes a new Chatter object. A long-term
// identity key is created and the map of sessions is initialized.
// You should not need to modify this code.
func NewChatter() *Chatter {
	c := new(Chatter)
	c.Identity = GenerateKeyPair()
	c.Sessions = make(map[PublicKey]*Session)
	return c
}

// EndSession erases all data for a session with the designated partner.
// All outstanding key material should be zeroized and the session erased.
func (c *Chatter) EndSession(partnerIdentity *PublicKey) error {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return errors.New("Don't have that session open to tear down")
	}

	delete(c.Sessions, *partnerIdentity)

	// TODO: your code here to zeroize remaining state

	return nil
}

// InitiateHandshake prepares the first message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the initiator.
func (c *Chatter) InitiateHandshake(partnerIdentity *PublicKey) (*PublicKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, errors.New("Already have session open")
	}

	//generate alice's ephemeral key-pair
	eph_keys := GenerateKeyPair() //

	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       eph_keys,
	}

	return &eph_keys.PublicKey, nil
	//return nil, errors.New("Not implemented")
}

// ReturnHandshake prepares the second message sent in a handshake, containing
// an ephemeral DH share. The partner which calls this method is the responder.
func (c *Chatter) ReturnHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*PublicKey, *SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; exists {
		return nil, nil, errors.New("Already have session open")
	}

	//generate ephemeral key-pair, generate symemetricKey,
	eph_keys := GenerateKeyPair() //generate bob's eph key pair
	sym_key := CombineKeys(
		DHCombine(partnerIdentity, &eph_keys.PrivateKey),    //g^A b
		DHCombine(partnerEphemeral, &c.Identity.PrivateKey), //g^a B
		DHCombine(partnerEphemeral, &eph_keys.PrivateKey),   //g^a b
	)
	c.Sessions[*partnerIdentity] = &Session{
		CachedReceiveKeys: make(map[int]*SymmetricKey),
		MyDHRatchet:       eph_keys,
		PartnerDHRatchet:  partnerEphemeral,
		RootChain:         sym_key,
		// TODO: your code here
	}

	// TODO: your code here
	return &eph_keys.PublicKey, sym_key.DeriveKey(HANDSHAKE_CHECK_LABEL), nil
	//return nil, nil, errors.New("Not implemented")
}

// FinalizeHandshake lets the initiator receive the responder's ephemeral key
// and finalize the handshake.The partner which calls this method is the initiator.
func (c *Chatter) FinalizeHandshake(partnerIdentity,
	partnerEphemeral *PublicKey) (*SymmetricKey, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't finalize session, not yet open")
	}

	my_eph_key := &c.Sessions[*partnerIdentity].MyDHRatchet.PrivateKey

	//generate ephemeral key-pair for Alice
	sym_key := CombineKeys(
		DHCombine(partnerEphemeral, &c.Identity.PrivateKey), // g^b A
		DHCombine(partnerIdentity, my_eph_key),              //g^B a
		DHCombine(partnerEphemeral, my_eph_key),             //g^b a
	)

	c.Sessions[*partnerIdentity].RootChain = sym_key
	c.Sessions[*partnerIdentity].PartnerDHRatchet = partnerEphemeral
	// TODO: your code here

	return sym_key.DeriveKey(HANDSHAKE_CHECK_LABEL), nil
	//return nil, errors.New("Not implemented")
}

// SendMessage is used to send the given plaintext string as a message.
// You'll need to implement the code to ratchet, derive keys and encrypt this message.
func (c *Chatter) SendMessage(partnerIdentity *PublicKey,
	plaintext string) (*Message, error) {

	if _, exists := c.Sessions[*partnerIdentity]; !exists {
		return nil, errors.New("Can't send message to partner with no open session")
	}

	counter := c.Sessions[*partnerIdentity].SendCounter
	var cur_key *SymmetricKey

	//handle the initial case
	if counter == 0 {
		cur_key = c.Sessions[*partnerIdentity].RootChain
	} else {
		cur_key = c.Sessions[*partnerIdentity].SendChain
	}

	new_key := cur_key.DeriveKey(CHAIN_LABEL)
	//next_root := cur_key.DeriveKey(ROOT_LABEL)
	IV := NewIV()
	message := &Message{
		Sender:   &c.Identity.PublicKey,
		Receiver: partnerIdentity,
		//NextDHRatchet: next_root,
		Counter: counter + 1,
		//LastUpdate: ,
		Ciphertext: new_key.AuthenticatedEncrypt(plaintext, nil, IV),
		IV:         IV,
		// TODO: your code here
	}

	//update session
	c.Sessions[*partnerIdentity].SendCounter = counter + 1
	c.Sessions[*partnerIdentity].SendChain = new_key
	return message, nil
	//return message, errors.New("Not implemented")
}

func decryptCipher(time int, cipher []byte, key *SymmetricKey, IV []byte) (string, *SymmetricKey) {

	newKey := key.Duplicate()
	for i := 0; i < time; i++ {
		newKey = newKey.DeriveKey(CHAIN_LABEL)
	}

	plaintext, _ := newKey.AuthenticatedDecrypt(cipher, nil, IV)
	return plaintext, newKey
}

// ReceiveMessage is used to receive the given message and return the correct
// plaintext. This method is where most of the key derivation, ratcheting
// and out-of-order message handling logic happens.
func (c *Chatter) ReceiveMessage(message *Message) (string, error) {

	if _, exists := c.Sessions[*message.Sender]; !exists {
		return "", errors.New("Can't receive message from partner with no open session")
	}

	// sync
	//handle the initial case
	var cur_key *SymmetricKey
	partner := message.Sender
	//send_counter := message.Counter
	receive_counter := c.Sessions[*partner].ReceiveCounter
	if receive_counter == 0 {
		cur_key = c.Sessions[*partner].RootChain
	} else {
		cur_key = c.Sessions[*partner].ReceiveChain
	}
	plaintext, next_key := decryptCipher(1, message.Ciphertext, cur_key, message.IV)

	c.Sessions[*partner].ReceiveCounter = receive_counter + 1
	c.Sessions[*partner].ReceiveChain = next_key
	return plaintext, nil
}
