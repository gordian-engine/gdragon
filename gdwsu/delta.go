package gdwsu

// UpdateFromCentral only needs to notify the remote state
// that a prevote or precommit is now eligible for read.
// The remote state values already hold references to vote and signature content,
// so this update effectively unblocks a read.
type UpdateFromCentral struct {
	KeyIdx      uint16
	IsPrecommit bool
}

// ReceivedFromPeer is the preprocessed delta from an inbound peer.
type ReceivedFromPeer struct {
	// The pair of the key index and the signature
	// are an effective representation of a gcrypto.SparseSignature.
	KeyIdx uint16
	Sig    []byte

	TargetHash []byte

	// True if precommit, false if prevote.
	IsPrecommit bool
}

// ParsedPacket is the parsed version of an inbound packet.
type ParsedPacket struct {
	IsPrecommit bool

	KeyIdx uint16
	HashID uint16

	TargetHash []byte

	Sig []byte
}
