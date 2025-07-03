package gdtmp2p

// VoteDelta is the delta type for a vote session.
type VoteDelta struct {
	BlockHash []byte

	KeyIndex  uint16
	Signature []byte
}
