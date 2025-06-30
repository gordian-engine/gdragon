package gdtmp2p

// BroadcastAnnotation is a subset of [breathcast.IncomingBroadcastConfig]
// that is set as an annotation on [tmconsensus.ProposedHeader]
// so that recipients can correctly receive a broadcast.
type BroadcastAnnotation struct {
	NData, NParity uint16

	TotalDataSize int

	HashNonce []byte

	RootProofs [][]byte

	ChunkSize uint16
}
