package gdtmp2ptest_test

import (
	"testing"

	"github.com/gordian-engine/gdragon/gdtmp2p/gdtmp2ptest"
	"github.com/gordian-engine/gordian/tm/tmp2p/tmp2ptest"
)

func TestNetwork(t *testing.T) {
	t.Parallel()

	tmp2ptest.TestNetworkCompliance(t, gdtmp2ptest.NewNetwork)
}
