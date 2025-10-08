// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certloader_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"

	"github.com/cilium/cilium/pkg/crypto/certloader"
	"github.com/stretchr/testify/assert"
)

func TestNewFileReloaderErrors(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	_, err := certloader.NewFileReloaderReady(relay.caFiles, hubble.certFile, "")
	assert.Equal(t, err, certloader.ErrInvalidKeypair)

	_, err = certloader.NewFileReloaderReady(relay.caFiles, "", hubble.privkeyFile)
	assert.Equal(t, err, certloader.ErrInvalidKeypair)

	_, err = certloader.NewFileReloader(relay.caFiles, hubble.certFile, "")
	assert.Equal(t, err, certloader.ErrInvalidKeypair)

	_, err = certloader.NewFileReloader(relay.caFiles, "", hubble.privkeyFile)
	assert.Equal(t, err, certloader.ErrInvalidKeypair)
}

func TestHasKeypair(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	tests := []struct {
		name        string
		constructor func() (*certloader.FileReloader, error)
		hasKeypair  bool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			hasKeypair: false,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasKeypair: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			if tt.hasKeypair {
				assert.True(t, r.HasKeypair())
			} else {
				assert.False(t, r.HasKeypair())
			}
		})
	}
}

func TestHasCustomCA(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	tests := []struct {
		name        string
		constructor func() (*certloader.FileReloader, error)
		hasCustomCA bool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, "", "")
			},
			hasCustomCA: false,
		},
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			hasCustomCA: false,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: false,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: false,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, "", "")
			},
			hasCustomCA: true,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			hasCustomCA: true,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: true,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			hasCustomCA: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			if tt.hasCustomCA {
				assert.True(t, r.HasCustomCA())
			} else {
				assert.False(t, r.HasCustomCA())
			}
		})
	}
}

func TestReady(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	tests := []struct {
		name        string
		constructor func() (*certloader.FileReloader, error)
		isReady     bool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, "", "")
			},
			isReady: true,
		},
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			isReady: true,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			isReady: true,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			isReady: false,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, "", "")
			},
			isReady: true,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			isReady: false,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			isReady: true,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			isReady: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			if tt.isReady {
				assert.True(t, r.Ready())
			} else {
				assert.False(t, r.Ready())
			}
		})
	}
}

func TestKeypairAndCACertPool(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleCaCertPool := x509.NewCertPool()
	if ok := hubbleCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}

	hubbleKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	tests := []struct {
		name               string
		constructor        func() (*certloader.FileReloader, error)
		expectedKeypair    *tls.Certificate
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "CA only (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "CA and keypair (ready)",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			keypair, caCertPool := r.KeypairAndCACertPool()
			assert.Equal(t, tt.expectedKeypair, keypair)
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, tt.expectedCaCertPool.Subjects(), caCertPool.Subjects())
			} else {
				assert.Nil(t, caCertPool)
			}
		})
	}
}

func TestPrivilegedReload(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleCaCertPool := x509.NewCertPool()
	if ok := hubbleCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}

	hubbleKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	tests := []struct {
		name               string
		constructor        func() (*certloader.FileReloader, error)
		expectedKeypair    *tls.Certificate
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: nil,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			expectedKeypair:    nil,
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair:    &hubbleKeypair,
			expectedCaCertPool: hubbleCaCertPool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			prevKeypairGeneration, prevCaCertPoolGeneration := r.Generations()
			keypair, caCertPool, err := r.Reload()
			assert.NoError(t, err)
			// keypair check
			assert.Equal(t, tt.expectedKeypair, keypair)
			// caCertPool check
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, tt.expectedCaCertPool.Subjects(), caCertPool.Subjects())
			} else {
				assert.Nil(t, caCertPool)
			}
			// generations check
			keypairGeneration, caCertPoolGeneration := r.Generations()
			if tt.expectedKeypair != nil {
				assert.Equal(t, prevKeypairGeneration+1, keypairGeneration)
			} else {
				assert.Equal(t, prevKeypairGeneration, keypairGeneration)
			}
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, prevCaCertPoolGeneration+1, caCertPoolGeneration)
			} else {
				assert.Equal(t, prevCaCertPoolGeneration, caCertPoolGeneration)
			}
			// ensures that KeypairAndCACertPool() returns the expected values
			keypair, caCertPool = r.KeypairAndCACertPool()
			assert.Equal(t, tt.expectedKeypair, keypair)
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, tt.expectedCaCertPool.Subjects(), caCertPool.Subjects())
			} else {
				assert.Nil(t, caCertPool)
			}
		})
	}
}

func TestReloadKeypair(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	tests := []struct {
		name            string
		constructor     func() (*certloader.FileReloader, error)
		expectedKeypair *tls.Certificate
	}{
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			expectedKeypair: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair: &hubbleKeypair,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			expectedKeypair: nil,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedKeypair: &hubbleKeypair,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			prevKeypairGeneration, _ := r.Generations()
			keypair, err := r.ReloadKeypair()
			assert.NoError(t, err)
			// keypair check
			assert.Equal(t, tt.expectedKeypair, keypair)
			// generations check
			keypairGeneration, _ := r.Generations()
			if tt.expectedKeypair != nil {
				assert.Equal(t, prevKeypairGeneration+1, keypairGeneration)
			} else {
				assert.Equal(t, prevKeypairGeneration, keypairGeneration)
			}
			// ensures that KeypairAndCACertPool() returns the expected values
			keypair, caCertPool := r.KeypairAndCACertPool()
			assert.Equal(t, tt.expectedKeypair, keypair)
			assert.Nil(t, caCertPool)
		})
	}
}

func TestReloadCA(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	hubbleCaCertPool := x509.NewCertPool()
	if ok := hubbleCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}

	tests := []struct {
		name               string
		constructor        func() (*certloader.FileReloader, error)
		expectedCaCertPool *x509.CertPool
	}{
		{
			name: "empty",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, "", "")
			},
			expectedCaCertPool: nil,
		},
		{
			name: "keypair only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(nil, hubble.certFile, hubble.privkeyFile)
			},
			expectedCaCertPool: nil,
		},
		{
			name: "CA only",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, "", "")
			},
			expectedCaCertPool: hubbleCaCertPool,
		},
		{
			name: "CA and keypair",
			constructor: func() (*certloader.FileReloader, error) {
				return certloader.NewFileReloader(relay.caFiles, hubble.certFile, hubble.privkeyFile)
			},
			expectedCaCertPool: hubbleCaCertPool,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := tt.constructor()
			if err != nil {
				t.Error(err)
				return
			}
			_, prevCaCertPoolGeneration := r.Generations()
			caCertPool, err := r.ReloadCA()
			assert.NoError(t, err)
			// caCertPool check
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, tt.expectedCaCertPool.Subjects(), caCertPool.Subjects())
			} else {
				assert.Nil(t, caCertPool)
			}
			// generations check
			_, caCertPoolGeneration := r.Generations()
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, prevCaCertPoolGeneration+1, caCertPoolGeneration)
			} else {
				assert.Equal(t, prevCaCertPoolGeneration, caCertPoolGeneration)
			}
			// ensures that KeypairAndCACertPool() returns the expected values
			keypair, caCertPool := r.KeypairAndCACertPool()
			assert.Nil(t, keypair)
			if tt.expectedCaCertPool != nil {
				assert.Equal(t, tt.expectedCaCertPool.Subjects(), caCertPool.Subjects())
			} else {
				assert.Nil(t, caCertPool)
			}
		})
	}
}

func TestReloadError(t *testing.T) {
	dir, hubble, relay := directories(t)
	setup(t, hubble, relay)
	defer cleanup(dir)

	expectedCaCertPool := x509.NewCertPool()
	if ok := expectedCaCertPool.AppendCertsFromPEM(initialRelayClientCA); !ok {
		t.Fatal("AppendCertsFromPEM", initialRelayClientCA)
	}
	expectedKeypair, err := tls.X509KeyPair(initialHubbleServerCertificate, initialHubbleServerPrivkey)
	if err != nil {
		t.Fatal("tls.X509KeyPair", err)
	}

	r, err := certloader.NewFileReloaderReady(relay.caFiles, hubble.certFile, hubble.privkeyFile)
	assert.NoError(t, err)
	assert.NotNil(t, r)
	assert.True(t, r.Ready())

	keypair, caCertPool := r.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), caCertPool.Subjects())

	// delete one of the keypair file, so that reloading the keypair should
	// fail.
	if err = os.Remove(hubble.privkeyFile); err != nil {
		t.Fatal(err)
	}

	prevKeypairGeneration, prevCaCertPoolGeneration := r.Generations()
	_, _, err = r.Reload()
	assert.Error(t, err)

	// we expect keypair and caCertPool to not have changed on failed reload.
	keypair, caCertPool = r.KeypairAndCACertPool()
	assert.Equal(t, &expectedKeypair, keypair)
	assert.Equal(t, expectedCaCertPool.Subjects(), caCertPool.Subjects())
	// generations should not have changed
	keypairGeneration, caCertPoolGeneration := r.Generations()
	assert.Equal(t, prevKeypairGeneration, keypairGeneration)
	assert.Equal(t, prevCaCertPoolGeneration, caCertPoolGeneration)
}
