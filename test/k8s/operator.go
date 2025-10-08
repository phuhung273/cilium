// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sOperatorTest", func() {
	var (
		kubectl *helpers.Kubectl
		podPath string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(kubectl)

		podPath = helpers.ManifestGet(kubectl.BasePath(), "external_pod.yaml")

		kubectl.ApplyDefault(podPath).ExpectSuccess("cannot install pod path")
	})

	AfterEach(func() {
		deploymentManager.DeleteAll()
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		_ = kubectl.Delete(podPath)
		ExpectAllPodsTerminated(kubectl)
		deploymentManager.DeleteCilium()
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		kubectl.CollectFeatures()
	})

	Context("Prometheus", func() {
		It("Test mTLS using existingSecret", func() {
			deploymentManager.DeployCilium(map[string]string{
				"operator.prometheus.enabled":                   "true",
				"operator.prometheus.tls.enabled":               "true",
				"operator.prometheus.tls.server.existingSecret": "hubble-server-certs",
			}, DeployCiliumOptionsAndDNS)

			By("Looking for operator pod IP")
			operatorPodIPs, err := kubectl.GetPodsIPs(helpers.KubeSystemNamespace, helpers.OperatorLabel)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs for %s", helpers.OperatorLabel)
			Expect(len(operatorPodIPs)).To(BeNumerically(">", 0), "Expected pod IPs mismatch")

			var operatorPodIP string
			// Any operator pod would work
			for _, value := range operatorPodIPs {
				operatorPodIP = value
				break
			}

			By("Looking for test pod")
			var podList v1.PodList
			Expect(kubectl.Exec(fmt.Sprintf("%s get pod -l test=toservices -o json", helpers.KubectlCmd)).Unmarshal(&podList)).To(BeNil())
			Expect(len(podList.Items)).To(BeNumerically(">", 0), "No test pods available")

			testPod := podList.Items[0]

			By("Parsing root CA cert and key")
			secret, err := kubectl.GetSecret(defaults.CASecretName, helpers.KubeSystemNamespace)
			Expect(err).To(BeNil(), "Could not get root CA")

			caCertBytes, ok := secret.Data[defaults.CASecretCertName]
			Expect(ok).To(BeTrue(), fmt.Sprintf("Could not find %s in secret", defaults.CASecretCertName))
			caCertBlock, _ := pem.Decode(caCertBytes)
			Expect(caCertBlock).NotTo(BeNil(), fmt.Sprintf("Could not decode %s", defaults.CASecretCertName))
			caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
			Expect(err).To(BeNil(), fmt.Sprintf("Could not parse %s", defaults.CASecretCertName))

			caKeyBytes, ok := secret.Data[defaults.CASecretKeyName]
			Expect(ok).To(BeTrue(), fmt.Sprintf("Could not find %s in secret", defaults.CASecretKeyName))
			caKeyBlock, _ := pem.Decode(caKeyBytes)
			Expect(caKeyBlock).NotTo(BeNil(), fmt.Sprintf("Could not decode %s", defaults.CASecretKeyName))
			caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
			Expect(err).To(BeNil(), fmt.Sprintf("Could not parse %s", defaults.CASecretKeyName))

			By("Generating client cert and key")
			clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
			Expect(err).To(BeNil(), "Could not generate client key")
			clientTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject: pkix.Name{
					CommonName:   "client",
					Organization: []string{"Example Org"},
				},
				NotAfter:    time.Now().Add(time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			clientCert, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
			Expect(err).To(BeNil(), "Could not create client cert")

			By("Writing CA, client cert, client key to test pod")
			writeFileToTestPod := func(path string, bytes []byte) {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace,
					testPod.Name,
					// Because cert content includes newline breaking kubectl exec syntax
					// We need this trick to base64-encode content to form a singleline string
					// Then decode using bash
					fmt.Sprintf("sh -c \"echo %s | base64 -d > %s\"", base64.StdEncoding.EncodeToString(bytes), path),
				)
				res.ExpectSuccess(fmt.Sprintf("Could not write %s to pod", path))
			}

			writeFileToTestPod("ca.crt", caCertBytes)
			clientCertPemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: clientCert}
			var clientCertBuf bytes.Buffer
			pem.Encode(&clientCertBuf, clientCertPemBlock)
			writeFileToTestPod("tls.crt", clientCertBuf.Bytes())

			clientKeyPemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}
			var clientKeyBuf bytes.Buffer
			pem.Encode(&clientKeyBuf, clientKeyPemBlock)
			writeFileToTestPod("tls.key", clientKeyBuf.Bytes())

			By("Executing mTLS curl")
			server := fmt.Sprintf("%s.default.hubble-grpc.cilium.io:9963", helpers.K8s1)
			cmd := fmt.Sprintf("curl --cert tls.crt --key tls.key --cacert ca.crt --retry 10 --resolve %s:%s https://%s/metrics", server, operatorPodIP, server)
			res := kubectl.ExecPodCmd(helpers.DefaultNamespace, testPod.Name, cmd)
			res.ExpectSuccess("Could not access Prometheus endpoint using mTLS")
		})
	})
})
