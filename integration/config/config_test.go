/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
package config_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/gogo/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric/common/configtx"
	"github.com/hyperledger/fabric/common/tools/protolator"
	"github.com/hyperledger/fabric/integration/nwo"
	"github.com/hyperledger/fabric/integration/nwo/commands"
	"github.com/hyperledger/fabric/internal/configtxlator/update"
	"github.com/hyperledger/fabric/pkg/config"
	"github.com/hyperledger/fabric/protoutil"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/tedsuo/ifrit"
)

var _ = Describe("Config", func() {
	var (
		testDir string
		// client    *docker.Client
		network *nwo.Network
		// chaincode nwo.Chaincode
		process ifrit.Process
		// signer  identity.SignerSerializer
		peer    *nwo.Peer
		orderer *nwo.Orderer
		mspDir  string
	)

	BeforeEach(func() {
		var err error
		testDir, err = ioutil.TempDir("", "config")
		Expect(err).NotTo(HaveOccurred())

		network = nwo.New(nwo.MostBasicSolo(), testDir, nil, StartPort(), components)

		network.GenerateConfigTree()
		network.Bootstrap()

		networkRunner := network.NetworkGroupRunner()
		process = ifrit.Invoke(networkRunner)
		Eventually(process.Ready(), network.EventuallyTimeout).Should(BeClosed())

		network.CreateAndJoinChannel(network.Orderer("orderer"), "testchannel")
		peer = network.Peer("Org1", "peer0")
		mspDir = network.PeerUserMSPDir(peer, "Admin")
		orderer = network.Orderer("orderer")
	})

	AfterEach(func() {
		if process != nil {
			process.Signal(syscall.SIGTERM)
			Eventually(process.Wait(), network.EventuallyTimeout).Should(Receive())
		}
		if network != nil {
			network.Cleanup()
		}
		// os.RemoveAll(testDir)
	})

	Describe("channel config", func() {
		It("creates a signature for a given config update", func() {
			By("creating a channel config update")
			configUpdate := createChannelUpdate(network, peer, network.Orderer("orderer"), "testchannel")

			// By("using peer-channel-signconfigtx to sign")
			// configUpdateEnvelope, _ /*peerSignConfigTxSignature*/, updateFile := getSignatureFromPeerChannelSignConfigTx(network, peer, configUpdate, "testchannel", testDir)
			// Expect(configUpdateEnvelope.Signatures).To(HaveLen(1))
			// By("printing the signconfigtx signature")
			// protolator.DeepMarshalJSON(os.Stdout, peerSignConfigTxSignature)

			By("creating the signer")
			adminCert, err := ioutil.ReadFile(filepath.Join(mspDir, "admincerts", "Admin@org1.example.com-cert.pem"))
			Expect(err).NotTo(HaveOccurred())
			privCert, err := ioutil.ReadFile(filepath.Join(mspDir, "keystore", "priv_sk"))
			Expect(err).NotTo(HaveOccurred())
			fmt.Printf("!! DL msp dir : %+v\n", mspDir)
			signer, err := config.NewSigner(adminCert, privCert, "Org1MSP")
			Expect(err).NotTo(HaveOccurred())

			By("creating the detached signature")
			detachedSignature, err := config.SignConfigUpdate(configUpdate, signer)
			Expect(err).NotTo(HaveOccurred())

			By("printing the detached signature")
			protolator.DeepMarshalJSON(os.Stdout, detachedSignature)

			By("creating the config update envelope")
			configUpdateEnvelope := &common.ConfigUpdateEnvelope{
				ConfigUpdate: config.MarshalOrPanic(configUpdate),
				Signatures: []*common.ConfigSignature{
					detachedSignature,
				},
			}

			By("creating a signed config update envelope")
			signedEnvelope, err := protoutil.CreateSignedEnvelope(common.HeaderType_CONFIG_UPDATE, "testchannel", nil, configUpdateEnvelope, 0, 0)
			Expect(err).NotTo(HaveOccurred())

			By("printing the signed envelope")
			protolator.DeepMarshalJSON(os.Stdout, signedEnvelope)

			By("writing the signed envelope to a file")
			updateFile := filepath.Join(testDir, "config-update.pb")
			err = ioutil.WriteFile(updateFile, config.MarshalOrPanic(signedEnvelope), 0660)
			Expect(err).NotTo(HaveOccurred())

			// get current configuration block number
			currentBlockNumber := nwo.CurrentConfigBlockNumber(network, peer, nil, "testchannel")

			By("submitting the config update")
			sess, err := network.PeerAdminSession(peer, commands.ChannelUpdate{
				ChannelID:  "testchannel",
				Orderer:    network.OrdererAddress(orderer, nwo.ListenPort),
				File:       updateFile,
				ClientAuth: network.ClientAuthRequired,
			})
			Expect(err).NotTo(HaveOccurred())
			Eventually(sess, network.EventuallyTimeout).Should(gexec.Exit(0))
			Expect(sess.Err).To(gbytes.Say("Successfully submitted channel update"))

			ccb := func() uint64 { return nwo.CurrentConfigBlockNumber(network, peer, nil, "testchannel") }
			Eventually(ccb, network.EventuallyTimeout).Should(BeNumerically(">", currentBlockNumber))

			By("deploying another chaincode using the same chaincode package")
			chaincodePath := components.Build("github.com/hyperledger/fabric/integration/chaincode/module")
			anotherChaincode := nwo.Chaincode{
				Name:                "Your_Chaincode",
				Version:             "Version+0_0",
				Path:                chaincodePath,
				Lang:                "binary",
				PackageFile:         filepath.Join(testDir, "modulecc.tar.gz"),
				Ctor:                `{"Args":["init","a","100","b","200"]}`,
				ChannelConfigPolicy: "/Channel/Application/Endorsement",
				Sequence:            "1",
				InitRequired:        true,
				Label:               "my_simple_chaincode",
			}
			nwo.DeployChaincode(network, "testchannel", orderer, anotherChaincode)
		})
	})
})

// create a channel update for enabling V2_0 capabilities
func createChannelUpdate(n *nwo.Network, peer *nwo.Peer, orderer *nwo.Orderer, channel string) *common.ConfigUpdate {
	currentConfig := nwo.GetConfig(n, peer, orderer, channel)
	updatedConfig := proto.Clone(currentConfig).(*common.Config)
	updatedConfig.ChannelGroup.Groups["Application"].Values["Capabilities"] = &common.ConfigValue{
		ModPolicy: "Admins",
		Value: protoutil.MarshalOrPanic(
			&common.Capabilities{
				Capabilities: map[string]*common.Capability{
					"V2_0": {},
				},
			},
		),
	}
	configUpdate, err := update.Compute(currentConfig, updatedConfig)
	Expect(err).NotTo(HaveOccurred())
	configUpdate.ChannelId = "testchannel"
	return configUpdate
}

func getSignatureFromPeerChannelSignConfigTx(n *nwo.Network, peer *nwo.Peer, configUpdate *common.ConfigUpdate, channel, testDir string) (*common.ConfigUpdateEnvelope, *common.ConfigSignature, string) {
	signedEnvelope, err := protoutil.CreateSignedEnvelope(
		common.HeaderType_CONFIG_UPDATE,
		"testchannel",
		nil, // local signer
		&common.ConfigUpdateEnvelope{ConfigUpdate: protoutil.MarshalOrPanic(configUpdate)},
		0, // message version
		0, // epoch
	)
	Expect(err).NotTo(HaveOccurred())
	Expect(signedEnvelope).NotTo(BeNil())
	updateFile := filepath.Join(testDir, "update.pb")
	err = ioutil.WriteFile(updateFile, protoutil.MarshalOrPanic(signedEnvelope), 0600)
	Expect(err).NotTo(HaveOccurred())

	sess, err := n.PeerAdminSession(peer, commands.SignConfigTx{
		File:       updateFile,
		ClientAuth: n.ClientAuthRequired,
	})
	Expect(err).NotTo(HaveOccurred())
	Eventually(sess, n.EventuallyTimeout).Should(gexec.Exit(0))
	fileBytes, err := ioutil.ReadFile(updateFile)
	Expect(err).NotTo(HaveOccurred())
	signedConfigUpdateEnvelope := &common.Envelope{}
	err = proto.Unmarshal(fileBytes, signedConfigUpdateEnvelope)
	Expect(err).NotTo(HaveOccurred())
	protolator.DeepMarshalJSON(os.Stdout, signedConfigUpdateEnvelope)
	payload, err := protoutil.UnmarshalPayload(signedConfigUpdateEnvelope.Payload)
	Expect(err).NotTo(HaveOccurred())
	configUpdateEnvelope, err := configtx.UnmarshalConfigUpdateEnvelope(payload.Data)
	Expect(err).NotTo(HaveOccurred())
	Expect(configUpdateEnvelope.Signatures).To(HaveLen(1))
	return configUpdateEnvelope, configUpdateEnvelope.Signatures[0], updateFile
}
