// Copyright 2017 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main contains the implementation and entry point for the createtree
// command.
//
// Example usage:
// $ ./createtree --admin_server=host:port
//
// The command outputs the tree ID of the created tree to stdout, or an error to
// stderr in case of failure. The output is minimal to allow for easy usage in
// automated scripts.
//
// Several flags are provided to configure the create tree, most of which try to
// assume reasonable defaults.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/client/rpcflags"
	"github.com/google/trillian/cmd"
	"github.com/google/trillian/merkle/rfc6962"
	"github.com/google/trillian/types"
	"google.golang.org/grpc"
)

var (
	logServerAddr = flag.String("log_server", "", "Address of the gRPC Trillian Log Server (host:port)")
	rpcDeadline   = flag.Duration("rpc_deadline", time.Second*10, "Deadline for RPC requests")

	configFile = flag.String("config", "", "Config file containing flags, file contents can be overridden by command line flags")

	errAdminAddrNotSet = errors.New("empty --admin_server, please provide the Admin server host:port")
)

var hasher = rfc6962.DefaultHasher

const logID = 6480803095042929005

// TODO(Martin2112): Pass everything needed into this and don't refer to flags.
func newClient(ctx context.Context) (trillian.TrillianLogClient, *client.LogClient, error) {

	dialOpts, err := rpcflags.NewClientDialOptionsFromFlags()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to determine dial options: %v", err)
	}

	conn, err := grpc.Dial(*logServerAddr, dialOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial %v: %v", *logServerAddr, err)
	}
	// TODO: close

	logClient := trillian.NewTrillianLogClient(conn)
	verifier := client.NewLogVerifier(hasher)
	cli := client.New(logID, logClient, verifier, types.LogRootV1{})

	return logClient, cli, nil
}

func getAndVerifyInclusionProof(ctx context.Context, logCli trillian.TrillianLogClient, cli *client.LogClient, leafHash []byte, sth *types.LogRootV1) ([]*trillian.Proof, bool, error) {
	resp, err := logCli.GetInclusionProofByHash(ctx,
		&trillian.GetInclusionProofByHashRequest{
			LogId:    logID,
			LeafHash: leafHash,
			TreeSize: int64(sth.TreeSize),
		})
	if err != nil {
		return nil, false, err
	}
	if len(resp.Proof) < 1 {
		return nil, false, nil
	}
	for _, proof := range resp.Proof {
		if err := cli.VerifyInclusionByHash(sth, leafHash, proof); err != nil {
			return nil, false, fmt.Errorf("VerifyInclusionByHash(): %v", err)
		}
	}
	return resp.Proof, true, nil
}

func main() {
	flag.Parse()
	defer glog.Flush()

	if *configFile != "" {
		if err := cmd.ParseFlagFile(*configFile); err != nil {
			glog.Exitf("Failed to load flags from config file %q: %s", *configFile, err)
		}
	}

	if *logServerAddr == "" {
		glog.Exitf("%v", errAdminAddrNotSet)
	}

	if flag.NArg() == 0 {
		glog.Exitf("Missing command")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *rpcDeadline)
	defer cancel()

	logCli, cli, err := newClient(ctx)
	if err != nil {
		glog.Exitf("Failed to create the client: %v", err)
	}

	cmd := flag.Arg(0)
	switch cmd {
	case "log":
		if flag.NArg() < 2 {
			glog.Exitf("Missing message")
		}

		msg := []byte(flag.Arg(1))

		err := cli.AddLeaf(ctx, msg)
		if err != nil {
			glog.Exitf("Failed to log: %v", err)
		}

		hash := hasher.HashLeaf(msg)
		glog.Infof("Leaf hash: %s", base64.StdEncoding.EncodeToString(hash))

		root := cli.GetRoot()
		glog.Infof("Tree size: %d. Root hash: %v", root.TreeSize, root.RootHash)

	case "verify":
		root, err := cli.UpdateRoot(ctx)
		if err != nil {
			glog.Exitf("Failed to update root: %v", err)
		}

		hash, err := base64.StdEncoding.DecodeString(flag.Arg(1))
		if err != nil {
			glog.Exitf("Failed to decode: %v", err)
		}

		proofs, b, err := getAndVerifyInclusionProof(ctx, logCli, cli, hash, root)
		if err != nil {
			glog.Exitf("Failed to verify: %v", err)
		}

		if b {
			glog.Info("Verification: SUCCEED")
		} else {
			glog.Error("Verification: FAILED")
		}

		for _, proof := range proofs {
			glog.Infof("leaf_index: %d", proof.LeafIndex)
			glog.Info("hashes:")
			for _, hash := range proof.GetHashes() {
				glog.Infof("\t%s", base64.StdEncoding.EncodeToString(hash))
			}
		}

	case "root":
		root, err := cli.UpdateRoot(ctx)
		if err != nil {
			glog.Exitf("Failed to update root: %v", err)
		}

		glog.Infof("%+v", root)
	}

	glog.Info("Done")
}
