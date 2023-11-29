// Example script of a CKB SimpleChannelServiceClient.

import { privateKeyToBlake160 } from "@ckb-lumos/hd/lib/key";
import { mkSimpleChannelServiceClient } from "@polycrypt/perun-wallet-wrapper/client";
import { Allocation, Balances } from "@polycrypt/perun-wallet-wrapper/wire";
import { Script, helpers } from "@ckb-lumos/lumos";
import { ec as EC } from "elliptic";
import * as fs from "fs";
import {
  SerializeOffChainParticipant,
  SerializeSEC1EncodedPubKey,
} from "./perun-types";
import { bytes } from "@ckb-lumos/codec";
import { blockchain } from "@ckb-lumos/base";
import BIP32Factory from "bip32";
import * as ecc from "tiny-secp256k1";

const bip32 = BIP32Factory(ecc);

const ec = new EC("secp256k1");

const args = process.argv.slice(2); // Remove node and script name.

if (args.length !== 4) {
  console.error(
    "Usage: .exe <rpc-endpoint> <system-scripts-location> <alice-pk-file> <bob-pk-file>",
  );
  process.exit(1);
}

function parseSystemScripts(filePath: string) {
  const data = fs.readFileSync(filePath);
  const scripts = JSON.parse(data.toString());
  const result: any = {
    PREFIX: "ckt",
    SCRIPTS: {},
  };
  for (const key in scripts) {
    const script = scripts[key];
    switch (key) {
      case "secp256k1_data":
        continue;
      case "type_id":
        continue;
      default:
    }

    if (script.cell_dep) {
      result.SCRIPTS[key.toLocaleUpperCase()] = {
        DEP_TYPE: script.cell_dep.dep_type,
        INDEX: script.cell_dep.out_point.index,
        TX_HASH: script.cell_dep.out_point.tx_hash,
        CODE_HASH: script.script_id.code_hash,
        HASH_TYPE: script.script_id.hash_type,
      };
    } else {
      result[key] = {
        INDEX: script.out_point.index,
        TX_HASH: script.out_point.tx_hash,
      };
    }
  }
  return result;
}

const testnetConfig = parseSystemScripts(args[1]);
console.log(testnetConfig);

class CKBClient {
  private privateKey: string;
  private publicKey: string;
  private blake160Pubkey: string;
  private lockScript: Script;
  constructor(keypair: EC.KeyPair | { privateKey: string; publicKey: string }) {
    if ((keypair as any).privateKey && (keypair as any).publicKey) {
      this.privateKey = (keypair as any).privateKey;
      this.publicKey = (keypair as any).publicKey;
    } else {
      this.privateKey = (keypair as any).getPrivate("hex");
      this.publicKey = (keypair as any).getPublic().encode("hex", true);
    }
    this.blake160Pubkey = privateKeyToBlake160("0x" + this.privateKey);
    const secpTemplate = testnetConfig.SCRIPTS.SECP256K1_BLAKE160_SIGHASH_ALL;
    this.lockScript = {
      codeHash: secpTemplate.CODE_HASH,
      hashType: secpTemplate.HASH_TYPE,
      args: this.blake160Pubkey,
    };
  }

  pubkey(): string {
    // return this.keypair.getPublic().encode("hex", true);
    return this.publicKey;
  }

  asParticipant(): Uint8Array {
    const sec1bytes = bytes.bytify("0x" + this.publicKey);

    const serializedPubKey = SerializeSEC1EncodedPubKey(sec1bytes.buffer);
    const serializableScript = {
      code_hash: bytes.bytify(this.lockScript.codeHash).buffer,
      hash_type: blockchain.HashType.pack(this.lockScript.hashType),
      args: bytes.bytify(this.lockScript.args).buffer,
    };

    const buf = SerializeOffChainParticipant({
      payment_script: serializableScript,
      unlock_script: serializableScript,
      pub_key: serializedPubKey,
    });
    return new Uint8Array(buf);
  }

  address(): string {
    return helpers.encodeToAddress(this.lockScript, {
      config: testnetConfig,
    });
  }

  encodedAddress(): Uint8Array {
    return Uint8Array.from(Buffer.from(this.address()));
  }
}

function parsePrivKeyFile(pkFile: string): EC.KeyPair {
  const bytes = fs.readFileSync(pkFile);
  // The second line in our pkFile is the `ChainCode` for the BIP44 standard.
  return ec.keyFromPrivate(bytes.toString().split("\n")[0].trim(), "hex");
}

function customBip44PubKeyDerivation(pkFile: string): {
  privateKey: string;
  publicKey: string;
} {
  const bytest = fs.readFileSync(pkFile);
  const text = bytest.toString();
  const pk = text.split("\n")[0];
  const chaincode = text.split("\n")[1];
  const node = bip32.fromPrivateKey(
    Buffer.from(bytes.bytify("0x" + pk).buffer),
    Buffer.from(bytes.bytify("0x" + chaincode).buffer),
  );
  const res = node.derivePath("m/44'/309'/0'/0/0");
  const pubkey = res.publicKey.toString("hex");
  return {
    privateKey: res.privateKey!.toString("hex"),
    publicKey: pubkey,
  };
}

async function main(
  rpcEndpoint: string,
  alicePkFile: string,
  bobPkFile: string,
) {
  const addrEncoder = function (addr: Uint8Array | string): Uint8Array {
    if (typeof addr === "string") {
      return Uint8Array.from(Buffer.from(addr, "hex"));
    }
    return addr;
  };
  const serviceClient = mkSimpleChannelServiceClient(addrEncoder, rpcEndpoint);

  // Custom BIP44 derivation for alice.
  const aliceCreds = customBip44PubKeyDerivation(alicePkFile);

  const alice = new CKBClient(aliceCreds);
  console.log("Alice Address:", alice.address());
  console.log("Alice PubKey:", alice.pubkey());
  const bob = new CKBClient(parsePrivKeyFile(bobPkFile));
  console.log("Bob Address:", bob.address());
  console.log("Bob PubKey:", bob.pubkey());
  const challengeDuration = 10;
  const alloc = Allocation.create({
    assets: [new Uint8Array(32)],
    balances: Balances.create({
      balances: [
        {
          balance: [
            bytes.bytify("0x02540be400"), // Alice's balance (100 CKBytes).
            bytes.bytify("0x02540be400"), // Bob's balance (100 CKBytes).
          ],
        },
      ],
    }),
  });

  const res = await serviceClient.openChannel(
    alice.asParticipant(),
    bob.encodedAddress(),
    alloc,
    challengeDuration,
  );

  console.log("OpenChannel Result:");
  console.log(res);
}

try {
  main(args[0], args[2], args[3])
    .then(() => {
      console.log("done");
    })
    .catch((err) => {
      console.error(err);
    });
} catch (err) {
  console.error(err);
}
