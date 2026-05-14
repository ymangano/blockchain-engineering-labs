import asyncio
import logging

logging.getLogger("LabCommunity").setLevel(logging.CRITICAL)

from ipv8.community import *
from ipv8.lazy_community import lazy_wrapper
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.messaging.lazy_payload import VariablePayload, vp_compile
from ipv8_service import IPv8

COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
MEMBER_1_PUBLIC_KEY_HEX = "4c69624e61434c504b3adc31a700de7e0d53fc6c3cfc52e2b8122f35d74def4aaf55b9ccdf81116f5f4f7d8c15de980916c0e953a4f23423ad1ff6abb34dbae4ac3c12bfdb76c0f4e81c" #Darian
MEMBER_2_PUBLIC_KEY_HEX = "4c69624e61434c504b3a70597fc8337cce9c703a98ae454aef1ba9a0e9ab61a3b84933a606d1ec44466197b54b27c07d167ddfc134d03247b8290a6013d0b4ccc07817272e846aa51e50" # Jayran
MEMBER_3_PUBLIC_KEY_HEX = "4c69624e61434c504b3aea1ebe2bb45bbaef6fd358df15349cf7494ea4c3079bd09876d867e0cd339d5c341269531ea65b0f99daf123b585ebcef5c21d9e17c54d755e5cc5916c024ce4" # Yves

@vp_compile
class RegisterPayload(VariablePayload):
    msg_id = 1
    names = ["member1_key", "member2_key", "member3_key"]
    format_list = ["varlenH", "varlenH", "varlenH"]

@vp_compile
class ResponsePayload(VariablePayload):
    msg_id = 2
    names = ["success", "group_id", "message"]
    format_list = ["?", "varlenHutf8", "varlenHutf8"]

@vp_compile
class ChallengeRequestPayload(VariablePayload):
    msg_id = 3
    format_list = ["varlenHutf8"]
    names = ["group_id"]

@vp_compile
class ChallengeResponsePayload(VariablePayload):
    msg_id = 4
    format_list = ["varlenH", "q", "d"]
    names = ["nonce", "round_number", "deadline"]

@vp_compile
class SignatureBundlePayload(VariablePayload):
    msg_id = 5
    format_list = ["varlenHutf8", "q", "varlenH", "varlenH", "varlenH"]
    names = ["group_id", "round_number", "sig1", "sig2", "sig3"]

@vp_compile
class RoundResultPayload(VariablePayload):
    msg_id = 6
    format_list = ["?", "q", "q", "varlenHutf8"]
    names = ["success", "round_number", "rounds_completed", "message"]

@vp_compile
class NonceToSign(VariablePayload):
    msg_id = 7
    format_list = ["varlenH", "q", "varlenHutf8"]
    names = ["nonce", "round_number", "group_id"]

@vp_compile
class SignatureSubmissionPayload(VariablePayload):
    msg_id = 8
    format_list = ["q", "varlenH"]
    names = ["round_number", "signature"]

class LabCommunity(Community):
    community_id = COMMUNITY_ID

    def started(self):
        print("Lab community started!")
        print("Looking for peers...")

    def __init__(self, settings):
        super().__init__(settings)
        self.add_message_handler(ResponsePayload, self.on_response)
        self.add_message_handler(NonceToSign, self.on_nonce_to_sign)
        self.add_message_handler(SignatureSubmissionPayload, self.on_signature_submission)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RoundResultPayload, self.on_round_result)

        self.server_peer = None
        self.darian_peer = None
        self.jayran_peer = None
        self.signatures = [None, None, None]
        self.success = False

        self.round_number = 0
        self.group_id = 0

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer, payload):
        if peer != self.server_peer:
            print("Ignoring response from non-server peer")
            return

        print("SERVER RESPONSE:")
        print(payload)

    @lazy_wrapper(NonceToSign)
    def on_nonce_to_sign(self, peer, payload):

        if peer == self.jayran_peer:
            print("Received NONCE_TO_SIGN from Jayran's node. Payload:", payload)
        elif peer == self.darian_peer:
            print("Received NONCE_TO_SIGN from Darian's node. Payload:", payload)
        else:
            print("Ignoring NONCE_TO_SIGN from non-teammate peer")
            return

        signature = self.sign_nonce(payload.nonce) 
        signature_submission_payload = SignatureSubmissionPayload(payload.round_number, signature)
        self.group_id = payload.group_id
        self.ez_send(peer, signature_submission_payload)
        print("Sent signature submission to peer:", peer)

    @lazy_wrapper(SignatureSubmissionPayload)
    def on_signature_submission(self, peer, payload):
        if peer == self.jayran_peer:
            print("Received SIGNATURE_SUBMISSION from Jayran's node. Payload:", payload)
            self.signatures[1] = payload.signature # put jayran's signature in the second position (member 2)
        elif peer == self.darian_peer:
            print("Received SIGNATURE_SUBMISSION from Darian's node. Payload:", payload)
            self.signatures[0] = payload.signature # put darian's signature in the first position (member 1)
        else:
            print("Ignoring SIGNATURE_SUBMISSION from non-teammate peer")
            return
        
        if (any(signature is None for signature in self.signatures)):
            return
        
        else:
            print("Received all signatures! Submitting to server...")
            signature_bundle_payload = SignatureBundlePayload(self.group_id, payload.round_number, self.signatures[0], self.signatures[1], self.signatures[2])
            self.ez_send(self.server_peer, signature_bundle_payload)

    @lazy_wrapper(ChallengeResponsePayload)
    def on_challenge_response(self, peer, payload):
        if peer != self.server_peer:
            print("Ignoring CHALLENGE_RESPONSE from non-server peer")
            return
        
        self.round_number = payload.round_number

        if self.round_number != 3 or self.success:
            print("Not round number 3: ignoring challenge response from round: ", payload.round_number)
            return

        self.signatures[2] = self.sign_nonce(payload.nonce) # Put my own signature last (member 3)
        payload = NonceToSign(payload.nonce, payload.round_number, self.group_id)
        self.ez_send(self.jayran_peer, payload)
        self.ez_send(self.darian_peer, payload)
        print("Sent NONCE_TO_SIGN to teammates.")

    @lazy_wrapper(RoundResultPayload)
    def on_round_result(self, peer, payload):
        if peer != self.server_peer:
            print("Ignoring ROUND_RESULT from non-server peer")
            return

        print("ROUND RESULT:")
        print(payload) 
        if (payload.success and payload.rounds_completed == 3):
            print("Challenge completed successfully!")
            self.success = True
            return

    def sign_nonce(self, nonce: bytes) -> bytes:
        return self.crypto.create_signature(self.my_peer.key, nonce)

    async def find_teammates_and_server(self):
        found_jayran, found_darian, found_server = False, False, False
        while not (found_jayran and found_darian and found_server):
            peers = self.get_peers()
            print(f"Discovered {len(peers)} peer(s)")

            for peer in peers:
                peer_key = peer.public_key.key_to_bin().hex()

                if peer_key == SERVER_PUBLIC_KEY_HEX:
                    print("FOUND THE SERVER!")
                    self.server_peer = peer
                    found_server = True

                elif peer_key == MEMBER_1_PUBLIC_KEY_HEX:   
                    print("Found Darian's node!")
                    self.darian_peer = peer
                    found_darian = True

                elif peer_key == MEMBER_2_PUBLIC_KEY_HEX:
                    print("Found Jayran's node!")
                    self.jayran_peer = peer
                    found_jayran = True

                else:
                    print("Other peer found, skipping ..")

            await asyncio.sleep(1)

        print("Found all required peers!")

async def main():
    builder = ConfigBuilder()

    builder.clear_keys()
    builder.clear_overlays()

    builder.add_key(
        "mynode",
        "curve25519",
        "lab1_key.pem"
    )

    builder.add_overlay(
        "LabCommunity",
        "mynode",
        [
            WalkerDefinition(Strategy.RandomWalk, 10, {"timeout": 3.0})
        ],
        default_bootstrap_defs,
        {},
        []
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "LabCommunity": LabCommunity
        }
    )

    await ipv8.start()
 
    overlay = ipv8.get_overlay(LabCommunity)
    print("IPv8 started.")

    my_peer = overlay.my_peer
    public_bytes = my_peer.public_key.key_to_bin()
    print(f"Connecting With Public Key: {public_bytes.hex()}") 
    
    await overlay.find_teammates_and_server()

    try:   
        while overlay.success == False:
            if overlay.group_id != 0:
                payload = ChallengeRequestPayload(overlay.group_id)
                overlay.ez_send(overlay.server_peer, payload)
                print("Sent challenge request to server with group ID:", overlay.group_id)

            await asyncio.sleep(0.05)
            
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Interrupted by user.\n")
    finally:
        await ipv8.stop()
        print("IPV8 Stopped.")

if __name__ == "__main__":
    asyncio.run(main())