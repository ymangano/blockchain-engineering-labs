from ipv8.messaging.lazy_payload import VariablePayload, vp_compile


@vp_compile
class RegisterBlockchainPayload(VariablePayload):
    msg_id = 1
    format_list = ["varlenHutf8", "varlenH"]
    names = ["group_id", "community_id"]


@vp_compile
class RegisterResponsePayload(VariablePayload):
    msg_id = 2
    format_list = ["?", "varlenHutf8"]
    names = ["success", "message"]
