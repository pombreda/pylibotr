from pylibotr import *
from ctypes import *

class OTR(object):
    def __init__(self):
	otrl_init(3, 0, 0)
	self.us = otrl_userstate_create()
        print type(self.us)
        print dir(self.us)
        print type(self.us.contents)

    def __del__(self):
        print type(self.us)

    def free(self):
        print "Freeing memory"
        otrl_userstate_free(self.us)

    def genPrivKey(self, fname="/tmp/fname1", acct="acct2@gmail.com", proto="gmail.com"):
	otrl_privkey_generate(self.us, fname, acct, proto)

    def setupUIops(self):
        o = OtrlMessageAppOps()
        o.create_privkey = o.create_privkey.__class__(self.create_priv_key)
        o.policy = o.policy.__class__(self.policy)
        o.is_logged_in = o.is_logged_in.__class__(lambda *args: self.notice('is_logged_in', args))
        o.inject_message = o.inject_message.__class__(lambda *args: self.notice('inject_message', args))
        o.notify = o.notify.__class__(lambda *args: self.notice('notify', args))
        o.display_otr_message = o.display_otr_message.__class__(lambda *args: self.notice('display_otr_message', args))
        o.update_context_list = o.update_context_list.__class__(lambda *args: self.notice('update_context_list', args))
        o.protocol_name = o.protocol_name.__class__(lambda *args: self.notice('protocol_name', args))
        o.protocol_name_free = o.protocol_name_free.__class__(lambda *args: self.notice('protocol_name_free', args))
        o.new_fingerprint = o.new_fingerprint.__class__(lambda *args: self.notice('new_fingerprint', args))
        o.write_fingerprint = o.write_fingerprints.__class__(lambda *args: self.notice('write_fingerprint', args))
        o.gone_secure = o.gone_secure.__class__(lambda *args: self.notice('gone_secure', args))
        o.gone_insecure = o.gone_insecure.__class__(lambda *args: self.notice('gone_insecure', args))
        o.still_secure = o.still_secure.__class__(lambda *args: self.notice('still_secure', args))
        o.log_message = o.log_message.__class__(lambda *args: self.notice('log_message', args))
        self.uiops = o

    def policy(self, opdata, context):
        print "policy username is: %s" % context.contents.username
        return OTRL_POLICY_ALLOW_V1 | OTRL_POLICY_ALLOW_V2 | OTRL_POLICY_REQUIRE_ENCRYPTION | OTRL_POLICY_ERROR_START_AKE

    def notice(self, msg, args):
        print msg, args

    def create_priv_key(self, *args):
        print "create_priv_key %s" % args


    def sendMsg(self, recipient_name="myrecipient", message="Test", accountname="mysender@gmail.com", protocolid="gmail.com"):
        """otrl_message_sending.argtypes = [OtrlUserState, POINTER(OtrlMessageAppOps), c_void_p, STRING, STRING, STRING, STRING, POINTER(OtrlTLV), POINTER(STRING), CFUNCTYPE(None, c_void_p, POINTER(ConnContext)), c_void_p]"""
        newmessage = c_char_p()
        opdata = create_string_buffer(100)
        tlvs = None
        add_app_info = CFUNCTYPE(None, c_void_p, POINTER(ConnContext))
        add_app_info_data = None
        res = otrl_message_sending(self.us, byref(self.uiops), opdata, accountname, protocolid, recipient_name, message, tlvs, byref(newmessage), add_app_info(), add_app_info_data)
        print "result of message_sending is : %s" % res
        print "newmessage is: %s" % newmessage
        if newmessage:
            print "new message is set sending again"
            res = otrl_message_sending(self.us, byref(self.uiops), opdata, accountname, protocolid, recipient_name, message, tlvs, byref(newmessage), add_app_info(), add_app_info_data)
            print "result of message_sending is : %s" % res
            print "newmessage is: %s" % newmessage
            otrl_message_free(newmessage)
            

    def threearg(self, a,b,c):
        print "called a with args"

def thunk(*args):
    print args

if __name__ == "__main__":
    otr = OTR()
    otr.setupUIops()
    otr.sendMsg()
    otr.free()
