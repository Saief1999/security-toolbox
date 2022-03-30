import kerberos as krb
import base64

r1:int
r2:int
service_name="securitytools@ramizouari.tn"
client_name="securitytools/saiefzneti.tn@RAMIZOUARI.TN"

r1,s_context=krb.authGSSServerInit(service_name)
r2,c_context=krb.authGSSClientInit(service_name,client_name)

krb.authGSSClientStep(c_context,"")
C1=krb.authGSSClientResponse(c_context)


krb.authGSSServerStep(s_context,C1)
S1=krb.authGSSServerResponse(s_context)

krb.authGSSClientStep(c_context,S1)

msg="Saief Zneti"
encoded=base64.b64encode(msg.encode("ascii")).decode()
krb.authGSSClientWrap(c_context,encoded)
cipher=krb.authGSSClientResponse(c_context)

#print(cipher)
krb.authGSSClientUnwrap(s_context,cipher)
recovered=krb.authGSSClientResponse(s_context)
print(base64.b64decode(recovered).decode("ascii"))