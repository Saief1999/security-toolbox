# Steps for presentation
## 1. Pre-presentation
1. Start the KDC service (KDC owner)
2. Open the ports (KDC owner):
   1. 88/udp and 88/tcp for KDC
   2. 749/udp and 749/tcp for KADMIN 
3. Check that the **securitytools** service is defined on `/etc/services` (Both Clients)
4. Check that the port for the service **securitytools** is open (Both Clients)
5. Check that both hosts are reachable (Both Clients)
   1. Check `/etc/hosts`  and **Change both IPs if necessary**
   2. Ping `ramizouari.tn` and `saiefzneti.tn`  on both machines for sanity check.
6. For each service, `kinit` to get the TGT for that service
7. Check that the keytab file `/etc/krb5.keytab` is available on both machines, and it contains the latest key version of both hosts
## 2. Presentation
1. Show  `/etc/krb5.conf` for Realm configuration
2. Show `/etc/hosts` for  hosts definition
3. Show `/etc/services` to show the `securitytools` service
4. Open `kadmin` with user `securitytools/admin`
5. Open keytab `/etc/krb5.keytab` with `ktutil` and list entries
6. Show the diagram
7. Launch the application and enjoy your success :house: