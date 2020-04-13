# # Lab 5 - Kerberos Version 4 Implementation

This is an implementation of Kerberos Version 4 done in Java using Netbeans 8.2 

No outside libraries other than the standard Java library were used.

# How to Run:
1. For best results, open this project in Netbeans 8.2
2. Begin by building and running AGS_TGS_Server.java and V_Server.java. Then, once those are awaiting connection, run C_Client.java
3. Make sure that the user password between C_Client and AGS_TGS_Server is the same. Key K_v in AGS_TGS_Server and V_Server must also be the same.
4. If you are running each server and client on one local machine, "localhost" works as an ip address input for all connections.
5. From here, the interactions should run on its own, going through the steps of the Kerberos algorithm and producing output whenever
  each client/server sends/receives data.
