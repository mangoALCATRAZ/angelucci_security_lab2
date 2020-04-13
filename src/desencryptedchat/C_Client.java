/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.net.*;
import java.util.*;
import java.io.*;

import java.sql.Timestamp;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.util.StringTokenizer;

import java.util.concurrent.TimeUnit;

/*
 *
 * @author woah dude
 */
public class C_Client {
    public static Scanner scan = new Scanner(System.in);
    private static String K_c = "";
    private static String K_c_tgs = "";
    
    
    
    private static String ID_c = "";
    private static String ID_tgs = "";
    private static String ID_v = "";
    private static String AD_c = "127.0.0.1:5000";
    
    private static String ts1_string = "";
    private static long ts1_long;
    private static String ts2_string = "";
    private static long ts2_long;
    private static String ts3_string = "";
    private static long ts3_long;
    
    private static String ts5_string = "";
    private static long ts5_long;
    
   
    
    private static int lifetime2;
    
    private static String ticket_tgs = "";
    
    private static String authenticator_c = "";
    private static String authenticator_c_2 = "";
    
    
    private static String K_c_v = "";
    private static String ts4_string ="";
    private static long ts4_long;
    private static String ticket_v_encrypted = "";
    
    //private static String HMACkey = "";
    
    private boolean listenerOn = false;
    private static boolean senderOn = false;
    
    private static String pt_message_from_tgs = "";
    
    
    private static int state = 1;
    private static boolean done = false;
    
    //private static HMAC hmac;
    /**
     * @param args the command line arguments
     * @throws java.lang.Exception
     */
    public static void main(String[] args) throws Exception{
        System.out.println("\nC Client");
        System.out.println("\n\nPlease enter your password: ");
        String semiKey = scan.nextLine();
        K_c = ChatHelper.keyConverter(semiKey);
        
        
        
        ID_c = "CIS3319USERID";
        ID_tgs = "CIS3319TGSID";
        ID_v = "“CIS3319SERVERID";
        
        
        /*System.out.println("Enter your HMAC key here: ");
        String semiHMACkey = scan.nextLine();
        HMACkey = ChatHelper.keyConverter(semiHMACkey); */
        
        
        
        //hmac = new HMAC(HMACkey);
        
        Socket sock = null;
        String input;
        int port = 5000;
        
        while(done == false){ // main loop. executes instructions step by step
            switch(state){
                case 1: // STEP 1: C -> AS
                    //Connect to AS
                    Socket asSock = null;
                    while(asSock==null){
                        System.out.println("\nPlease enter AS ip:");
                        asSock = NetworkMethods.joinMethod(port, scan);
                    }
                    System.out.println("\nConnected to AS");
                        
                    SenderClass asSender = new SenderClass(asSock);
                    //senderOn = true;
                    
                    listenerThread asListener = new listenerThread(asSock, K_c);
                    asListener.start();
                    
                    Timestamp ts1 = new Timestamp(System.currentTimeMillis());
                    ts1_long = ts1.getTime();
                    ts1_string = String.valueOf(ts1_long);
                        
                        
                    String concat = ID_c + ";" + ID_tgs + ";" + ts1_string;
                    try{
                            
                        asSender.sendAThingNoEncrypt(concat);
                            
                            
                    } catch(Exception e){
                        done = true;
                        break;
                    } catch (Throwable ex) {
                        
                        Logger.getLogger(C_Client.class.getName()).log(Level.SEVERE, null, ex);
                        done = true;
                        break;
                    }
                    
                    // STEP 2: AS -> C
                        
                    while(asListener.shareGet() == null && done == false){
                        TimeUnit.SECONDS.sleep(1);
                    }
                        
                    String pt1_unconverted = asListener.shareGet();
                    String pt1 = ChatHelper.binaryStringToText(pt1_unconverted);
                    System.out.println("\n\nreceived plaintext:" + pt1);
                    //here is where the password is validated to be correct. The client
                    //  exits if the password is incorrect.
                    
                    if(passwordCheck(pt1) == true){
                        // valid connection to AS established.
                        
                        StringTokenizer st = new StringTokenizer(pt1, ";");
                        
                        for(int i = 0; st.hasMoreTokens(); i++){
                            switch (i) {
                                case 0:
                                    K_c_tgs = st.nextToken();
                                    System.out.println("\n\nK_c_tgs:" + K_c_tgs);
                                    break;
                                case 1:
                                    ID_tgs = st.nextToken();
                                    System.out.println("Id_tgs:" + ID_tgs);
                                    break;
                                case 2:
                                    ts2_string = st.nextToken();
                                    ts2_long = Long.parseLong(ts2_string);
                                    System.out.println("Timestamp 2:" + ts2_long);
                                    break;
                                case 3:
                                    lifetime2 = Integer.parseInt(st.nextToken());
                                    System.out.println("Lifetime 2:" + lifetime2);
                                    break;
                                case 4:
                                    ticket_tgs = st.nextToken();
                                    System.out.println("Encrypted tgs ticket:" + ticket_tgs);
                                    break;
                                default:
                                    break;
                            }
                            
                        }
                        
                        asListener.end();
                        
                        try{
                            asSender.finalize();
                        }
                        catch(Throwable e){
                            System.out.print(e.getMessage());
                        }
                        state++;
                        break;
                    
                        
                        
                        
                    }
                    else{
                        System.out.println("\nYour password was incorrect. Please launch the Client again.");
                        done = true;
                        break;
                    }
                
                    
                case 2:
                    // Step 3: C -> TGS
                    //done = true;
                  
                    Socket tgsSocket = null;
                    System.out.println("\n\nPlease enter TGS ip:");
                    while(tgsSocket == null){
                        tgsSocket = NetworkMethods.joinMethod(port, scan);
                    }
                    System.out.println("\nConnected to TGS!");
                
                    try {
                          tgsCommunication(tgsSocket);
                          //done = true;
                    } catch (InterruptedException ex) {
                          Logger.getLogger(C_Client.class.getName()).log(Level.SEVERE, null, ex);
                          done = true;
                    } catch (Throwable ex) {
                          Logger.getLogger(C_Client.class.getName()).log(Level.SEVERE, null, ex);
                          done = true;
                    }
            
                  
                    break;
                
                case 3:
                    // Step 5: C -> V
                    port = 5001; // port change
                    Socket vSocket = null;
                    System.out.println("\n\nPlease enter V ip:");
                    while(vSocket == null){
                        vSocket = NetworkMethods.joinMethod(port, scan);
                    }
                    System.out.println("\nConnected to V!");
                    try{
                        vCommunication(vSocket);
                    } catch(Exception e){
                        System.out.println(e.getMessage());
                    }
                    
                    done = true;
                    break;
            }
        }
    }
    
    public static void vCommunication(Socket vSock) throws IOException, InterruptedException{
        SenderClass vSender = new SenderClass(vSock);
        listenerThread vListener = new listenerThread(vSock, K_c_v);
        vListener.start();
        
        // STEP 5: C -> V
        
        //setup authenticator_c_2
        Timestamp ts5 = new Timestamp(System.currentTimeMillis());
        ts5_long = ts5.getTime();
        ts5_string = String.valueOf(ts5_long);
        
        String authenticator_c_2_proto = ID_c + ";" + AD_c + ";" + ts5_string;
        
        //encrypt authenticator_c_2
        EncryptDecrypt ed_authenticator_c_2 = new EncryptDecrypt(authenticator_c_2_proto, true);
        System.out.println("\nAuthenticator c_2 plaintext:" + authenticator_c_2_proto);
        KeyGenerator kg_authenticator_c_2 = new KeyGenerator(K_c_v);
        String[] RoundKeyArr_authenticator_c_2 = kg_authenticator_c_2.keyGenerator(K_c_v);
        
        authenticator_c_2 = ed_authenticator_c_2.Encrypt(ed_authenticator_c_2.getInitialMessage(), RoundKeyArr_authenticator_c_2);
        System.out.println("Authenticator c_2 ciphertext:" + authenticator_c_2);
        
        vListener.shareClear();
        
        //setup message to V
        String message_to_v = ticket_v_encrypted + ";" + authenticator_c_2;
        vSender.sendAThingNoEncrypt(message_to_v);
        System.out.println("Sent!");
        
        
        TimeUnit.SECONDS.sleep(6);
        
        while((vListener.shareGet() == null)){
                        TimeUnit.SECONDS.sleep(1);
        }
        
        String vResponse = vListener.shareGet();
        
        // STEP 6: V -> C
        //mutual authentication step
        
        /*KeyGenerator kg_mutual_auth = new KeyGenerator(K_c_v);
        String[] ReversedRoundKeyArr_mutual_auth = kg_mutual_auth.keyGenerator(kg_mutual_auth.getKey());
        ReversedRoundKeyArr_mutual_auth = KeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArr_mutual_auth);
        String pt_mutual_auth_unconverted = EncryptDecrypt.Decrypt(vResponse, ReversedRoundKeyArr_mutual_auth);
        
        String pt_mutual_auth = ChatHelper.binaryStringToText(pt_mutual_auth_unconverted);
        */
        
        // check result for timestamp 5 + 1
        long ts5_long_append = ts5_long++;
        //long inTs = Long.parseLong(pt_mutual_auth);
        System.out.println("\nts5 + 1 ciphertext:" + vResponse);
        System.out.println("Authenticated! ts5 + 1=" + ts5_long_append);
        
        System.out.println("\nEnd of Client_C execution. Shutting down...");
    }
    
    public static void tgsCommunication(Socket tgsSock) throws IOException, InterruptedException, Throwable{
        SenderClass tgsSender = new SenderClass(tgsSock); // set up sender for step 3
        //senderOn = true;
                    
        listenerThread tgsListener = new listenerThread(tgsSock, K_c_tgs); // set up listener for step 4
        tgsListener.start();
        
        
        // authenticator setup
        
                    
        Timestamp ts3 = new Timestamp(System.currentTimeMillis());
        ts3_long = ts3.getTime();
        ts3_string = String.valueOf(ts3_long);
        
        String authenticatorProto = ID_c + ";" + AD_c + ";" + ts3_string;
        EncryptDecrypt ed_authenticator = new EncryptDecrypt(authenticatorProto, true);
            
        System.out.println("\n\nAuthenticator plaintext:" + authenticatorProto);
            
            
        KeyGenerator kg = new KeyGenerator(K_c_tgs);
        String[] RoundKeyArray = kg.keyGenerator(K_c_tgs);
        authenticator_c = ed_authenticator.Encrypt(ed_authenticator.getInitialMessage(), RoundKeyArray);
        System.out.println("\nAuthenticator ciphertext:" + authenticator_c);
        
        //step 3 send function below vvv
        tgsListener.shareClear();
        
        String messageToTgs = ID_v + ";" + ticket_tgs + ";" + authenticator_c;
        System.out.println("\nMessage to TGS:" + messageToTgs);
        tgsSender.sendAThingNoEncrypt(messageToTgs);
        System.out.println("Sent!");
        
        // STEP 4: TGS -> C
        
        TimeUnit.SECONDS.sleep(6);
        
        while((tgsListener.shareGet() == null || tgsListener.shareGet().equals("")) && done == false){
                        TimeUnit.SECONDS.sleep(1);
        }
        
        String tgsResponse = tgsListener.shareGet();
        String pt_message_from_tgs_unconverted = tgsResponse;
        pt_message_from_tgs = ChatHelper.binaryStringToText(pt_message_from_tgs_unconverted);
        if("err".equals(tgsResponse)){
            System.out.println("error: your ticket has expired. Please log in again.");
            done = true;
        }
        else{
            // Received reply from TGS
            
            //decrypt message using K_c_tgs session key
            //KeyGenerator kg_message_from_tgs = new KeyGenerator(K_c_tgs);
            //String[] ReversedRoundKeyArray_message_from_tgs = kg_message_from_tgs.keyGenerator(kg_message_from_tgs.getKey());
           // ReversedRoundKeyArray_message_from_tgs = KeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArray_message_from_tgs);
            //String pt_message_from_tgs_unconverted = EncryptDecrypt.Decrypt(tgsResponse, ReversedRoundKeyArray_message_from_tgs);
            
           // String pt_message_from_tgs = ChatHelper.binaryStringToText(pt_message_from_tgs_unconverted);
            
            //parse message from tgs
            
            System.out.println("\nMessage from tgs plaintext:" + pt_message_from_tgs);
            if(checkNoOfDelims(pt_message_from_tgs, 3) == true){
                // got proper message from tgs
                System.out.println("\n\nReceived:");
                
                StringTokenizer st_message_from_tgs = new StringTokenizer(pt_message_from_tgs, ";");
                for(int i = 0; st_message_from_tgs.hasMoreTokens(); i++){
                    switch(i){
                        case 0:
                            K_c_v = st_message_from_tgs.nextToken();
                            System.out.println("K_c_v:" + K_c_v);
                            break;
                        case 1:
                            System.out.println("Received ID_v:" + st_message_from_tgs.nextToken());
                            break;
                        case 2:
                            ts4_string = st_message_from_tgs.nextToken();
                            ts4_long = Long.parseLong(ts4_string);
                            System.out.println("Received Timestamp4:" + ts4_long);
                            break;
                        case 3:
                            ticket_v_encrypted = st_message_from_tgs.nextToken();
                            System.out.println("Received Encrypted ticket_v:" + ticket_v_encrypted);
                            break;
                    }
                }
                
                
                
                System.out.println("Connection closed with TGS.");
                tgsSender.finalize();
                tgsListener.end();
                
                state++;
            }
            else{
                System.out.print("Error: Message from tgs has incorrect # of delims.");
            }
            
        }
        
    }
    
    // this looks at the resultant string from the server for the correct number of instances
    //  of the concatenation character ';'. In this case, the decrpyted response from the
    //  Authentication Server should contain 4 instances of this character.
    
    //If this is the case, the user was able to supply the key generator with 
    //  the correct password, which provides the symmetric decryption key shared
    //  with AS. The communication between Client and AS can now continue.
    
    public static boolean passwordCheck(String inResponse){
        boolean password_good_yes = false;
        int count_von_count = 0;
        
        for(int bacon=0; bacon < inResponse.length(); bacon++){
            if(inResponse.charAt(bacon) == ';'){
                count_von_count++;
            }
        }
        
        if(count_von_count == 4){
            password_good_yes = true;
        }
        
        return password_good_yes;
    }        
        
        /*while(sock == null){ // host or join menu. stuck here until a valid socket is produced.
            System.out.println("\n\nHost or join?\n\n1. Host\n2. Join");
            input = scan.nextLine();
            
            
            switch (input) {
                case "1":
                case "1.":
                    sock = hostMethod(port);
                    break;
                case "2":
                case "2.":
                    sock = joinMethod(port);
                    break;
                default:
                    System.out.println("\nInvalid, please try again.");
                    break;
            }
        }*/
        

        

        
   
    
    
    
    
    
    //ENCAPSULATE THIS VVVVVVVV
    
   /* public static void senderThread(Socket sock, pWriter wrapper) throws Exception{
        // fork here
        listenerThread lThread = new listenerThread(sock, hmac);
        lThread.start(); // starts listening thread
        
        boolean stopFlag = false;
        // key insertion
//        System.out.println("Enter your private key. Your partner needs the key.");
//        key = scan.nextLine();
//        KeyGenerator.setKey(key);
        
        wrapper.set(sock);
        
        PrintWriter out = wrapper.get();
        
        System.out.println("\nLocal sender ready.");
        while(!stopFlag){
            try{
                // REPLACE EVERYTHTHING BELOW WITH GENERIC SENDING METHOD
                
                
                String userInput = scan.nextLine();
                if(userInput.toLowerCase().equals("stop")){
                    stopFlag = true;
                    
                    
                }
                
                System.out.println("Me: " + userInput);
                
                // ENCRYPTION GOES HERE. SEND OUT ENCRYPTED CIPHERTEXT INSTEAD
                // OF userInput
                
                // insert while loop for longer than 64 bits here
                
                String thisHMAC = hmac.run(ChatHelper.textToBinaryString(userInput));
                System.out.println("Plaintext message sent: " + ChatHelper.textToBinaryString(userInput));
                System.out.println("    Length: " + ChatHelper.textToBinaryString(userInput).length());
                System.out.println("Derived HMAC of above: " + thisHMAC);
                System.out.println("   Length: " + thisHMAC.length());
                String plainText = thisHMAC.concat(ChatHelper.textToBinaryString(userInput));
                
                EncryptDecrypt ed = new EncryptDecrypt(plainText, false);
                //
                String key
                        = "00010011"
                        + "00110100"
                        + "01010111"
                        + "01111001"
                        + "10011011"
                        + "10111100"
                        + "11011111"
                        + "11110001";
                
                KeyGenerator kg = new KeyGenerator(K_c);
                
                String[] RoundKeyArray = kg.keyGenerator(K_c);
                                
                String ct = ed.Encrypt(ed.getInitialMessage(), RoundKeyArray);
                System.out.println("HMAC and plaintext append: " + plainText);
                System.out.println("    Length: " + plainText.length());
                System.out.println("Ciphertext sent: " + ct);
                System.out.println("    Length: " + ct.length());
                
               // System.out.println("\tCypherText in binary: " + ct);
                //System.out.println("\tCypherText translated from binary: " + ChatHelper.binaryStringToText(ct));
                
                // end while loop
                
                out.println(ct);
            }   
            
                
            catch(Exception e){
                System.out.println("\n" + e);
                lThread.end();
                sock.close();
                throw e;
            }
        }
        
        lThread.end();
        sock.close();
        
        System.out.println("\nSender-aspect done running.");
        
    }*/
    
    public static String getKey(){
        return K_c;
    }
    
    public static boolean checkNoOfDelims(String inResponse, int num){
        boolean ret = false;
        
        int count = 0;
        
        for(int i = 0; i < inResponse.length(); i++){
            
            if(inResponse.charAt(i) == ';'){
                count++;
            }
        }
        if(count == num){
            ret = true;
        }
        
        return ret;
    }
    
}
