/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.io.IOException;
import java.util.*;
import java.net.*;
import java.util.concurrent.TimeUnit;

import java.sql.Timestamp;
import java.util.logging.Level;
import java.util.logging.Logger;
/**
 *
 * @author woah dude
 */
public class V_Server {
    public static Scanner scan = new Scanner(System.in);
    
    private static String K_v = "";
    private static String ticket_v_encrypted = "";
    private static String ticket_v_decrypted;
    
    private static String K_c_v = "";
    private static String ID_c = "";
    private static String AD_c = "";
    private static String ID_v = "";
    private static int lifetime_4;
    private static String ts4_string = "";
    private static long ts4_long;
    
    private static String ID_c_from_auth = "";
    private static String AD_c_from_auth = "";
    private static String ts5_string_from_auth;
    
    
    private static String authenticator_c_encrypted = "";
    private static String authenticator_c_decrypted = "";
    
    private static boolean done;
    
    public static void main(String[] args) throws IOException{
        done = false;
        
        System.out.println("\nV Server");
        System.out.println("\n\nPlease enter the K_v key:");
        
        String k_v_semiKey = scan.nextLine();
        K_v = ChatHelper.keyConverter(k_v_semiKey);
        
        Socket cSocket = null;
        String input;
        int port = 5001;
        
        while(done == false){
            while(cSocket == null){
                cSocket = NetworkMethods.hostMethod(port);
                
            }
            System.out.println("\nV connected to C_Client!");
            try{
                // Step 5: C -> V and Step 6: V -> C
                
                vServer(cSocket);
                done = true;
            }
            catch(Exception e){
                System.out.println(e.getMessage());
                done = true;
            } catch (Throwable ex) {
                Logger.getLogger(V_Server.class.getName()).log(Level.SEVERE, null, ex);
                done = true;
            }
        }
    }
    
    public static void vServer(Socket cSock) throws IOException, InterruptedException, Throwable{
        listenerThread listener = new listenerThread(cSock, K_v);
        listener.setDecryptFlag(false);
        listener.start();
        
        SenderClass sender = new SenderClass(cSock);
        while(listener.shareGet() == null){
            TimeUnit.SECONDS.sleep(1);
        }
        
        // Step 5: C -> V
        
        // got message from C
        
        String response_from_c = listener.shareGet();
        
        // parse message from c
        
        if(checkNoOfDelims(response_from_c, 1) == true){
            System.out.println("\nResponse from c plaintext:");
            StringTokenizer st_response = new StringTokenizer(response_from_c, ";");
            
            for(int i = 0; st_response.hasMoreElements(); i++){
                switch(i){    
                    case 0:
                        ticket_v_encrypted = st_response.nextToken();
                        System.out.println("Received encrypted ticket_v:" + ticket_v_encrypted);
                        break;
                    
                    case 1:
                        authenticator_c_encrypted = st_response.nextToken();
                        System.out.println("Received encrypted authenticator_c_2:" + authenticator_c_encrypted);
                }
            }
            
            //decrypt ticket_v
            KeyGenerator kg_ticket_v = new KeyGenerator(K_v);
            String[] ReversedRoundKeyArr_ticket_v = kg_ticket_v.keyGenerator(kg_ticket_v.getKey());
            ReversedRoundKeyArr_ticket_v = KeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArr_ticket_v);
            String pt_ticket_v_unconverted = EncryptDecrypt.Decrypt(ticket_v_encrypted, ReversedRoundKeyArr_ticket_v);
            ticket_v_decrypted = ChatHelper.binaryStringToText(pt_ticket_v_unconverted);
            
            System.out.println("\nticket_v plaintext:" + ticket_v_decrypted);
            //parse decrypted ticket_v
            if(checkNoOfDelims(ticket_v_decrypted, 5) == true){
                StringTokenizer st_ticket_v = new StringTokenizer(ticket_v_decrypted, ";");
                for(int i = 0; st_ticket_v.hasMoreTokens(); i++){
                    switch(i){
                        case 0:
                            K_c_v = st_ticket_v.nextToken();
                            System.out.println("K_c_v:" + K_c_v);
                            break;
                        case 1:
                            ID_c = st_ticket_v.nextToken();
                            System.out.println("ID_c:" + ID_c);
                            break;
                        case 2:
                            AD_c = st_ticket_v.nextToken();
                            System.out.println("AD_c:" + AD_c);
                            break;
                        case 3:
                            ID_v = st_ticket_v.nextToken();
                            System.out.println("ID_v:" + ID_v);
                            break;
                        case 4:
                            ts4_string = st_ticket_v.nextToken();
                            ts4_long = Long.parseLong(ts4_string);
                            System.out.println("Timestamp_4:" + ts4_long);
                            break;
                        case 5:
                            lifetime_4 = Integer.parseInt(st_ticket_v.nextToken());
                            System.out.println("Lifetime_4:" + lifetime_4);
                            break;
                    }
                }
                
                //ticket validity check
                Timestamp tsCurrent = new Timestamp(System.currentTimeMillis());
                long tscLong = tsCurrent.getTime();
                
                long life = Long.valueOf(lifetime_4);
                long diff = tscLong - ts4_long;
                if(diff < life){
                    // ticket is still valid, proceed
                    
                    //decrypt authenticator
                    
                    KeyGenerator kg_authenticator_c = new KeyGenerator(K_c_v);
                    String[] ReversedRoundKeyArray_auth = kg_authenticator_c.keyGenerator(kg_authenticator_c.getKey());
                    ReversedRoundKeyArray_auth = KeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArray_auth);
                    String pt_auth_unconverted = EncryptDecrypt.Decrypt(authenticator_c_encrypted, ReversedRoundKeyArray_auth);
                    
                    authenticator_c_decrypted = ChatHelper.binaryStringToText(pt_auth_unconverted);
                    
                    //parse decrypted authenticator
                    if(checkNoOfDelims(authenticator_c_decrypted, 2) == true){
                        System.out.println("\nAuthenticator plaintext:" + authenticator_c_decrypted);
                        StringTokenizer st_auth = new StringTokenizer(authenticator_c_decrypted, ";");
                        for(int i = 0; st_auth.hasMoreElements(); i++){
                            switch(i){
                                case 0:
                                    ID_c_from_auth = st_auth.nextToken();
                                    System.out.println("Received ID_c:" + ID_c_from_auth);
                                    break;
                                case 1:
                                    AD_c_from_auth = st_auth.nextToken();
                                    System.out.println("Received AD_c:" + AD_c_from_auth);
                                    break;
                                case 2:
                                    ts5_string_from_auth = st_auth.nextToken();
                                    System.out.println("Timestamp_5" + ts5_string_from_auth);
                                    break;
                                    
                            }
                        }
                        
                        if((ID_c_from_auth.equals(ID_c)) && (AD_c_from_auth.equals(AD_c))){
                            //authenticated!
                            
                            System.out.println("\nThe client has been sucessfully authenticated.");
                            long ts5_long = Long.parseLong(ts5_string_from_auth);
                            long ts5_increm = ts5_long++;
                            
                            String ts5_increm_string = String.valueOf(ts5_increm);
                            System.out.println("Timestamp_5 + 1:" + ts5_increm_string);
                            sender.sendAThing(K_c_v, ts5_increm_string);
                            System.out.println("Sent!");
                            
                            
                            System.out.println("\n\nV is finished executing. Shutting down....");
                            
                        }
                    }
                }
                else{
                    System.out.println("\nErr: ticket_v is expired.");
                }
                
            }
            else{
                System.out.println("\nv ticket delims err");
            }
            
            
        }
        else{
            System.out.println("\nerr: number of delims is wrong");
        }
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
