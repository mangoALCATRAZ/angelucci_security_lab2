/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.net.*;
import java.io.*;
/**
 *
 * @author woah dude
 */
public class listenerThread extends Thread{
    private Socket sock;
    private volatile boolean endFlag;
    private String privateKey = "";
    private HMAC hmac;
    
    public listenerThread(Socket inSock, HMAC in){
        sock = inSock;
        endFlag = false;
        
        hmac = in;
    }
    
    @Override
    public void run() {
        try{
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            
            System.out.println("\nListener Thread Ready.");
            
            while(!endFlag){
                String received = in.readLine(); //incoming ciphertext
//                System.out.println("received cyphertext: " + received);
                
                // DECRYPTION GOES HERE, PRINT OUT RESULTING PLAINTEXT INSTEAD OF received
                
                
                // we might need to allow input of a normal key below
                
                String key
                        = "00010011"
                        + "00110100"
                        + "01010111"
                        + "01111001"
                        + "10011011"
                        + "10111100"
                        + "11011111"
                        + "11110001";
                
                privateKey = DESencryptedChat.getKey();
                KeyGenerator kg = new KeyGenerator(privateKey);
                
                
                String[] ReversedRoundKeyArray = kg.keyGenerator(kg.getKey());
                
//                String[] ReversedRoundKeyArray = KeyGenerator.keyGenerator(KeyGenerator.getKey());
                
                ReversedRoundKeyArray = KeyGenerator.roundKeyArrayReversal(ReversedRoundKeyArray);
                String pt = EncryptDecrypt.Decrypt(received, ReversedRoundKeyArray);
               // String rawMessage = ChatHelper.binaryStringToText(pt);
                
                
               
                String hmacChecksum = pt.substring(0, 255);
                String bitMessage = pt.substring(256, pt.length());
                
                System.out.println("\n\nCiphertext received: " + received);
                System.out.println("HMAC and plaintext append received: " + pt);
                System.out.println("Plain message received: " + bitMessage);
                
                System.out.println("HMAC checksum received: " + hmacChecksum);
                
                String newChecksum = hmac.run(bitMessage);
                
                System.out.println("New derived HMAC: " + newChecksum);
                if(newChecksum.equals(hmacChecksum)){
                    System.out.println(sock.getInetAddress().toString() + ": " + ChatHelper.binaryStringToText(bitMessage));
                }
                else{
                    System.out.println("\n\nerror with hmac");
                }
                
                
                
                
                
                
            }
            
            sock.close();
            System.out.println("Server-aspect done running.");

            
        }
        catch(IOException e){
            
            System.out.print("\nListener thread: " + e);
            
            
        }
   }
    
    // called by other thread
    public void end(){
        endFlag = true;
    }
}
    

