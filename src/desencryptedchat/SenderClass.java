/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.io.IOException;
import java.net.*;
import java.io.*;
/**
 *
 * @author woah dude
 */
public class SenderClass {
    private Socket sock;
    private pWriter wrapper;
    private PrintWriter print;
    
    public SenderClass(Socket inSock) throws IOException{
        sock = inSock;
        wrapper = new pWriter();
        wrapper.set(sock);
        print = wrapper.get();
    }
    public void sendAThing(String keyIn, String input) throws Exception, Throwable{
        try{
            EncryptDecrypt ed = new EncryptDecrypt(input, true);
        
            KeyGenerator kg = new KeyGenerator(keyIn);
            String[] RoundKeyArray = kg.keyGenerator(keyIn);
            
            //System.out.println("\nThis key:" + kg.toString());
            
            String ciphertext = ed.Encrypt(ed.getInitialMessage(), RoundKeyArray);
            System.out.println("\nSent ciphertext:" + ciphertext);
        
            print.println(ciphertext);
        }
        catch(Exception e){
            System.out.println(e.getMessage());
            
            
            this.finalize();
            
           
            
            throw e;
        }
    }
    public void sendAThingNoEncrypt(String input){
        print.println(input);
    }
    
    public void finalize() throws Throwable {
        super.finalize();
        
        sock.close();
        print.close();
        
    }
}
