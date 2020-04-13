/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;
import java.io.IOException;
import java.net.*;
import java.util.*;
/**
 *
 * @author woah dude
 */
public class NetworkMethods {
    public static Socket hostMethod(int inPort) throws IOException{
        Socket ret = null;
        
     
        
        try{
            ServerSocket serverSocket = new ServerSocket(inPort);
            System.out.println("\n\nAwaiting connection...");
            ret = serverSocket.accept();
            
            System.out.println("\n" + ret.getInetAddress().toString() + " connected!");
        }
        catch(IOException e){
            System.out.println("\n" + e);
            throw e;
        
        }
        return ret;
    }
    
    


public static Socket joinMethod(int inPort, Scanner scan) throws IOException{
        Socket ret = null;
        String ip;
        
        try{
            //System.out.println("\n\nPlease enter ip: ");
            ip = scan.nextLine();
            
            ret = new Socket(ip, inPort);
            System.out.println("\n\nConnected");
        }
        catch(IOException e){
            System.out.println("\n" + e);
            throw e;
        }
        
        return ret;
        
        
        
        
       
        
       
    }
}