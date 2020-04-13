/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.io.*;
import java.net.*;

/**
 * PrintWriter wrapper class
 * 
 * 
 * @author woah dude
 */
public class pWriter {
    private PrintWriter pw;
    
    public pWriter(){
        pw = null; // defaults to null
    }
    
    public void set(Socket in) throws IOException{
       pw = new PrintWriter(in.getOutputStream(), true);
    }
    
    public PrintWriter get(){
        return pw;
    }
    
}
