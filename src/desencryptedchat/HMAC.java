/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package desencryptedchat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 *
 * @author Matt
 */
public class HMAC {
    private String Kpadded = "";
    private String ipad = "00110110" +
            "00110110" +
            "00110110" +
            "00110110" +
            "00110110" +
            "00110110" +
            "00110110" +
            "00110110";
    private String opad = "01011100" +
            "01011100" +
            "01011100" +
            "01011100" +
            "01011100" +
            "01011100" +
            "01011100" +
            "01011100";
            

    public HMAC(String keyIn){
        Kpadded = keyIn;
    }
    
    public String run(String in){ // null if error
        // ipad run first
        String retHMAC;
        try{
            String ipadHash = ipadRun(in);
            retHMAC = opadRun(ipadHash);
            
        }
        catch(NoSuchAlgorithmException e){
            System.out.println(e);
            retHMAC = null;
        }
        
        return retHMAC;
    }
    public String SHA256(String in) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        digest.update(in.getBytes(StandardCharsets.UTF_8));
        
        byte[] hash = digest.digest();
        
        
        return ChatHelper.byteArrToBinaryString(hash);

    }
    
    public String ipadRun(String in) throws NoSuchAlgorithmException{
        String Si = EncryptDecrypt.XOR(Kpadded, ipad);
        String beforeHash = Si.concat(in);
        
        String hash = SHA256(beforeHash);
        return hash;
    }
    
    public String opadRun(String ipadHashIn) throws NoSuchAlgorithmException{
        String s0 = EncryptDecrypt.XOR(Kpadded, opad);
        String beforeHash = s0.concat(ipadHashIn);
        String hash = SHA256(beforeHash);
        
        return hash;
        
    }
}
