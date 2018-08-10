/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;


/**
 *
 * @author Sudheer
 */
public class DesEncrypter {


     Cipher ecipher;
     private Key key;

  Cipher dcipher;

  byte[] salt = { (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x35,
      (byte) 0xE3, (byte) 0x03 };

  DesEncrypter(String passPhrase) throws Exception {
    int iterationCount = 2;
    //PBEWithMD5AndDES
    
     KeyGenerator generator;
                    generator = KeyGenerator.getInstance("DES");
                   SecureRandom sec = new SecureRandom(passPhrase.getBytes());
                    generator.init(sec);
                    key = generator.generateKey();
    //KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
    //key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
    ecipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    dcipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
      

    //AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);

    ecipher.init(Cipher.ENCRYPT_MODE, key);
    dcipher.init(Cipher.DECRYPT_MODE, key);

  }

  public String encrypt(String str) throws Exception {
      return Base64Coder.encodeString(str);//encodeString(str);
//       System.out.println(sss);
     //  return sss;
   // return new BASE64Encoder().encode(ecipher.doFinal(str.getBytes()));
  }

//  public String encrypt(byte[] dataBytesToEncrypt)throws Exception {
//       return new BASE64Encoder().encode(ecipher.doFinal(dataBytesToEncrypt));
//  }
//
//  public byte[] updateIt(byte[] h, int i, int i1){
//      return new BASE64Encoder().encode(ecipher.update(h,i,i1)).getBytes();
//  }
//  public byte[] Final(){
//     byte[] p=null;
//      try {
//         p  = ecipher.doFinal();
//        } catch (IllegalBlockSizeException ex) {
//            Exceptions.printStackTrace(ex);
//        } catch (BadPaddingException ex) {
//            Exceptions.printStackTrace(ex);
//        }
//        return p;
//  }

//  public String decrypt(byte[] dataBytesToDecypt)throws Exception {
//       return new BASE64Encoder().encode(ecipher.doFinal(dataBytesToDecypt));
//  }

  public String decrypt(String str) throws Exception {
       return Base64Coder.decodeString(str);
     // System.out.println(ss);
     // String h=  new String(dcipher.doFinal(new BASE64Decoder().decodeBuffer(str)));
       //return ss;
  }

//   public byte[] updateDe(String h){
//       byte[] pp=null;
//
//            try {
//                pp = dcipher.update(new BASE64Decoder().decodeBuffer(h));
//
//            } catch (Exception ex) {
//                Exceptions.printStackTrace(ex);
//            }
//
//
//       return pp;
//  }
//  public byte[] FinalDe(){
//     byte[] p=null;
//      try {
//         p  =   dcipher.doFinal();
//        } catch (IllegalBlockSizeException ex) {
//            Exceptions.printStackTrace(ex);
//        } catch (BadPaddingException ex) {
//            Exceptions.printStackTrace(ex);
//        }
//        return p;
//  }

//  public String encode(String str) {
//    BASE64Encoder encoder = new BASE64Encoder();
//        try {
//            str = new String(ecipher.doFinal(str.getBytes()));
//        } catch (IllegalBlockSizeException ex) {
//            Exceptions.printStackTrace(ex);
//        } catch (BadPaddingException ex) {
//            Exceptions.printStackTrace(ex);
//        }
//    return str;
//}
//
//public String decode(String str) {
//    BASE64Decoder decoder = new BASE64Decoder();
//
//            try {
//                str = new String(dcipher.doFinal(str.getBytes()));
//            } catch (IllegalBlockSizeException ex) {
//                Exceptions.printStackTrace(ex);
//            } catch (BadPaddingException ex) {
//                Exceptions.printStackTrace(ex);
//            }
//
//    return str;
//}

}
