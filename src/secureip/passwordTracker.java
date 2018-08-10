/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import javax.swing.JOptionPane;
import secureip.common.SharedData;

/**
 *
 * @author I14746
 */
public class passwordTracker {
    RandomAccessFile pkey=null;
     DesEncrypter encrypter;
     String encrypted ="";
     private SharedData sharedData=SharedData.getSingletonObject();

   public String getCurrentKey(){
       String psw = null;
       File temp = new File(sharedData.getWD()+"/"+"preceptor.key");
       sharedData =sharedData.getSingletonObject();
       try {
            encrypter = new DesEncrypter("I14746");
        } catch (Exception ex) {
           
        }
      
       if(!temp.exists()){
            try {
            pkey = new RandomAccessFile(sharedData.getWD()+"/"+"preceptor.key","rw");
            pkey.seek(0);
            String defaultPass= "preceptor";
            //Sets the flag to notify that clean setup
            sharedData.cleanInstall =true;
            //Sets the flag to notify that clean setup Ends here
            try {
                encrypted = encrypter.encrypt(defaultPass);
            } catch (Exception ex) {
            }

               pkey.setLength(encrypted.length());
               pkey.write(encrypted.getBytes());
               pkey.close();
               psw = getCurrentPass();
             } catch (IOException ex) {
            }
            
       }

         else
       {
           psw=getCurrentPass();
           sharedData.cleanInstall=false;
       }
       return psw;
   }


    public boolean isPWDfileOnDisk(){
        File temp = new File(sharedData.getWD()+"/"+"preceptor.key");
        return temp.exists();
    }
    public String getCurrentPass() {
         try {
            encrypter = new DesEncrypter("I14746");
        } catch (Exception ex) {
        }
        String curPass = null;
        String ps=null;
        try {
           
            pkey = new RandomAccessFile(sharedData.getWD()+"/"+"preceptor.key","rw");
            pkey.seek(0);
            byte[] b = new byte[(int)pkey.length()];
            pkey.read(b, 0, (int) pkey.length());
            ps = new String(b);
            pkey.close();
            try {
                ps = encrypter.decrypt(ps);
            } catch (Exception ex) {
            }
           
        } catch (IOException ex) {
        }
         return ps;
    }

    void setNewPassWord(String text) {
        try {
            encrypter = new DesEncrypter("I14746");
        } catch (Exception ex) {
        }
        try {
            text = encrypter.encrypt(text);
        } catch (Exception ex) {
        }
        try {
            pkey = new RandomAccessFile(sharedData.getWD() + "/" + "preceptor.key", "rw");
            pkey.seek(0);
            pkey.setLength(text.length());
            pkey.write(text.getBytes());
            pkey.close();

          } catch (IOException ex) {
        }
    }

     void setProperties(String text) {
        try {
            encrypter = new DesEncrypter("I14746");
        } catch (Exception ex) {
        }
        try {
            text = encrypter.encrypt(text);
        } catch (Exception ex) {
        }
        try {
            pkey = new RandomAccessFile(sharedData.getWD() + "/" + "preceptor.properties", "rw");
            pkey.seek(0);
            pkey.setLength(text.length());
            pkey.write(text.getBytes());
            pkey.close();
          } catch (IOException ex) {
        }
    }


     public String getCurrentProps() {
         try {
            encrypter = new DesEncrypter("I14746");
        } catch (Exception ex) {
        }
        String curPass = null;
        String ps=null;
        try {

        pkey = new RandomAccessFile(sharedData.getWD()+"/"+"preceptor.properties","rw");
        pkey.seek(0);
        byte[] b = new byte[(int)pkey.length()];
        pkey.read(b, 0, (int) pkey.length());
        ps = new String(b);
        try {
            ps = encrypter.decrypt(ps);
        } catch (Exception ex) {
        }

        } catch (IOException ex) {
        }
        try {
            pkey.close();
        } catch (IOException ex) {
        }
         return ps;
    }
}
