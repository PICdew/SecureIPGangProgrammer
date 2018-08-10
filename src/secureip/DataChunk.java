/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import com.microchip.mplab.mdbcore.memory.PhysicalMemory;
import com.microchip.mplab.mdbcore.memory.memorytypes.ProgramMemory;
import secureip.common.SharedData;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.LinkedList;
import org.openide.util.Exceptions;

/**
 *
 * @author I14746
 */
public class DataChunk {

    AESCrypt aes = null;
    LinkedList data_list = new LinkedList();
    data_core dc = new data_core();

    public void fill_data_chunk(){

       CDevice deviceInfo = new CDevice();
       deviceInfo.getDeviceInfo();
       //byte[] data = new byte[0x1600 - 0x1200];
       PhysicalMemory pm = deviceInfo.getMemory(ProgramMemory.class);
      
       data_list.clear();
       byte[] data_48 = new byte[48];
       byte[] data_64 = new byte[64];
       for(long start=0x0; start< 0x2b00;){
       //for(long start=0x1300; start<0x4000;){
           dc = new data_core();

           dc.addrs[0] = (byte) (start & 0xFF);
           dc.addrs[1] = (byte) ((start >> 8) & 0xFF);
           dc.addrs[2] = (byte) ((start >> 16) & 0xFF);

          
           pm.Read(start, 64, data_64);
           for(int k=1;k<64;k++){
               if(k%4>0)data_48[k - k/4 -1] = data_64[k-1];
           }

           System.arraycopy(data_48, 0, dc.first_chunk, 0, 48);
           //System.out.println(Arrays.toString(dc.first_chunk));
           pm.Read(start+32, 64, data_64);
           for(int k=1;k<64;k++){
               if(k%4>0)data_48[k - k/4 -1] = data_64[k-1];
           }

           System.arraycopy(data_48, 0, dc.second_chunk, 0, 48);
           //System.out.println(Arrays.toString(dc.second_chunk));
           data_list.add(dc);
           start = start + 64;
           //System.gc();
       }

       byte[] config = deviceInfo.getConfigMemoryData();
       byte[] byte_21 = new byte[21];
//       for(int k=0;k<18;){
//            byte_21[k+2] = 0;
//            byte_21[k+1] = config[k];
//            byte_21[k] = config[k+1];
//            k = k+3;
//       }
       int m=0;
       for(int k=0;k<19;){
            byte_21[k] = 0;
            byte_21[k+1] = config[m];
            byte_21[k+2] = config[m+1];
            k = k+3;
            m=m+2;
       }
        byte[] config_64 = new byte[64];
        System.arraycopy(byte_21, 0, config_64, 0, 21);
         for(int array_iterator=0;array_iterator<64;){
            byte[] bytes16 = new byte[16];
            System.arraycopy(config_64, array_iterator, bytes16, 0, 16);
            byte[] encrypted = aes.encrypt(bytes16);
            System.arraycopy(encrypted, 0, config_64, array_iterator, 16);
            array_iterator = array_iterator +16;
        }
        SharedData.getSingletonObject().setConfigdata(config_64);
    }

    
     public void fill_Boot_data_chunk(){

       CDevice deviceInfo = new CDevice();
       deviceInfo.getDeviceInfo();
       //byte[] data = new byte[0x1600 - 0x1200];
       PhysicalMemory pm = deviceInfo.getMemory(ProgramMemory.class);
      
       data_list.clear();
       byte[] data_48 = new byte[48];
       byte[] data_64 = new byte[64];
       for(long start=0x0; start<0x100;){
       //for(long start=0x1300; start<0x4000;){
           dc = new data_core();

           dc.first_chunk[0] = (byte) (start & 0xFF);
           dc.first_chunk[1] = (byte) ((start >> 8) & 0xFF);
           dc.first_chunk[2] = (byte) ((start >> 16) & 0xFF);

          
           pm.Read(start, 64, data_64);
           for(int k=1;k<64;k++){
               if(k%4>0)data_48[k - k/4 -1] = data_64[k-1];
           }

           System.arraycopy(data_48, 0, dc.first_chunk, 3, 48);
           //System.out.println(Arrays.toString(dc.first_chunk));
           pm.Read(start+32, 64, data_64);
           for(int k=1;k<64;k++){
               if(k%4>0)data_48[k - k/4 -1] = data_64[k-1];
           }

           System.arraycopy(data_48, 0, dc.second_chunk, 0, 48);
           //System.out.println(Arrays.toString(dc.second_chunk));
           data_list.add(dc);
           start = start + 64;
           //System.gc();
       }
       for(long start=0x2b00; start<deviceInfo.getPgmMemEndAddrs();){
       //for(long start=0x1300; start<0x4000;){
           dc = new data_core();

           dc.first_chunk[0] = (byte) (start & 0xFF);
           dc.first_chunk[1] = (byte) ((start >> 8) & 0xFF);
           dc.first_chunk[2] = (byte) ((start >> 16) & 0xFF);

          
           pm.Read(start, 64, data_64);
           for(int k=1;k<64;k++){
               if(k%4>0)data_48[k - k/4 -1] = data_64[k-1];
           }

           System.arraycopy(data_48, 0, dc.first_chunk, 3, 48);
           //System.out.println(Arrays.toString(dc.first_chunk));
           pm.Read(start+32, 64, data_64);
           for(int k=1;k<64;k++){
               if(k%4>0)data_48[k - k/4 -1] = data_64[k-1];
           }

           System.arraycopy(data_48, 0, dc.second_chunk, 0, 48);
           //System.out.println(Arrays.toString(dc.second_chunk));
           data_list.add(dc);
           start = start + 64;
           //System.gc();
       }
       SharedData.getSingletonObject().setBootList(data_list);
    }
        
        
        
    public class data_core{
        byte[] addrs = new byte[16];
        byte[] first_chunk = new byte[64];
        byte[] second_chunk = new byte[64];
        public data_core(){

        }
    }

    public void create_aes_object(String key){
        try {
            aes = new AESCrypt(key);
        } catch (GeneralSecurityException ex) {
            Exceptions.printStackTrace(ex);
        } catch (UnsupportedEncodingException ex) {
            Exceptions.printStackTrace(ex);
        }
    }

    public void encrypt_chunks(){
       
        for(int i=0;i<data_list.size();i++){        
        data_core d_core = (data_core) data_list.get(i);
            byte[] bytes16 = new byte[16];
            System.arraycopy(d_core.addrs, 0, bytes16, 0, 16);
            byte[] encrypted = aes.encrypt(bytes16);
            System.arraycopy(encrypted, 0, d_core.addrs, 0, 16);
        for(int array_iterator=0;array_iterator<64;){
            //byte[] bytes16 = new byte[16];
            System.arraycopy(d_core.first_chunk, array_iterator, bytes16, 0, 16);
            encrypted = aes.encrypt(bytes16);
            System.arraycopy(encrypted, 0, d_core.first_chunk, array_iterator, 16);
            array_iterator = array_iterator +16;
        }

        for(int array_iterator=0;array_iterator<64;){
            bytes16 = new byte[16];
            System.arraycopy(d_core.second_chunk, array_iterator, bytes16, 0, 16);
            encrypted = aes.encrypt(bytes16);
            System.arraycopy(encrypted, 0, d_core.second_chunk, array_iterator, 16);
            array_iterator = array_iterator +16;
        }
        data_list.set(i, d_core);
        }
    }
}
