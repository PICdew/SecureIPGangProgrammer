/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URL;
import java.util.Properties;
import secureip.common.SharedData;


/**
 *
 * @author I14746
 */
public class PreviousStateExplorer {
    private Properties properties;
    DesEncrypter encrypter;
    public boolean tampered=false;
    private SharedData sharedData=SharedData.getSingletonObject();
    String encrypted ="";
    public boolean freeze=false;
    public boolean SQTP_Exhausted=false;
    final Class<?> referenceClass = SecureIPApp.class;
    final URL url = referenceClass.getProtectionDomain().getCodeSource().getLocation();
    passwordTracker pt= new passwordTracker();
    String wd= sharedData.getWD();
    File user = new File(wd+"/"+"user.properties");
    File advanced = new File(wd+"/"+"advanced.properties");
    File hidden = new File(wd+"/"+"hidden.properties");
    File logFile = new File(wd+"/"+"iButton_log.txt");

    public void logFile(String w) throws IOException{
        logFile.createNewFile();
        FileOutputStream log = new FileOutputStream(logFile);
        log.write(w.getBytes());
        log.flush();
        log.close();        
    }
    
     public void loadDefaultProps() {
        properties = new Properties();
        
    }

     public void advancedPropsSaver(Properties adv){
        sharedData.setGlobalProps(adv);
     }


     public void saveToFile(Properties adv){
        if(adv!=null){
        try {
        try {
            encrypter = new DesEncrypter("I14746");
        } catch (Exception ex) {
        }
        FileOutputStream fos = new FileOutputStream(advanced);
        advanced.createNewFile();
        adv.store(fos,null);
        fos.flush();
        fos.close();            //original file

        RandomAccessFile fins=new RandomAccessFile(advanced,"rw");

        byte[] b = new byte[(int)advanced.length()];
        fins.read(b,0,(int)advanced.length()) ;
        fins.close();
        advanced.delete();
        String hh = new String(b);

        pt.setProperties(hh);
      } catch (IOException ex) {
      }
    }
     }
     public Properties getAdvProps(){
        sharedData =sharedData.getSingletonObject();
        Properties fromShared=sharedData.getGlobalProps();
        if(fromShared==null){
            Properties f= getFromFile();
            //if(sharedData.getLibrary().getAssemblySession()!=null){
                sharedData.setGlobalProps(f);
            //}
            return f;
        }
        else return fromShared;
       //  return getFromFile();
    }

     public Properties getFromFile(){

         File keyFile = new File(wd+"/"+"preceptor.key");
         if(!keyFile.exists()){
            loadDefaultProps();
            advancedPropsSaver(properties);
        }
         Properties prop = new Properties();
          try {
            File temp = new File(wd);
            System.out.println("APPDATA:"+wd);
            if(!temp.isDirectory()){
                temp.mkdirs();
            }
            RandomAccessFile isa = new RandomAccessFile(wd+"/"+"preceptor.properties","rw");
            byte[] buf = new byte[(int)isa.length()];
            try {
            isa.seek(0);
            isa.read(buf,0,(int)isa.length());
            } catch (Exception ex) {
               
            }
            isa.close();
            String dec=null;
            String ps=null;

            if(buf.length==0){
            File keyFilef = new File(wd+"/"+"preceptor.key");
            if(keyFilef.exists()){
            tampered=true;
        }
        loadDefaultProps();
        prop =properties;
        return prop;
     }

        String decs=pt.getCurrentProps();
        user.createNewFile();
        FileInputStream fis = new FileInputStream(user);
        RandomAccessFile raf = new RandomAccessFile(user,"rw");
        raf.seek(0);
        raf.setLength(decs.length());
        raf.write(decs.getBytes());
        raf.close();

        prop = new Properties();
        prop.load(fis);
        fis.close();
        user.delete();
        if(prop.size()==0){
        loadDefaultProps();
        prop = properties;
        }

        } catch (IOException ex) {
            loadDefaultProps();
            prop = properties;
           
        }
        user.delete();
        return prop;
     }

    void deletePropFile() {
        File ipeSettings = new File(wd+"/"+"preceptor.properties");
        System.out.println("File deletion = " + ipeSettings.delete());
        Properties pro = new Properties();
        sharedData.setGlobalProps(pro);
    }

    boolean deletePropsFile() {
        File propFile = new File(wd+"/"+"preceptor.properties");
        return propFile.delete();
    }

    boolean deleteKeyFile() {
        File keyFile = new File(wd+"/"+"preceptor.key");
        return keyFile.delete();
    }


  
}
