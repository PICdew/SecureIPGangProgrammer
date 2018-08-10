/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;


import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Observable;
import java.util.Observer;
import java.util.Properties;
import java.util.Vector;
import javax.swing.filechooser.FileSystemView;
import org.openide.util.Exceptions;
import secureip.common.SharedData;

/**
 *
 * @author I14746
 */
public class ibtnObserver implements Observer{

    Vector device = new Vector();
    Vector dummy = new Vector();
    ibtnNotifier Notifier =null;
    Properties props = new Properties();
    private SharedData sharedData = SharedData.getSingletonObject();
    private boolean haltScanning;
    private int current_Count=0;

    public ibtnObserver(){
       
        Notifier = ibtnNotifier.getIPENotifierController();
        Thread scanner = new Thread(new Runnable() {
        public void run()
        {
            while(true){
            props = sharedData.getGlobalProps();
            if(props==null) props = new Properties();
                
            if(Boolean.parseBoolean(props.getProperty("detect.external.drive", "false"))){
                detect_USB();
            }
            if(Boolean.parseBoolean(props.getProperty("detect.internet", "false"))){
                isInternetReachable();
            }
            sleep(2000);
            }
        }});
        scanner.setPriority(Thread.MIN_PRIORITY);
        scanner.start();
    }


    private boolean detect_USB(){
        boolean detected = false;
        String driveLetter = "";
        FileSystemView fsv = FileSystemView.getFileSystemView();

        File[] f = File.listRoots();
        for (int i = 0; i < f.length; i++) {
        String drive = f[i].getPath();
        String displayName = fsv.getSystemDisplayName(f[i]);
        String type = fsv.getSystemTypeDescription(f[i]);
        boolean isDrive = fsv.isDrive(f[i]);
        boolean isFloppy = fsv.isFloppyDrive(f[i]);
        boolean canRead = f[i].canRead();
        boolean canWrite = f[i].canWrite();

        if (canRead && canWrite && !isFloppy && isDrive && (type.toLowerCase().contains("removable") || type.toLowerCase().contains("rimovibile"))) {
        //log.info("Detected PEN Drive: " + drive + " - "+ displayName);
        driveLetter = drive;
        detected = true;
        break;
        }
    }
        if(detected){
            Notifier.setDiskDetected(true);
        }
        return detected;
    }
 
   public void update(Observable o, Object arg) {
        Vector d = (Vector)arg;
        current_Count = d.size();
        if(Notifier==null ||device == null){
            System.out.println("this is null...");
        }
        Notifier.setIbtnList((Vector)device);
   }



     private void sleep(int time){
        try {
            Thread.sleep(time);
        } catch (InterruptedException ex) {
            Exceptions.printStackTrace(ex);
        }
    }


     public boolean isInternetReachable()
        {
            try {
                //make a URL to a known source
                URL url = new URL("http://www.google.com");

                //open a connection to that source
                HttpURLConnection urlConnect = (HttpURLConnection)url.openConnection();

                //trying to retrieve data from the source. If there
                //is no connection, this line will fail
                Object objData = urlConnect.getContent();

            } catch (UnknownHostException e) {
                // TODO Auto-generated catch block
                //e.printStackTrace();
                return false;
            }
            catch (IOException e) {
                // TODO Auto-generated catch block
                //e.printStackTrace();
                return false;
            }
            Notifier.setInternetConnectedstate(true);
            return true;
        }

   

}
