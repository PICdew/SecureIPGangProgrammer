// SharedData.java - Contains Shared Data between classes in different packages

/*$Id: SharedData.java,v 1.39 2013/11/07 14:30:11 herles Exp $*/
/*
 ******************************************************************************
 *                                                                            *
 *                                                                            *
 *                                                                            *
 * This program is free software; you can redistribute it and/or modify it    *
 * under the terms of the GNU Lesser General Public License as published by   *
 * the Free Software Foundation; either version 2.1 of the License, or        *
 * (at your option) any later version.                                        *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public    *
 * License for more details.                                                  *
 *                                                                            *
 * You should have received a copy of the GNU Lesser General Public License   *
 * along with this program; if not, write to the Free Software Foundation,    *
 * Inc., 675 Mass Ave, Cambridge, MA 02139, USA.                              *
 *                                                                            *
 ******************************************************************************
 */
/**
 * <dl>
 * <dt>Purpose: To Share Data between classes
 * <dd>
 *
 * <dt>Description:
 * <dd> This is a Singleton Class that shares data between classes
 *
 * </dl>
 *
 * @version $Date: 2013/11/07 14:30:11 $
 * @author  Sudheer
 * @since   JDK 1.6.21
 */

package secureip.common;

import com.microchip.mplab.crownkingx.xPIC;
import com.microchip.mplab.mdbcore.assemblies.Assembly;
import secureip.PreviousStateExplorer;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.LinkedList;
import java.util.Properties;
import java.util.Vector;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.SourceDataLine;
import org.openide.util.Exceptions;
import secureip.DataFrame;

public class SharedData
{

    public Properties globalProps= null;
    public boolean cleanInstall=false;
    private Assembly assembly;
    private LinkedList enc_data=null;
    private LinkedList Boot_List=null;
    private byte[] config= null;
    private boolean factoryuse=false;
    private iButton_features ibtn_feature;
    private String password;
    public boolean right_pw=false;
    public boolean hold = false;
    public boolean haltScanning;
    public DataFrame DF_recieved;
    public boolean dataRecievedFlag=false;
    /**
    * Constructor  -
    *
    * @return      void
    */
    private SharedData()
    {
       // deviceInfo = new CDevice();
    }

     public void dataRecieved(byte[] buffer) {
        DF_recieved = new DataFrame();
        System.arraycopy(buffer, 1, DF_recieved.DestAddrs, 0, 2);
        System.arraycopy(buffer, 3, DF_recieved.Command, 0, 2);
        System.arraycopy(buffer, 5, DF_recieved.FrameNo, 0, 2);
        DF_recieved.Length = buffer[7];
        DF_recieved.Payload = new byte[DF_recieved.Length];
        System.arraycopy(buffer, 8, DF_recieved.Payload, 0, DF_recieved.Length);
    }
 
    public String getWD() {
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(secureip.SecureIPApp.class).getContext().getResourceMap(secureip.SecureIPApp.class);
        String version = resourceMap.getString("Application.version");
        String wd = System.getProperty("user.home");
        if(System.getProperty("os.name").contains("Windows")){
            wd = System.getenv("APPDATA").replace("\\", "/")+"/Preceptor/"+version;
        }
        return wd;
    }

    public  final static String getDateTime()
    {
    DateFormat df = new SimpleDateFormat("HH:mm:ss");
   // DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
    return df.format(new Date());
    }

    public void setPwd(String pass){
        this.password = pass;
    }

    public String getPwd(){
        password = password.replaceAll(",", "").trim();
        password = password.replaceAll("0x", "").trim();
        return this.password;
    }

    public  final static String getDateTimeFull()
    {
   // DateFormat df = new SimpleDateFormat("HH:mm:ss");
    DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
    return df.format(new Date());
    }
    /**
    * Singleton class object get method
    *
    * @return       SharedData Object
    */
    public static SharedData getSingletonObject()
    {
    if (ref == null)
        // it's ok, we can call this constructor
        ref = new SharedData();
    return ref;
    }

    public Properties getGlobalProps(){
    return globalProps;
    }

    public void setGlobalProps(Properties p){
    globalProps = p;
    }

    public void SaveAndApply(Properties prop){
            PreviousStateExplorer  pse = new PreviousStateExplorer();
            //advProp.setProperty("audible.tone", Boolean.toString(audibleNotificationChkBx.isSelected()));
            //advProp.setProperty("Generate Reports", String.valueOf(generateReportsCbox.isSelected()));
            if(prop==null){
                prop = getGlobalProps();
            }
            pse.advancedPropsSaver(prop);
            pse.saveToFile(getGlobalProps());
    }
    private static SharedData ref;

    public void setAssemblySession(Assembly session) {
        this.assembly = session;
    }

    public Assembly getAssemblySession() {
        return this.assembly;
    }

    public void setEncryptedData(LinkedList data_list) {
        this.enc_data = data_list;
    }

    public LinkedList getIbtnData() {
        return this.enc_data;
    }
    public void setBootList(LinkedList data_list) {
        this.Boot_List = data_list;
    }
    public LinkedList getBootList(){
        return this.Boot_List;
    } 
    public void setConfigdata(byte[] byte_21) {
        this.config = byte_21;
    }

    public byte[] getConfigdata() {
        return this.config;
    }

    public void setFactoryUse(boolean b) {
        this.factoryuse= b;
    }

    public boolean isFactoryUse(){
        return this.factoryuse;
    }

    public void setFeature(iButton_features btn_feature) {
        this.ibtn_feature = btn_feature;
    }

    public iButton_features getFeatures(){
        return this.ibtn_feature;
    }

    public class iButton_features{

        public String desc;
        public boolean ispwdProtected;
        public Vector mem_vector = new Vector();
        public iButton_features(){
            
        }
    };

    public DataFrame getDataframe(){
        return this.DF_recieved;
    }
    public void sound(int hz, int msecs, double vol) {
        try {
            if (vol > 1.0 || vol < 0.0) {
                throw new IllegalArgumentException("Volume out of range 0.0- 1.0");
            }
            byte[] buf = new byte[msecs * 8];
            for (int i = 0; i < buf.length; i++) {
                double angle = i / (8000.0 / hz) * 2.0 * Math.PI;
                buf[i] = (byte) (Math.sin(angle) * 127.0 * vol);
            }
            // shape the front and back ends of the wave form
            for (int i = 0; i < 20 && i < buf.length / 2; i++) {
                buf[i] = (byte) (buf[i] * i / 20);
                buf[buf.length - 1 - i] = (byte) (buf[buf.length - 1 - i] *
        i / 20);
            }
            AudioFormat af = new AudioFormat(8000f, 8, 1, true, false);
            SourceDataLine sdl = AudioSystem.getSourceDataLine(af);
            sdl.open(af);
            sdl.start();
            sdl.write(buf, 0, buf.length);
            sdl.drain();
            sdl.close();
        } catch (LineUnavailableException ex) {
            Exceptions.printStackTrace(ex);
        }
}


    public class mem_bank{
        public String desc;
        public String size;
        public String startAddrs;
        public boolean isWriteprotected;
    }

   
    
 }
