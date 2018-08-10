/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author I14746
 */
public class SimpleSerialPort {

    public static void main(String[] args) {
        SerialHelper sh = new SerialHelper();
        try {
            sh.connect("COM8", 9600);
            byte[] SYST_RST = {(byte)0xfe,0x01,0x41,0x00,0x00,0x40};
            sh.getSerialOutputStream().write(SYST_RST);
           
        } catch (IOException ex) {
            Logger.getLogger(SimpleSerialPort.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
