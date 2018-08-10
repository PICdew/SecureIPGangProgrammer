/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import secureip.ibtnNotifier;
import secureip.NotifyData;
import java.util.ArrayList;
import java.util.Observable;
import java.util.Observer;
import java.util.ResourceBundle;
import javax.swing.Icon;
import javax.swing.JOptionPane;
import javax.swing.text.SimpleAttributeSet;
import secureip.common.SharedData;

/**
 *
 * @author i00182
 */
public class iBtnEvents implements Observer{

    public ibtnNotifier imp=null;
    org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(secureip.SecureIPApp.class).getContext().getResourceMap(SecureIPView.class);
    Icon IncompatibleIcon = resourceMap.getIcon("wrong.icon");
    SimpleAttributeSet RedText = new SimpleAttributeSet();;


    //This list will contain the titles of any windows that should be cleared
    //when a new session is started
    private ArrayList<String> ClearWindowList = new ArrayList<String>();
    //private String message;
    private SharedData sharedData = SharedData.getSingletonObject();


    private enum OutputType{
      Message,
      Error,
      Color,
      ErrorLink
    };

    private OutputType typeOfOutput;
    /**
    * addObserver -  Add this class to Host
    *
    * @param        none
    * @return       void
    */
    public void addObserver()
    {
        imp=ibtnNotifier.getIPENotifierController();
        imp.addObserver(this);
    }

    /**
    * update -  Get notification when Tool/Msg occurs
    *
    * @param        Observable
    * @param        Object
    * @return       void
    */
    public void update(Observable o, Object arg) {
        NotifyData nData=(NotifyData)arg;if(nData.m_eOperation==ibtnNotifier.Operation.ID_INTERNET_NOTIFY){
          ResourceBundle bundle = ResourceBundle.getBundle("secureip.resources.StringBundle");
          JOptionPane.showMessageDialog(SecureIPApp.getApplication().getView().getFrame(), bundle.getString("INTERNET.CONNECTION.MESSAGE"),bundle.getString("INTERNET.CONNECTION"), JOptionPane.WARNING_MESSAGE, null);
          System.exit(0);
        }
         else if(nData.m_eOperation==ibtnNotifier.Operation.ID_EXTERNAL_DRIVE){
           ResourceBundle bundle = ResourceBundle.getBundle("secureip.resources.StringBundle");
          JOptionPane.showMessageDialog(SecureIPApp.getApplication().getView().getFrame(), bundle.getString("EXTERNAL.DRIVE.MESSAGE"),bundle.getString("EXTERNAL.DRIVE"), JOptionPane.WARNING_MESSAGE, null);
          System.exit(0);
         }
    }
}
