/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import java.util.ArrayList;
import java.util.Observable;
import java.util.Vector;

/**
 *
 * @author I14746
 */
public class ibtnNotifier extends Observable {

private static ibtnNotifier singleton = null;





public static enum Operation {ID_INTERNET_NOTIFY,ID_BTN_NOTIFY, ID_MSG_OBJECT,ID_EXTERNAL_DRIVE}; //Added memory change notification
private NotifyData notifyData;

    public boolean  setIbtnList(Vector device) {
        notifyData.m_eOperation=Operation.ID_BTN_NOTIFY;
        notifyData.toolArrayList=device;
        setChanged();
        notifyObservers(notifyData);
        return true;
     }

    public void setInternetConnectedstate(boolean b) {
        notifyData.m_eOperation=Operation.ID_INTERNET_NOTIFY;
        setChanged();
        notifyObservers(notifyData);
    }

     void setDiskDetected(boolean b) {
        notifyData.m_eOperation=Operation.ID_EXTERNAL_DRIVE;
        setChanged();
        notifyObservers(notifyData);
    }

    

        ibtnNotifier()
    {
        notifyData=new NotifyData();
    }


     public static ibtnNotifier getIPENotifierController()
    {
        if (singleton == null)
        {
            singleton = new ibtnNotifier();
        }
        return singleton;
    }
}
