/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

import secureip.ibtnNotifier.Operation;
import java.util.ArrayList;
import java.util.Vector;

/**
 *
 * @author I00182
 */
public class NotifyData {
    public Vector toolArrayList;
    public String msgNotification;
    public Operation m_eOperation;
    public int ActionID;
    public boolean MemoryChange; //this notifies IPE if memory objects have changed
}
