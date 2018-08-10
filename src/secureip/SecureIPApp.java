/*
 * SecureIPApp.java
 */

package secureip;

import org.jdesktop.application.Application;
import org.jdesktop.application.SingleFrameApplication;

/**
 * The main class of the application.
 */
public class SecureIPApp extends SingleFrameApplication {
    SecureIPView ibtnView = null;
    /**
     * At startup create and show the main frame of the application.
     */
    @Override protected void startup() {
        if(ibtnView == null) {
          ibtnView = new SecureIPView(this);
          show(ibtnView);
        }
      else{
          ibtnView.getFrame().dispose();
          ibtnView = new SecureIPView(this);
          show(ibtnView);
      }
    }

    /**
     * This method is to initialize the specified window by injecting resources.
     * Windows shown in our application come fully initialized from the GUI
     * builder, so this additional configuration is not needed.
     */
    @Override protected void configureWindow(java.awt.Window root) {
    }

    public SecureIPView getView(){
       return this.ibtnView;
    }
    /**
     * A convenient static getter for the application instance.
     * @return the instance of SecureIPApp
     */
    public static SecureIPApp getApplication() {
        return Application.getInstance(SecureIPApp.class);
    }

    /**
     * Main method launching the application.
     */
    public static void main(String[] args) {
        launch(SecureIPApp.class, args);
    }
}
