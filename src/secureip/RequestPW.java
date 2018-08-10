/*
 * Microchip Software Notice
 * 
 * Subject to your compliance with the terms of this license, Microchip
 * Technology Inc. (“Microchip”) hereby grants you a non-exclusive license, free
 * of charge license to the accompanying software (“Software”) solely for use
 * with Microchip microcontrollers and/or Microchip digital signal controller
 * products.  Subject to the foregoing, you (either directly or through third
 * party contractors working on your behalf) may: (a) use and make copies of the
 * Software; (b) modify and prepare derivative works of the Software provided in
 * source code form, subject to Microchip’s rights in and to the unmodified code
 * delivered to you; (c) distribute the Software and copies thereof and derived
 * code; and (d) demonstrate, sell, offer to sell, and distribute products
 * (incorporating or bundled with your software and third party software) to
 * end user customers and OEM customers that include the Software (including
 * derived code) or otherwise distribute the Software as a component of an
 * software development kit to ODM and OEM customers, provided that, in all
 * cases (described in clauses (a) through (d) herein), the Software and derived
 * code are accompanied by the header file that accompanies the Software.
 * 
 * Further, Microchip is not responsible for any and all modifications made to
 * the Software by your or other authorized users.  You and your authorized
 * users will use commercially reasonable efforts to note any such modifications
 * at the end of the applicable header file notice.
 * 
 * The Software are owned by Microchip or its licensors, and protected under
 * applicable copyright laws.  All rights reserved.  This Software and any
 * accompanying information are for information purposes only, and do not modify
 * Microchip’s standard warranty for its microcontroller or digital signal
 * controller products.  It is your responsibility to ensure that the Software
 * meet your requirements.
 * 
 * EXCEPT AS EXPRESSLY STATED ABOVE BY MICROCHIP, THE SOFTWARE IS PROVIDED
 * “AS IS.” MICROCHIP EXPRESSLY DISCLAIMS ANY WARRANTY OF ANY KIND, WHETHER
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
 * IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, OR CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, HARM TO YOUR
 * EQUIPMENT, COST OF PROCUREMENT OF SUBSTITUTE GOODS, TECHNOLOGY OR SERVICES,
 * ANY CLAIMS BY THIRD PARTIES (INCLUDING BUT NOT LIMITED TO ANY DEFENSE
 * THEREOF), ANY CLAIMS FOR INDEMNITY OR CONTRIBUTION, OR OTHER SIMILAR COSTS.
 * 
 * TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP’S LIABILITY FOR USE OF THE
 * SOFTWARE OR DERIVED CODE WILL NOT EXCEED $1,000 USD. MICROCHIP PROVIDES THE
 * SOFTWARE CONDITIONALLY UPON ACCEPTANCE OF THESE TERMS.
 */

/*
 * RequestPW.java
 *
 * Created on Jan 22, 2012, 3:51:20 PM
 */

package secureip;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.Icon;
import secureip.common.SharedData;
import java.awt.Image;
import java.awt.Toolkit;
import javax.swing.plaf.IconUIResource;

/**
 *
 * @author I14746
 */
public class RequestPW extends javax.swing.JDialog {
    private SharedData sharedData;
     PreviousStateExplorer pse=new PreviousStateExplorer();
     Properties p=new Properties();
     private boolean right_pw=false;

    /** Creates new form RequestPW */
    public RequestPW(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
        passwordTracker pwt= new passwordTracker();
        passTxtField.setText("");
        p= pse.getAdvProps();
        // to show and hide default password in login screen
        pwdMessageLbl.setVisible(!pwt.isPWDfileOnDisk() 
                                 || "preceptor".equals(pwt.getCurrentKey()));
        sharedData= sharedData.getSingletonObject();
        if(Boolean.parseBoolean(p.getProperty("Keep Logged", "false")))
        {
            rememberPwdChkBx.setSelected(true);
            passTxtField.setText(pwt.getCurrentKey());
            validateBtn.setFocusable(true);
            PreviousStateExplorer pse = new PreviousStateExplorer();
        }
        passTxtField.addKeyListener(new KeyListener() {

        public void keyTyped(KeyEvent e) {
          //  throw new UnsupportedOperationException("Not supported yet.");
        if(e.getKeyChar()==KeyEvent.VK_ENTER){
             //   OKButton.doClick();
            validateBtn.doClick();
            }
        }

        public void keyPressed(KeyEvent e) {
        //    throw new UnsupportedOperationException("Not supported yet.");
        }

        public void keyReleased(KeyEvent e) {
         //   throw new UnsupportedOperationException("Not supported yet.");
        }
    });
     }

    /** This method is called from within the constructor to
     * initialize the form.asdff
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.asdff
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel2 = new javax.swing.JLabel();
        lblLoginToAdminMode = new javax.swing.JLabel();
        validateBtn = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        passTxtField = new javax.swing.JPasswordField();
        changePassBtn = new javax.swing.JButton();
        lblLoginToAdminMode1 = new javax.swing.JLabel();
        lblWrongPass = new javax.swing.JLabel();
        pwdMessageLbl = new javax.swing.JLabel();
        rememberPwdChkBx = new javax.swing.JCheckBox();
        jSeparator1 = new javax.swing.JSeparator();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(secureip.SecureIPApp.class).getContext().getResourceMap(RequestPW.class);
        setTitle(resourceMap.getString("Advanced Settings.title")); // NOI18N
        setAlwaysOnTop(true);
        setName("Advanced Settings"); // NOI18N
        setResizable(false);
        addWindowListener(new java.awt.event.WindowAdapter() {
            public void windowClosed(java.awt.event.WindowEvent evt) {
                formWindowClosed(evt);
            }
        });

        jLabel2.setName("jLabel2"); // NOI18N

        lblLoginToAdminMode.setName("lblLoginToAdminMode"); // NOI18N

        validateBtn.setText(resourceMap.getString("validateBtn.text")); // NOI18N
        validateBtn.setName("validateBtn"); // NOI18N
        validateBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                validateBtnActionPerformed(evt);
            }
        });

        jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
        jLabel3.setName("jLabel3"); // NOI18N

        passTxtField.setText(resourceMap.getString("passTxtField.text")); // NOI18N
        passTxtField.setName("passTxtField"); // NOI18N
        passTxtField.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                passTxtFieldFocusGained(evt);
            }
        });

        changePassBtn.setText(resourceMap.getString("changePassBtn.text")); // NOI18N
        changePassBtn.setName("changePassBtn"); // NOI18N
        changePassBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                changePassBtnActionPerformed(evt);
            }
        });

        lblLoginToAdminMode1.setText(resourceMap.getString("lblLoginToAdminMode1.text")); // NOI18N
        lblLoginToAdminMode1.setName("lblLoginToAdminMode1"); // NOI18N

        lblWrongPass.setName("lblWrongPass"); // NOI18N

        pwdMessageLbl.setText(resourceMap.getString("pwdMessageLbl.text")); // NOI18N
        pwdMessageLbl.setName("pwdMessageLbl"); // NOI18N

        rememberPwdChkBx.setText(resourceMap.getString("rememberPwdChkBx.text")); // NOI18N
        rememberPwdChkBx.setName("rememberPwdChkBx"); // NOI18N
        rememberPwdChkBx.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rememberPwdChkBxActionPerformed(evt);
            }
        });

        jSeparator1.setName("jSeparator1"); // NOI18N

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(rememberPwdChkBx, javax.swing.GroupLayout.PREFERRED_SIZE, 248, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(123, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                    .addGroup(javax.swing.GroupLayout.Alignment.LEADING, layout.createSequentialGroup()
                        .addGap(23, 23, 23)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(lblWrongPass, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 332, Short.MAX_VALUE)
                            .addComponent(lblLoginToAdminMode)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                                .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, 102, Short.MAX_VALUE)
                                .addGap(230, 230, 230))))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(pwdMessageLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 224, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(changePassBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 199, javax.swing.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                .addComponent(validateBtn, javax.swing.GroupLayout.DEFAULT_SIZE, 140, Short.MAX_VALUE)))))
                .addGap(22, 22, 22))
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(layout.createSequentialGroup()
                            .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 357, Short.MAX_VALUE)
                            .addContainerGap())
                        .addGroup(layout.createSequentialGroup()
                            .addGap(13, 13, 13)
                            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                .addComponent(lblLoginToAdminMode1, javax.swing.GroupLayout.Alignment.LEADING)
                                .addGroup(layout.createSequentialGroup()
                                    .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 104, Short.MAX_VALUE)
                                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                    .addComponent(passTxtField, javax.swing.GroupLayout.PREFERRED_SIZE, 224, javax.swing.GroupLayout.PREFERRED_SIZE)))
                            .addGap(22, 22, 22)))))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(lblLoginToAdminMode, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 39, Short.MAX_VALUE)
                .addComponent(pwdMessageLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 26, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(lblWrongPass, javax.swing.GroupLayout.PREFERRED_SIZE, 17, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(changePassBtn)
                    .addComponent(validateBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(18, 18, 18)
                .addComponent(rememberPwdChkBx)
                .addContainerGap())
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addGroup(layout.createSequentialGroup()
                    .addGap(15, 15, 15)
                    .addComponent(lblLoginToAdminMode1, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(passTxtField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel3))
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 106, Short.MAX_VALUE)
                    .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGap(34, 34, 34)))
        );

        layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {changePassBtn, validateBtn});

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void validateBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_validateBtnActionPerformed

        passwordTracker pwt= new passwordTracker();
        String pw = new String(passTxtField.getPassword());
        String curPW= pwt.getCurrentKey();
        if(pw.compareTo(curPW)==0) {
            if(pw.compareTo("factoryuse")==0) sharedData.setFactoryUse(true);
            sharedData.right_pw = true;
            secureip.SecureIPApp.getApplication().getView().upperpanel.remove(secureip.SecureIPApp.getApplication().getView().MainDialog);
            secureip.SecureIPApp.getApplication().getView().upperpanel.add(secureip.SecureIPApp.getApplication().getView().jTabbedPane1);
            secureip.SecureIPApp.getApplication().getView().jTabbedPane1.add(secureip.SecureIPApp.getApplication().getView().getResourceMap().getString("MainDialog.TabConstraints.tabTitle"), secureip.SecureIPApp.getApplication().getView().MainDialog);
            secureip.SecureIPApp.getApplication().getView().jTabbedPane1.setVisible(true);
            secureip.SecureIPApp.getApplication().getView().jTabbedPane1.setSelectedIndex(0);
            p.setProperty("Keep Logged", String.valueOf(rememberPwdChkBx.isSelected()));
            pse.advancedPropsSaver(p);
            sharedData.SaveAndApply(p);
            this.dispose();

            try {
                this.finalize();
            } catch (Throwable ex) {
                Logger.getLogger(RequestPW.class.getName()).log(Level.SEVERE, null, ex);
            }
            
        } else{
            if(pw.equals("")){
                lblWrongPass.setText("Please provide the password.");
                //Icon ic=IButtonSecurityApp.getApplication().getView().getres().getIcon("wrong.icon");
                //lblWrongPass.setIcon(ic);
                lblWrongPass.setVisible(true);
            } else{
                sharedData.right_pw = false;
                sayInvalid();
            }
                
        }
}//GEN-LAST:event_validateBtnActionPerformed

    private void passTxtFieldFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_passTxtFieldFocusGained

        lblWrongPass.setIcon(null);
        lblWrongPass.setText("");
}//GEN-LAST:event_passTxtFieldFocusGained

    private void changePassBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_changePassBtnActionPerformed
        changePassword cp= new changePassword(null,true);
        cp.setLocationRelativeTo(this);
        cp.setVisible(true);
}//GEN-LAST:event_changePassBtnActionPerformed

    private void rememberPwdChkBxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rememberPwdChkBxActionPerformed

}//GEN-LAST:event_rememberPwdChkBxActionPerformed

    private void formWindowClosed(java.awt.event.WindowEvent evt) {//GEN-FIRST:event_formWindowClosed
//        if(right_pw == false)
//        System.exit(0);
    }//GEN-LAST:event_formWindowClosed

    /**
    * @param args the command line arguments
    */
    public static void main(String args[]) {
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                RequestPW dialog = new RequestPW(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });

                
                 dialog.setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton changePassBtn;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JLabel lblLoginToAdminMode;
    private javax.swing.JLabel lblLoginToAdminMode1;
    private javax.swing.JLabel lblWrongPass;
    private javax.swing.JPasswordField passTxtField;
    private javax.swing.JLabel pwdMessageLbl;
    private javax.swing.JCheckBox rememberPwdChkBx;
    private javax.swing.JButton validateBtn;
    // End of variables declaration//GEN-END:variables

    private void sayInvalid() {
        lblWrongPass.setText("Invalid password.");
//        Image ic = Toolkit.getDefaultToolkit().getImage(RequestPW.class.getResource("resources/login_icon.gif"));
       // Icon ic=IButtonSecurityApp.getApplication().getView().getres().getIcon("wrong.icon");
//        lblWrongPass.setIcon(ic);
        lblWrongPass.setVisible(true);
    }

}
