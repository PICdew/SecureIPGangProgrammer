/*
 * SecureIPView.java
 */

package secureip;

import com.microchip.crownking.mplabinfo.DeviceSupport;
import com.microchip.crownking.mplabinfo.FamilyDefinitions.Family;
import com.microchip.mplab.ipelib.device.MemoryObserver;
import com.microchip.mplab.mdbcore.assemblies.Assembly;
import com.microchip.mplab.mdbcore.assemblies.AssemblyFactory;
import com.microchip.mplab.mdbcore.loader.LoadException;
import com.microchip.mplab.mdbcore.loader.Loader;
import com.microchip.mplab.mdbcore.memory.MemoryModel;
import com.microchip.mplab.mdbcore.memory.PhysicalMemory;
import com.microchip.mplab.mdbcore.memory.memorytypes.ProgramMemory;
import com.microchip.mplab.util.observers.Observer;
import com.microchip.mplab.util.observers.Subject;
import com.sun.java.swing.SwingUtilities3;
import java.awt.Color;
import java.awt.GridLayout;
import java.awt.Image;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import org.jdesktop.application.Action;
import org.jdesktop.application.ResourceMap;
import org.jdesktop.application.SingleFrameApplication;
import org.jdesktop.application.FrameView;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import org.openide.util.Exceptions;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import javax.swing.ButtonGroup;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import org.openide.util.Lookup;
import secureip.DataChunk.data_core;
import secureip.common.SharedData;

/**
 * The application's main frame.
 */
public class SecureIPView extends FrameView {

    private PreviousStateExplorer pse=new PreviousStateExplorer();
    private Properties advProp=new Properties();
    private String com_port="";
    private SharedData sharedData = SharedData.getSingletonObject();
    //private boolean haltScanning;
    private Document statusText;
    private ResourceMap resourceMap;
    private Random random = new Random();
    private ResourceBundle bundle;
    private String toolCmd = "PK3CMD";
    private String toolName;
    //private byte[] iBtn_serial=null;
    private byte[] readBuf = new byte[32];
    Vector device = new Vector();
    Vector dummy = new Vector();
    
    byte[] aes_first_half = new byte[8];        // Goes to iButton
    byte[] aes_sec_half = new byte[8];      //Goes to header file
//    private static final byte[] full_key_ibtn = new byte[] { (byte)0xe0, 0x4f, (byte)0xd0,
//    0x20, (byte)0xea, 0x3a, 0x69, 0x10, (byte)0xa2, (byte)0xd8, 0x08, 0x00, 0x2b,
//    0x30, 0x30, (byte)0x9d };

    private byte[] i_key_full = new byte[8];

    private byte[] i_key_read = new byte[8];
    //byte[] aes_key = new byte[]{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf};
    byte[] aes_key = new byte[]{0x02,0x07, 0x0C,0x07 ,0x06,0x08, 0x01,0x01, 0x0A,0x04, 0x02,0x09, 0x03,0x0D, 0x06,0x0E};
    //byte[] aes_key = new byte[]{(byte)0x11,(byte)0x22,(byte)0x33,(byte)0x44,(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x88,(byte)0x99,(byte)0xaa,(byte)0xbb,(byte)0xcc,(byte)0xdd,(byte)0xee,(byte)0xff,(byte)0x11};
    //***************************STATICs********************************
    ArrayList<JLabel> iBtn_labels = new ArrayList<JLabel>();
    ArrayList<JLabel> MCU_labels = new ArrayList<JLabel>();
    ArrayList<JPanel> iBtn_panels = new ArrayList<JPanel>();
    ArrayList<JPanel> MCU_panels = new ArrayList<JPanel>();
    private int Pair_index =0;
    private boolean blink = false;
    private static byte[] FetchPgmrID = new byte[]{0x0,0x1};
    private static byte[] FetchIbtn = new byte[]{0x0,0x2};
    private static byte[] FetchDevID = new byte[]{0x0,0x3};
    private static byte[] IbtnRecovery = new byte[]{0x0,0x4};
    private static byte[] LockIbtn = new byte[]{0x0,0x5};
    private static byte[] WritetCredentials = new byte[]{0x0,0x6};
    private static byte[] EraseIbtn = new byte[]{0x0,0x7};
    private static byte[] PgmIbtn = new byte[]{0x0,0x8};
    private static byte[] PgmMCU = new byte[]{0x0,0x9};
    private static byte[] cfg_data = new byte[]{0x00,0x01, 0x07,0x07, 0x00, 0x13, (byte)0x87,(byte)0xB2, 0x31,(byte)0x0F, 0x33,(byte)0x0F, 0x00,0x07, (byte)0xC0, 0x03};
    private static byte[] lock_data = new byte[]{0,1,0,0,1,1,2,2,3,3,0,0,1,1,2,2,3,3};
    private static byte[] full_Access = new byte[]{0,0,1,1,2,2,3,3};
    private static byte[] ibtn_serial = new byte[] {0x37,0x40,(byte)0xEA,0x10,0x00,0x00,0x00,(byte)0x8D};
    private static byte[] SendCfg = new byte[]{0x0,0xC};
    private static byte[] StatusQuery = new byte[]{0x0,0xa};
    private static byte[] Reset = new byte[]{0x0,0xb};

    private  TimerTask Blinker_Task ;
    private static String TARGET_DEVICE = "dsPIC30F2010";
    private byte[] actual_key = new byte[16];
    private boolean initialSeting;
    private final JPopupMenu popup;
    private DataFrame DF_recieved;
    boolean dataRecievedFlag = false;
    private byte[] Command;
    private ArrayList<String> All_buttons= new ArrayList<String>();
    private ArrayList<String> All_MCUs= new ArrayList<String>();
    private SerialHelper sh = new SerialHelper();
    private boolean is_com_available =false;
    private Color disabled_color;
    private MemoryModel memModel;
    private Full_Info[] FullInfo = new Full_Info[10];
    private Observer memoryObserver;
    
    public SecureIPView(SingleFrameApplication app) {
        super(app);

        initComponents();
        List<Full_Info> full;
        iBtn_labels.add(ibtn1Lbl);
        iBtn_labels.add(ibtn2Lbl);
        iBtn_labels.add(ibtn3Lbl);
        iBtn_labels.add(ibtn4Lbl);
        iBtn_labels.add(ibtn5Lbl);
        iBtn_labels.add(ibtn6Lbl);
        iBtn_labels.add(ibtn7Lbl);
        iBtn_labels.add(ibtn8Lbl);
        iBtn_labels.add(ibtn9Lbl);
        iBtn_labels.add(ibtn10Lbl);

        iBtn_panels.add(jPanel8);
        iBtn_panels.add(jPanel13);
        iBtn_panels.add(jPanel15);
        iBtn_panels.add(jPanel17);
        iBtn_panels.add(jPanel19);
        iBtn_panels.add(jPanel22);
        iBtn_panels.add(jPanel24);
        iBtn_panels.add(jPanel26);
        iBtn_panels.add(jPanel28);
        iBtn_panels.add(jPanel21);

        MCU_panels.add(jPanel12);
        MCU_panels.add(jPanel14);
        MCU_panels.add(jPanel16);
        MCU_panels.add(jPanel18);
        MCU_panels.add(jPanel20);
        MCU_panels.add(jPanel23);
        MCU_panels.add(jPanel25);
        MCU_panels.add(jPanel27);
        MCU_panels.add(jPanel29);
        MCU_panels.add(jPanel30);
        
        MCU_labels.add(jLabel19);
        MCU_labels.add(jLabel20);
        MCU_labels.add(jLabel21);
        MCU_labels.add(jLabel22);
        MCU_labels.add(jLabel23);
        MCU_labels.add(jLabel24);
        MCU_labels.add(jLabel25);
        MCU_labels.add(jLabel26);
        MCU_labels.add(jLabel27);
        MCU_labels.add(jLabel28);
        
        disabled_color = jPanel8.getBackground();
        jTabbedPane1.setVisible(false);
        upperpanel.add(MainDialog);
        upperpanel.remove(jTabbedPane1);
        Image mainLogo = Toolkit.getDefaultToolkit().getImage(SecureIPView.class.getResource("resources/lock-128.png"));
        getFrame().setIconImage(mainLogo);

        jTabbedPane1.setSelectedIndex(0);
        jScrollPane2.setVisible(false);
       // this.getFrame().setSize(this.MainDialog.getWidth()+20, this.getFrame().getHeight());
        this.getFrame().pack();
        statusText = statusArea1.getDocument();
        StartBtn.setEnabled(true);
        sharedData.setGlobalProps(pse.getAdvProps());
        advProp = sharedData.getGlobalProps();
        jTabbedPane1.setSelectedIndex(0);
        thisKeyCount.setText(advProp.getProperty("this.key.count", "10"));
//        projectPath.setText(advProp.getProperty("Project Path", null));
        hexFilePath.setText(advProp.getProperty("Hex Path", null));
        ButtonGroup pgm_options = new ButtonGroup();
        pgm_options.add(rbtnBoth);
        pgm_options.add(rbtnonlyIbtn);
        pgm_options.add(rbtnonlyMCU);
        rbtnBoth.setSelected(true);
        
        rbtnBoth.setSelected(Boolean.parseBoolean(advProp.getProperty("both.as.pair", "true")));
        rbtnonlyIbtn.setSelected(Boolean.parseBoolean(advProp.getProperty("only.ibutton", "false")));
        rbtnonlyMCU.setSelected(Boolean.parseBoolean(advProp.getProperty("only.mcu", "false")));
        
        internet_ChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("detect.internet", "true")));
        Ext_drive_ChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("detect.external.drive", "true")));
        Keep_log_ChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("keep.log.header", "false")));
        Audible_Tone_ChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("audible.tone", "false")));
        showOutputChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("show.output", "false")));
        jScrollPane3.setVisible(Boolean.parseBoolean(advProp.getProperty("show.output", "false")));
        BootHexPath.setText(advProp.getProperty("Boot Hex Path", null));
        buttonGroup1.add(jRadioButton1);
        buttonGroup1.add(jRadioButton2);
        
        Blinker_Task = new TimerTask() {
            @Override
            public void run() {
            if(Pair_index<11 && Pair_index >0 && blink){
            if(iBtn_panels.get(Pair_index-1).getBackground().equals(Color.GREEN)){
                iBtn_panels.get(Pair_index-1).setBackground(disabled_color);
                MCU_panels.get(Pair_index-1).setBackground(disabled_color);                   
            }else{
                iBtn_panels.get(Pair_index-1).setBackground(Color.GREEN);
                MCU_panels.get(Pair_index-1).setBackground(Color.GREEN);
            }}
            }
         };
        Timer timer = new Timer();
        timer.scheduleAtFixedRate(Blinker_Task, 0, 300);
        advProp.setProperty("Temp Hex Path", "");
        
        iBtnEvents ibtnEvent=new iBtnEvents();
        ibtnEvent.addObserver();
        new ibtnObserver();
        
        initialSeting=true;
        String[] devices = null ;
            try{
            DeviceSupport devSupport = DeviceSupport.getInstance();
            devices  =devSupport.getDeviceNamesInFamily(Family.DSPIC30);
            }
            catch(Exception v){
            //  System.out.println("Error in loading devices in this family");
            }
            if(devices!=null){
            for(String s:devices )
            {
            DeviceCmbBx.addItem(s);
            }
            if(advProp.getProperty("Device",null)!=null){
                DeviceCmbBx.setSelectedItem(advProp.getProperty("Device"));
            }
            }
        
        initialSeting =false;
        resourceMap = getResourceMap();

         popup = new JPopupMenu();
        //final JMenuItem item1 = new JMenuItem("Split View");
        final JMenuItem item2 = new JMenuItem("Clear Window");
        final JMenuItem item3 = new JMenuItem("Copy");
        popup.add(item2);
        popup.add(item3);
        statusArea1.addMouseListener(new MouseAdapter(){
        public void mouseReleased(MouseEvent Me){
        if(Me.isPopupTrigger()){
        popup.show(Me.getComponent(), Me.getX(), Me.getY());
        }
        }
        public void mousePressed(MouseEvent e) {
        if (e.isPopupTrigger()) {
        popup.show(e.getComponent(), e.getX(), e.getY());
        }
        e.getComponent().repaint();
        }
        }
        );


        item2.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
        statusArea1.setText("");
        }

        });
        item3.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
        StringSelection stringSelection = new StringSelection(statusArea.getText());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        }
        }
        );

        thisKeyCount.addKeyListener(new KeyListener() {

        public void keyTyped(KeyEvent e) {
          //  throw new UnsupportedOperationException("Not supported yet.");
        if(e.getKeyChar()==KeyEvent.VK_ENTER){
             advProp.setProperty("this.key.count", thisKeyCount.getText());
            }
        }

        public void keyPressed(KeyEvent e) {
        //    throw new UnsupportedOperationException("Not supported yet.");
        }

        public void keyReleased(KeyEvent e) {
         //   throw new UnsupportedOperationException("Not supported yet.");
        }
    });

    jPasswordField1.addKeyListener(new KeyListener() {

        public void keyTyped(KeyEvent e) {
          //  throw new UnsupportedOperationException("Not supported yet.");
        if(e.getKeyChar()==KeyEvent.VK_ENTER){
             DecryptHexBtn.doClick();
            }
        }

        public void keyPressed(KeyEvent e) {
        //    throw new UnsupportedOperationException("Not supported yet.");
        }

        public void keyReleased(KeyEvent e) {
         //   throw new UnsupportedOperationException("Not supported yet.");
        }
    });

    Runnable r = new ConnectThread();
    Thread t = new Thread(r);
    t.start();
    //StartBtn.setEnabled(true);
    }

    @Action
    public void showAboutBox() {
        if (aboutBox == null) {
            JFrame mainFrame = SecureIPApp.getApplication().getMainFrame();
            aboutBox = new SecureIPAboutBox(mainFrame);
            aboutBox.setLocationRelativeTo(mainFrame);
        }
        SecureIPApp.getApplication().show(aboutBox);
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        upperpanel = new javax.swing.JPanel();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        MainDialog = new javax.swing.JPanel();
        StartBtn = new javax.swing.JButton();
        jScrollPane3 = new javax.swing.JScrollPane();
        statusArea1 = new javax.swing.JTextPane();
        StatusLbl = new javax.swing.JLabel();
        jPanel2 = new javax.swing.JPanel();
        BtnReset = new javax.swing.JButton();
        BtnRefresh = new javax.swing.JButton();
        pgmrIDlabel = new javax.swing.JLabel();
        jLabel29 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        jPanel8 = new javax.swing.JPanel();
        ibtn1Lbl = new javax.swing.JLabel();
        jPanel12 = new javax.swing.JPanel();
        jLabel19 = new javax.swing.JLabel();
        jPanel13 = new javax.swing.JPanel();
        ibtn2Lbl = new javax.swing.JLabel();
        jPanel14 = new javax.swing.JPanel();
        jLabel20 = new javax.swing.JLabel();
        jPanel15 = new javax.swing.JPanel();
        ibtn3Lbl = new javax.swing.JLabel();
        jPanel16 = new javax.swing.JPanel();
        jLabel21 = new javax.swing.JLabel();
        jPanel17 = new javax.swing.JPanel();
        ibtn4Lbl = new javax.swing.JLabel();
        jPanel18 = new javax.swing.JPanel();
        jLabel22 = new javax.swing.JLabel();
        jPanel19 = new javax.swing.JPanel();
        ibtn5Lbl = new javax.swing.JLabel();
        jPanel20 = new javax.swing.JPanel();
        jLabel23 = new javax.swing.JLabel();
        jPanel22 = new javax.swing.JPanel();
        ibtn6Lbl = new javax.swing.JLabel();
        jPanel23 = new javax.swing.JPanel();
        jLabel24 = new javax.swing.JLabel();
        jPanel24 = new javax.swing.JPanel();
        ibtn7Lbl = new javax.swing.JLabel();
        jPanel25 = new javax.swing.JPanel();
        jLabel25 = new javax.swing.JLabel();
        jPanel26 = new javax.swing.JPanel();
        ibtn8Lbl = new javax.swing.JLabel();
        jPanel27 = new javax.swing.JPanel();
        jLabel26 = new javax.swing.JLabel();
        jPanel28 = new javax.swing.JPanel();
        ibtn9Lbl = new javax.swing.JLabel();
        jPanel29 = new javax.swing.JPanel();
        jLabel27 = new javax.swing.JLabel();
        jPanel21 = new javax.swing.JPanel();
        ibtn10Lbl = new javax.swing.JLabel();
        jPanel30 = new javax.swing.JPanel();
        jLabel28 = new javax.swing.JLabel();
        ConfigurePanel = new javax.swing.JPanel();
        jPanel6 = new javax.swing.JPanel();
        hexFilePath = new javax.swing.JTextField();
        hexBtn = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        jPasswordField1 = new javax.swing.JPasswordField();
        DecryptHexBtn = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jPanel9 = new javax.swing.JPanel();
        DeviceCmbBx = new javax.swing.JComboBox();
        jPanel7 = new javax.swing.JPanel();
        jComboBox1 = new javax.swing.JComboBox();
        jPanel10 = new javax.swing.JPanel();
        jLabel10 = new javax.swing.JLabel();
        BootHexPath = new javax.swing.JTextField();
        hexBtn1 = new javax.swing.JButton();
        jPanel31 = new javax.swing.JPanel();
        rbtnonlyIbtn = new javax.swing.JRadioButton();
        rbtnonlyMCU = new javax.swing.JRadioButton();
        rbtnBoth = new javax.swing.JRadioButton();
        jPanel5 = new javax.swing.JPanel();
        internet_ChkBx = new javax.swing.JCheckBox();
        Ext_drive_ChkBx = new javax.swing.JCheckBox();
        pwdChangeAlert = new javax.swing.JCheckBox();
        thisKeyCount = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        diagnosticsPanel = new javax.swing.JPanel();
        Keep_log_ChkBx = new javax.swing.JCheckBox();
        Audible_Tone_ChkBx = new javax.swing.JCheckBox();
        showOutputChkBx = new javax.swing.JCheckBox();
        jPanel11 = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jButton1 = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jSeparator1 = new javax.swing.JSeparator();
        jLabel8 = new javax.swing.JLabel();
        jLabel9 = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jRadioButton1 = new javax.swing.JRadioButton();
        jRadioButton2 = new javax.swing.JRadioButton();
        pwdTxtField = new javax.swing.JTextField();
        unlockBtn = new javax.swing.JButton();
        jLabel14 = new javax.swing.JLabel();
        jButton4 = new javax.swing.JButton();
        jPanel4 = new javax.swing.JPanel();
        jButton3 = new javax.swing.JButton();
        menuBar = new javax.swing.JMenuBar();
        javax.swing.JMenu fileMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem exitMenuItem = new javax.swing.JMenuItem();
        jMenu1 = new javax.swing.JMenu();
        jMenuItem1 = new javax.swing.JMenuItem();
        javax.swing.JMenu helpMenu = new javax.swing.JMenu();
        javax.swing.JMenuItem aboutMenuItem = new javax.swing.JMenuItem();
        statusPanel = new javax.swing.JPanel();
        progressBar = new javax.swing.JProgressBar();
        jScrollPane2 = new javax.swing.JScrollPane();
        statusArea = new javax.swing.JTextPane();
        buttonGroup1 = new javax.swing.ButtonGroup();

        upperpanel.setMaximumSize(new java.awt.Dimension(600, 450));
        upperpanel.setName("upperpanel"); // NOI18N
        upperpanel.setPreferredSize(new java.awt.Dimension(600, 450));
        upperpanel.setLayout(new java.awt.GridLayout(1, 0));

        jTabbedPane1.setBorder(javax.swing.BorderFactory.createEtchedBorder());
        jTabbedPane1.setTabPlacement(javax.swing.JTabbedPane.LEFT);
        org.jdesktop.application.ResourceMap resourceMap = org.jdesktop.application.Application.getInstance(secureip.SecureIPApp.class).getContext().getResourceMap(SecureIPView.class);
        jTabbedPane1.setFont(resourceMap.getFont("jTabbedPane1.font")); // NOI18N
        jTabbedPane1.setName("jTabbedPane1"); // NOI18N
        //jTabbedPane1.setUI(new BasicTabbedPaneUI() {
            //    @Override
            //    protected int calculateTabAreaHeight(int tab_placement, int run_count, int max_tab_height) {
                //       if (jTabbedPane1.getTabCount() > 1)
                //           return super.calculateTabAreaHeight(tab_placement, run_count, max_tab_height);
                //        else
                //            return 0;
                //   }
            //});
    jTabbedPane1.addChangeListener(new javax.swing.event.ChangeListener() {
        public void stateChanged(javax.swing.event.ChangeEvent evt) {
            jTabbedPane1StateChanged(evt);
        }
    });

    MainDialog.setMaximumSize(new java.awt.Dimension(450, 350));
    MainDialog.setName("MainDialog"); // NOI18N
    MainDialog.setPreferredSize(new java.awt.Dimension(450, 350));

    StartBtn.setFont(resourceMap.getFont("StartBtn.font")); // NOI18N
    StartBtn.setIcon(resourceMap.getIcon("StartBtn.icon")); // NOI18N
    StartBtn.setText(resourceMap.getString("StartBtn.text")); // NOI18N
    StartBtn.setHorizontalTextPosition(javax.swing.SwingConstants.LEFT);
    StartBtn.setIconTextGap(10);
    StartBtn.setName("StartBtn"); // NOI18N
    StartBtn.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            StartBtnActionPerformed(evt);
        }
    });

    jScrollPane3.setName("jScrollPane3"); // NOI18N

    statusArea1.setEditable(false);
    statusArea1.setName("statusArea1"); // NOI18N
    jScrollPane3.setViewportView(statusArea1);

    StatusLbl.setFont(resourceMap.getFont("StatusLbl.font")); // NOI18N
    StatusLbl.setText(resourceMap.getString("StatusLbl.text")); // NOI18N
    StatusLbl.setName("StatusLbl"); // NOI18N

    jPanel2.setName("jPanel2"); // NOI18N

    BtnReset.setText(resourceMap.getString("BtnReset.text")); // NOI18N
    BtnReset.setName("BtnReset"); // NOI18N

    BtnRefresh.setText(resourceMap.getString("BtnRefresh.text")); // NOI18N
    BtnRefresh.setName("BtnRefresh"); // NOI18N
    BtnRefresh.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            BtnRefreshActionPerformed(evt);
        }
    });

    pgmrIDlabel.setFont(resourceMap.getFont("jLabel29.font")); // NOI18N
    pgmrIDlabel.setForeground(resourceMap.getColor("jLabel29.foreground")); // NOI18N
    pgmrIDlabel.setText(resourceMap.getString("pgmrIDlabel.text")); // NOI18N
    pgmrIDlabel.setName("pgmrIDlabel"); // NOI18N

    jLabel29.setFont(resourceMap.getFont("jLabel29.font")); // NOI18N
    jLabel29.setText(resourceMap.getString("jLabel29.text")); // NOI18N
    jLabel29.setName("jLabel29"); // NOI18N

    javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
    jPanel2.setLayout(jPanel2Layout);
    jPanel2Layout.setHorizontalGroup(
        jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel2Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jLabel29)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(pgmrIDlabel, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 631, Short.MAX_VALUE)
            .addComponent(BtnReset, javax.swing.GroupLayout.PREFERRED_SIZE, 80, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(BtnRefresh, javax.swing.GroupLayout.PREFERRED_SIZE, 81, javax.swing.GroupLayout.PREFERRED_SIZE))
    );

    jPanel2Layout.linkSize(javax.swing.SwingConstants.HORIZONTAL, new java.awt.Component[] {BtnRefresh, BtnReset});

    jPanel2Layout.setVerticalGroup(
        jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel2Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.CENTER)
                .addComponent(pgmrIDlabel, javax.swing.GroupLayout.PREFERRED_SIZE, 14, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(jLabel29)
                .addComponent(BtnReset)
                .addComponent(BtnRefresh))
            .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
    );

    jPanel2Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jLabel29, pgmrIDlabel});

    jPanel2Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {BtnRefresh, BtnReset});

    jPanel1.setName("jPanel1"); // NOI18N
    jPanel1.setLayout(new java.awt.GridLayout(10, 2, 5, 5));

    jPanel8.setBackground(resourceMap.getColor("jPanel8.background")); // NOI18N
    jPanel8.setName("jPanel8"); // NOI18N

    ibtn1Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn1Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn1Lbl.setText(resourceMap.getString("ibtn1Lbl.text")); // NOI18N
    ibtn1Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn1Lbl.setDisabledIcon(resourceMap.getIcon("ibtn1Lbl.disabledIcon")); // NOI18N
    ibtn1Lbl.setName("ibtn1Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel8Layout = new javax.swing.GroupLayout(jPanel8);
    jPanel8.setLayout(jPanel8Layout);
    jPanel8Layout.setHorizontalGroup(
        jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn1Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel8Layout.setVerticalGroup(
        jPanel8Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn1Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel8);

    jPanel12.setBackground(resourceMap.getColor("jPanel12.background")); // NOI18N
    jPanel12.setName("jPanel12"); // NOI18N

    jLabel19.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel19.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel19.setText(resourceMap.getString("jLabel19.text")); // NOI18N
    jLabel19.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel19.setDisabledIcon(resourceMap.getIcon("jLabel19.disabledIcon")); // NOI18N
    jLabel19.setName("jLabel19"); // NOI18N

    javax.swing.GroupLayout jPanel12Layout = new javax.swing.GroupLayout(jPanel12);
    jPanel12.setLayout(jPanel12Layout);
    jPanel12Layout.setHorizontalGroup(
        jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel19, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel12Layout.setVerticalGroup(
        jPanel12Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel19, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel12);

    jPanel13.setBackground(resourceMap.getColor("jPanel13.background")); // NOI18N
    jPanel13.setName("jPanel13"); // NOI18N

    ibtn2Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn2Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn2Lbl.setText(resourceMap.getString("ibtn2Lbl.text")); // NOI18N
    ibtn2Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn2Lbl.setDisabledIcon(resourceMap.getIcon("ibtn2Lbl.disabledIcon")); // NOI18N
    ibtn2Lbl.setName("ibtn2Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel13Layout = new javax.swing.GroupLayout(jPanel13);
    jPanel13.setLayout(jPanel13Layout);
    jPanel13Layout.setHorizontalGroup(
        jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn2Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel13Layout.setVerticalGroup(
        jPanel13Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn2Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel13);

    jPanel14.setBackground(resourceMap.getColor("jPanel14.background")); // NOI18N
    jPanel14.setName("jPanel14"); // NOI18N

    jLabel20.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel20.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel20.setText(resourceMap.getString("jLabel20.text")); // NOI18N
    jLabel20.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel20.setDisabledIcon(resourceMap.getIcon("jLabel20.disabledIcon")); // NOI18N
    jLabel20.setName("jLabel20"); // NOI18N

    javax.swing.GroupLayout jPanel14Layout = new javax.swing.GroupLayout(jPanel14);
    jPanel14.setLayout(jPanel14Layout);
    jPanel14Layout.setHorizontalGroup(
        jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel20, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel14Layout.setVerticalGroup(
        jPanel14Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel20, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel14);

    jPanel15.setBackground(resourceMap.getColor("jPanel15.background")); // NOI18N
    jPanel15.setName("jPanel15"); // NOI18N

    ibtn3Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn3Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn3Lbl.setText(resourceMap.getString("ibtn3Lbl.text")); // NOI18N
    ibtn3Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn3Lbl.setDisabledIcon(resourceMap.getIcon("ibtn3Lbl.disabledIcon")); // NOI18N
    ibtn3Lbl.setName("ibtn3Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel15Layout = new javax.swing.GroupLayout(jPanel15);
    jPanel15.setLayout(jPanel15Layout);
    jPanel15Layout.setHorizontalGroup(
        jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn3Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel15Layout.setVerticalGroup(
        jPanel15Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn3Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel15);

    jPanel16.setBackground(resourceMap.getColor("jPanel16.background")); // NOI18N
    jPanel16.setName("jPanel16"); // NOI18N

    jLabel21.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel21.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel21.setText(resourceMap.getString("jLabel21.text")); // NOI18N
    jLabel21.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel21.setDisabledIcon(resourceMap.getIcon("jLabel21.disabledIcon")); // NOI18N
    jLabel21.setName("jLabel21"); // NOI18N

    javax.swing.GroupLayout jPanel16Layout = new javax.swing.GroupLayout(jPanel16);
    jPanel16.setLayout(jPanel16Layout);
    jPanel16Layout.setHorizontalGroup(
        jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel21, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel16Layout.setVerticalGroup(
        jPanel16Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel21, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel16);

    jPanel17.setBackground(resourceMap.getColor("jPanel17.background")); // NOI18N
    jPanel17.setName("jPanel17"); // NOI18N

    ibtn4Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn4Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn4Lbl.setText(resourceMap.getString("ibtn4Lbl.text")); // NOI18N
    ibtn4Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn4Lbl.setDisabledIcon(resourceMap.getIcon("ibtn4Lbl.disabledIcon")); // NOI18N
    ibtn4Lbl.setName("ibtn4Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel17Layout = new javax.swing.GroupLayout(jPanel17);
    jPanel17.setLayout(jPanel17Layout);
    jPanel17Layout.setHorizontalGroup(
        jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn4Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel17Layout.setVerticalGroup(
        jPanel17Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn4Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel17);

    jPanel18.setBackground(resourceMap.getColor("jPanel18.background")); // NOI18N
    jPanel18.setName("jPanel18"); // NOI18N

    jLabel22.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel22.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel22.setText(resourceMap.getString("jLabel22.text")); // NOI18N
    jLabel22.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel22.setDisabledIcon(resourceMap.getIcon("jLabel22.disabledIcon")); // NOI18N
    jLabel22.setName("jLabel22"); // NOI18N

    javax.swing.GroupLayout jPanel18Layout = new javax.swing.GroupLayout(jPanel18);
    jPanel18.setLayout(jPanel18Layout);
    jPanel18Layout.setHorizontalGroup(
        jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel22, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel18Layout.setVerticalGroup(
        jPanel18Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel22, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel18);

    jPanel19.setBackground(resourceMap.getColor("jPanel19.background")); // NOI18N
    jPanel19.setName("jPanel19"); // NOI18N

    ibtn5Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn5Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn5Lbl.setText(resourceMap.getString("ibtn5Lbl.text")); // NOI18N
    ibtn5Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn5Lbl.setDisabledIcon(resourceMap.getIcon("ibtn5Lbl.disabledIcon")); // NOI18N
    ibtn5Lbl.setName("ibtn5Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel19Layout = new javax.swing.GroupLayout(jPanel19);
    jPanel19.setLayout(jPanel19Layout);
    jPanel19Layout.setHorizontalGroup(
        jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn5Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel19Layout.setVerticalGroup(
        jPanel19Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn5Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel19);

    jPanel20.setBackground(resourceMap.getColor("jPanel20.background")); // NOI18N
    jPanel20.setName("jPanel20"); // NOI18N

    jLabel23.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel23.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel23.setText(resourceMap.getString("jLabel23.text")); // NOI18N
    jLabel23.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel23.setDisabledIcon(resourceMap.getIcon("jLabel23.disabledIcon")); // NOI18N
    jLabel23.setName("jLabel23"); // NOI18N

    javax.swing.GroupLayout jPanel20Layout = new javax.swing.GroupLayout(jPanel20);
    jPanel20.setLayout(jPanel20Layout);
    jPanel20Layout.setHorizontalGroup(
        jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel23, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel20Layout.setVerticalGroup(
        jPanel20Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel23, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel20);

    jPanel22.setBackground(resourceMap.getColor("jPanel22.background")); // NOI18N
    jPanel22.setName("jPanel22"); // NOI18N

    ibtn6Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn6Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn6Lbl.setText(resourceMap.getString("ibtn6Lbl.text")); // NOI18N
    ibtn6Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn6Lbl.setDisabledIcon(resourceMap.getIcon("ibtn6Lbl.disabledIcon")); // NOI18N
    ibtn6Lbl.setName("ibtn6Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel22Layout = new javax.swing.GroupLayout(jPanel22);
    jPanel22.setLayout(jPanel22Layout);
    jPanel22Layout.setHorizontalGroup(
        jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn6Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel22Layout.setVerticalGroup(
        jPanel22Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn6Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel22);

    jPanel23.setBackground(resourceMap.getColor("jPanel23.background")); // NOI18N
    jPanel23.setName("jPanel23"); // NOI18N

    jLabel24.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel24.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel24.setText(resourceMap.getString("jLabel24.text")); // NOI18N
    jLabel24.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel24.setDisabledIcon(resourceMap.getIcon("jLabel24.disabledIcon")); // NOI18N
    jLabel24.setName("jLabel24"); // NOI18N

    javax.swing.GroupLayout jPanel23Layout = new javax.swing.GroupLayout(jPanel23);
    jPanel23.setLayout(jPanel23Layout);
    jPanel23Layout.setHorizontalGroup(
        jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel24, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel23Layout.setVerticalGroup(
        jPanel23Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel24, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel23);

    jPanel24.setBackground(resourceMap.getColor("jPanel24.background")); // NOI18N
    jPanel24.setName("jPanel24"); // NOI18N

    ibtn7Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn7Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn7Lbl.setText(resourceMap.getString("ibtn7Lbl.text")); // NOI18N
    ibtn7Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn7Lbl.setDisabledIcon(resourceMap.getIcon("ibtn7Lbl.disabledIcon")); // NOI18N
    ibtn7Lbl.setName("ibtn7Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel24Layout = new javax.swing.GroupLayout(jPanel24);
    jPanel24.setLayout(jPanel24Layout);
    jPanel24Layout.setHorizontalGroup(
        jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn7Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel24Layout.setVerticalGroup(
        jPanel24Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn7Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel24);

    jPanel25.setBackground(resourceMap.getColor("jPanel25.background")); // NOI18N
    jPanel25.setName("jPanel25"); // NOI18N

    jLabel25.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel25.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel25.setText(resourceMap.getString("jLabel25.text")); // NOI18N
    jLabel25.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel25.setDisabledIcon(resourceMap.getIcon("jLabel25.disabledIcon")); // NOI18N
    jLabel25.setName("jLabel25"); // NOI18N

    javax.swing.GroupLayout jPanel25Layout = new javax.swing.GroupLayout(jPanel25);
    jPanel25.setLayout(jPanel25Layout);
    jPanel25Layout.setHorizontalGroup(
        jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel25, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel25Layout.setVerticalGroup(
        jPanel25Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel25, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel25);

    jPanel26.setBackground(resourceMap.getColor("jPanel26.background")); // NOI18N
    jPanel26.setName("jPanel26"); // NOI18N

    ibtn8Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn8Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn8Lbl.setText(resourceMap.getString("ibtn8Lbl.text")); // NOI18N
    ibtn8Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn8Lbl.setDisabledIcon(resourceMap.getIcon("ibtn8Lbl.disabledIcon")); // NOI18N
    ibtn8Lbl.setName("ibtn8Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel26Layout = new javax.swing.GroupLayout(jPanel26);
    jPanel26.setLayout(jPanel26Layout);
    jPanel26Layout.setHorizontalGroup(
        jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn8Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel26Layout.setVerticalGroup(
        jPanel26Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn8Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel26);

    jPanel27.setBackground(resourceMap.getColor("jPanel27.background")); // NOI18N
    jPanel27.setName("jPanel27"); // NOI18N

    jLabel26.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel26.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel26.setText(resourceMap.getString("jLabel26.text")); // NOI18N
    jLabel26.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel26.setDisabledIcon(resourceMap.getIcon("jLabel26.disabledIcon")); // NOI18N
    jLabel26.setName("jLabel26"); // NOI18N

    javax.swing.GroupLayout jPanel27Layout = new javax.swing.GroupLayout(jPanel27);
    jPanel27.setLayout(jPanel27Layout);
    jPanel27Layout.setHorizontalGroup(
        jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel26, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel27Layout.setVerticalGroup(
        jPanel27Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel26, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel27);

    jPanel28.setBackground(resourceMap.getColor("jPanel28.background")); // NOI18N
    jPanel28.setName("jPanel28"); // NOI18N

    ibtn9Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn9Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn9Lbl.setText(resourceMap.getString("ibtn9Lbl.text")); // NOI18N
    ibtn9Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn9Lbl.setDisabledIcon(resourceMap.getIcon("ibtn9Lbl.disabledIcon")); // NOI18N
    ibtn9Lbl.setName("ibtn9Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel28Layout = new javax.swing.GroupLayout(jPanel28);
    jPanel28.setLayout(jPanel28Layout);
    jPanel28Layout.setHorizontalGroup(
        jPanel28Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn9Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel28Layout.setVerticalGroup(
        jPanel28Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn9Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel28);

    jPanel29.setBackground(resourceMap.getColor("jPanel29.background")); // NOI18N
    jPanel29.setName("jPanel29"); // NOI18N

    jLabel27.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel27.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel27.setText(resourceMap.getString("jLabel27.text")); // NOI18N
    jLabel27.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel27.setDisabledIcon(resourceMap.getIcon("jLabel27.disabledIcon")); // NOI18N
    jLabel27.setName("jLabel27"); // NOI18N

    javax.swing.GroupLayout jPanel29Layout = new javax.swing.GroupLayout(jPanel29);
    jPanel29.setLayout(jPanel29Layout);
    jPanel29Layout.setHorizontalGroup(
        jPanel29Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel27, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel29Layout.setVerticalGroup(
        jPanel29Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel27, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel29);

    jPanel21.setBackground(resourceMap.getColor("jPanel21.background")); // NOI18N
    jPanel21.setName("jPanel21"); // NOI18N

    ibtn10Lbl.setFont(resourceMap.getFont("ibtn1Lbl.font")); // NOI18N
    ibtn10Lbl.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    ibtn10Lbl.setText(resourceMap.getString("ibtn10Lbl.text")); // NOI18N
    ibtn10Lbl.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    ibtn10Lbl.setDisabledIcon(resourceMap.getIcon("ibtn10Lbl.disabledIcon")); // NOI18N
    ibtn10Lbl.setName("ibtn10Lbl"); // NOI18N

    javax.swing.GroupLayout jPanel21Layout = new javax.swing.GroupLayout(jPanel21);
    jPanel21.setLayout(jPanel21Layout);
    jPanel21Layout.setHorizontalGroup(
        jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn10Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel21Layout.setVerticalGroup(
        jPanel21Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(ibtn10Lbl, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel21);

    jPanel30.setBackground(resourceMap.getColor("jPanel30.background")); // NOI18N
    jPanel30.setName("jPanel30"); // NOI18N

    jLabel28.setFont(resourceMap.getFont("jLabel28.font")); // NOI18N
    jLabel28.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
    jLabel28.setText(resourceMap.getString("jLabel28.text")); // NOI18N
    jLabel28.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    jLabel28.setDisabledIcon(resourceMap.getIcon("jLabel28.disabledIcon")); // NOI18N
    jLabel28.setName("jLabel28"); // NOI18N

    javax.swing.GroupLayout jPanel30Layout = new javax.swing.GroupLayout(jPanel30);
    jPanel30.setLayout(jPanel30Layout);
    jPanel30Layout.setHorizontalGroup(
        jPanel30Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel28, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 536, Short.MAX_VALUE)
    );
    jPanel30Layout.setVerticalGroup(
        jPanel30Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jLabel28, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 30, Short.MAX_VALUE)
    );

    jPanel1.add(jPanel30);

    javax.swing.GroupLayout MainDialogLayout = new javax.swing.GroupLayout(MainDialog);
    MainDialog.setLayout(MainDialogLayout);
    MainDialogLayout.setHorizontalGroup(
        MainDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, MainDialogLayout.createSequentialGroup()
            .addContainerGap()
            .addGroup(MainDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addComponent(jPanel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jScrollPane3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)
                .addComponent(jPanel1, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)
                .addComponent(StartBtn, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)
                .addComponent(StatusLbl, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE))
            .addContainerGap())
    );
    MainDialogLayout.setVerticalGroup(
        MainDialogLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, MainDialogLayout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, 347, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(StartBtn)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 147, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(StatusLbl, javax.swing.GroupLayout.PREFERRED_SIZE, 24, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
    );

    jTabbedPane1.addTab(resourceMap.getString("MainDialog.TabConstraints.tabTitle"), MainDialog); // NOI18N

    ConfigurePanel.setMaximumSize(new java.awt.Dimension(450, 350));
    ConfigurePanel.setName("ConfigurePanel"); // NOI18N
    ConfigurePanel.setPreferredSize(new java.awt.Dimension(450, 350));

    jPanel6.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel6.border.title"))); // NOI18N
    jPanel6.setName("jPanel6"); // NOI18N

    hexFilePath.setEditable(false);
    hexFilePath.setName("hexFilePath"); // NOI18N

    hexBtn.setText(resourceMap.getString("hexBtn.text")); // NOI18N
    hexBtn.setName("hexBtn"); // NOI18N
    hexBtn.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            hexBtnActionPerformed(evt);
        }
    });

    jLabel1.setText(resourceMap.getString("jLabel1.text")); // NOI18N
    jLabel1.setName("jLabel1"); // NOI18N

    jPasswordField1.setText(resourceMap.getString("jPasswordField1.text")); // NOI18N
    jPasswordField1.setName("jPasswordField1"); // NOI18N

    DecryptHexBtn.setText(resourceMap.getString("DecryptHexBtn.text")); // NOI18N
    DecryptHexBtn.setName("DecryptHexBtn"); // NOI18N
    DecryptHexBtn.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            DecryptHexBtnActionPerformed(evt);
        }
    });

    jLabel2.setText(resourceMap.getString("jLabel2.text")); // NOI18N
    jLabel2.setName("jLabel2"); // NOI18N

    javax.swing.GroupLayout jPanel6Layout = new javax.swing.GroupLayout(jPanel6);
    jPanel6.setLayout(jPanel6Layout);
    jPanel6Layout.setHorizontalGroup(
        jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel6Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jLabel1)
                .addComponent(jLabel2))
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPasswordField1, javax.swing.GroupLayout.DEFAULT_SIZE, 845, Short.MAX_VALUE)
                .addComponent(hexFilePath, javax.swing.GroupLayout.DEFAULT_SIZE, 845, Short.MAX_VALUE))
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                .addComponent(DecryptHexBtn, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(hexBtn, javax.swing.GroupLayout.DEFAULT_SIZE, 99, Short.MAX_VALUE))
            .addContainerGap())
    );
    jPanel6Layout.setVerticalGroup(
        jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel6Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(hexFilePath, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(hexBtn)
                .addComponent(jLabel2))
            .addGap(18, 18, 18)
            .addGroup(jPanel6Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel1)
                .addComponent(jPasswordField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(DecryptHexBtn))
            .addContainerGap(22, Short.MAX_VALUE))
    );

    jPanel6Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {DecryptHexBtn, hexBtn, hexFilePath, jPasswordField1});

    jPanel9.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel9.border.title"))); // NOI18N
    jPanel9.setName("jPanel9"); // NOI18N

    DeviceCmbBx.setName("DeviceCmbBx"); // NOI18N
    DeviceCmbBx.addItemListener(new java.awt.event.ItemListener() {
        public void itemStateChanged(java.awt.event.ItemEvent evt) {
            DeviceCmbBxItemStateChanged(evt);
        }
    });

    javax.swing.GroupLayout jPanel9Layout = new javax.swing.GroupLayout(jPanel9);
    jPanel9.setLayout(jPanel9Layout);
    jPanel9Layout.setHorizontalGroup(
        jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel9Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(DeviceCmbBx, 0, 1046, Short.MAX_VALUE)
            .addContainerGap())
    );
    jPanel9Layout.setVerticalGroup(
        jPanel9Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel9Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(DeviceCmbBx, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap(20, Short.MAX_VALUE))
    );

    jPanel7.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel7.border.title"))); // NOI18N
    jPanel7.setName("jPanel7"); // NOI18N

    jComboBox1.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "DS1977" }));
    jComboBox1.setEnabled(false);
    jComboBox1.setName("jComboBox1"); // NOI18N

    javax.swing.GroupLayout jPanel7Layout = new javax.swing.GroupLayout(jPanel7);
    jPanel7.setLayout(jPanel7Layout);
    jPanel7Layout.setHorizontalGroup(
        jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel7Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jComboBox1, 0, 1046, Short.MAX_VALUE)
            .addContainerGap())
    );
    jPanel7Layout.setVerticalGroup(
        jPanel7Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel7Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap(12, Short.MAX_VALUE))
    );

    jPanel10.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel10.border.title"))); // NOI18N
    jPanel10.setName("jPanel10"); // NOI18N

    jLabel10.setText(resourceMap.getString("jLabel10.text")); // NOI18N
    jLabel10.setName("jLabel10"); // NOI18N

    BootHexPath.setEditable(false);
    BootHexPath.setName("BootHexPath"); // NOI18N

    hexBtn1.setText(resourceMap.getString("hexBtn1.text")); // NOI18N
    hexBtn1.setName("hexBtn1"); // NOI18N
    hexBtn1.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            hexBtn1ActionPerformed(evt);
        }
    });

    javax.swing.GroupLayout jPanel10Layout = new javax.swing.GroupLayout(jPanel10);
    jPanel10.setLayout(jPanel10Layout);
    jPanel10Layout.setHorizontalGroup(
        jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel10Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jLabel10)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(BootHexPath, javax.swing.GroupLayout.DEFAULT_SIZE, 899, Short.MAX_VALUE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(hexBtn1, javax.swing.GroupLayout.PREFERRED_SIZE, 36, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap())
    );
    jPanel10Layout.setVerticalGroup(
        jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel10Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel10Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(BootHexPath, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(hexBtn1)
                .addComponent(jLabel10))
            .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
    );

    jPanel31.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel31.border.title"))); // NOI18N
    jPanel31.setName("jPanel31"); // NOI18N

    rbtnonlyIbtn.setText(resourceMap.getString("rbtnonlyIbtn.text")); // NOI18N
    rbtnonlyIbtn.setName("rbtnonlyIbtn"); // NOI18N
    rbtnonlyIbtn.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            rbtnonlyIbtnActionPerformed(evt);
        }
    });

    rbtnonlyMCU.setText(resourceMap.getString("rbtnonlyMCU.text")); // NOI18N
    rbtnonlyMCU.setName("rbtnonlyMCU"); // NOI18N
    rbtnonlyMCU.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            rbtnonlyMCUActionPerformed(evt);
        }
    });

    rbtnBoth.setText(resourceMap.getString("rbtnBoth.text")); // NOI18N
    rbtnBoth.setName("rbtnBoth"); // NOI18N
    rbtnBoth.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            rbtnBothActionPerformed(evt);
        }
    });

    javax.swing.GroupLayout jPanel31Layout = new javax.swing.GroupLayout(jPanel31);
    jPanel31.setLayout(jPanel31Layout);
    jPanel31Layout.setHorizontalGroup(
        jPanel31Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel31Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel31Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(rbtnonlyIbtn)
                .addComponent(rbtnonlyMCU)
                .addComponent(rbtnBoth))
            .addContainerGap(149, Short.MAX_VALUE))
    );
    jPanel31Layout.setVerticalGroup(
        jPanel31Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel31Layout.createSequentialGroup()
            .addGap(22, 22, 22)
            .addComponent(rbtnonlyIbtn)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(rbtnonlyMCU)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(rbtnBoth)
            .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
    );

    javax.swing.GroupLayout ConfigurePanelLayout = new javax.swing.GroupLayout(ConfigurePanel);
    ConfigurePanel.setLayout(ConfigurePanelLayout);
    ConfigurePanelLayout.setHorizontalGroup(
        ConfigurePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(ConfigurePanelLayout.createSequentialGroup()
            .addContainerGap()
            .addGroup(ConfigurePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jPanel31, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(jPanel6, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jPanel9, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jPanel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jPanel10, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addContainerGap())
    );
    ConfigurePanelLayout.setVerticalGroup(
        ConfigurePanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(ConfigurePanelLayout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jPanel6, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addGap(11, 11, 11)
            .addComponent(jPanel10, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addGap(18, 18, 18)
            .addComponent(jPanel9, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addGap(18, 18, 18)
            .addComponent(jPanel7, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(jPanel31, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addGap(139, 139, 139))
    );

    jTabbedPane1.addTab(resourceMap.getString("ConfigurePanel.TabConstraints.tabTitle"), ConfigurePanel); // NOI18N

    jPanel5.setName("jPanel5"); // NOI18N

    internet_ChkBx.setText(resourceMap.getString("internet_ChkBx.text")); // NOI18N
    internet_ChkBx.setName("internet_ChkBx"); // NOI18N
    internet_ChkBx.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            internet_ChkBxActionPerformed(evt);
        }
    });

    Ext_drive_ChkBx.setText(resourceMap.getString("Ext_drive_ChkBx.text")); // NOI18N
    Ext_drive_ChkBx.setName("Ext_drive_ChkBx"); // NOI18N
    Ext_drive_ChkBx.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            Ext_drive_ChkBxActionPerformed(evt);
        }
    });

    pwdChangeAlert.setText(resourceMap.getString("pwdChangeAlert.text")); // NOI18N
    pwdChangeAlert.setName("pwdChangeAlert"); // NOI18N
    pwdChangeAlert.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            pwdChangeAlertActionPerformed(evt);
        }
    });

    thisKeyCount.setText(resourceMap.getString("thisKeyCount.text")); // NOI18N
    thisKeyCount.setName("thisKeyCount"); // NOI18N

    jLabel7.setText(resourceMap.getString("jLabel7.text")); // NOI18N
    jLabel7.setName("jLabel7"); // NOI18N

    javax.swing.GroupLayout jPanel5Layout = new javax.swing.GroupLayout(jPanel5);
    jPanel5.setLayout(jPanel5Layout);
    jPanel5Layout.setHorizontalGroup(
        jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel5Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(internet_ChkBx, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 493, Short.MAX_VALUE)
                .addGroup(jPanel5Layout.createSequentialGroup()
                    .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel5Layout.createSequentialGroup()
                            .addComponent(pwdChangeAlert)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(thisKeyCount))
                        .addComponent(Ext_drive_ChkBx, javax.swing.GroupLayout.Alignment.LEADING))
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 172, javax.swing.GroupLayout.PREFERRED_SIZE)))
            .addGap(599, 599, 599))
    );
    jPanel5Layout.setVerticalGroup(
        jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel5Layout.createSequentialGroup()
            .addGap(21, 21, 21)
            .addComponent(internet_ChkBx)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(Ext_drive_ChkBx)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addGroup(jPanel5Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(pwdChangeAlert)
                .addComponent(thisKeyCount, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(jLabel7))
            .addGap(559, 559, 559))
    );

    jTabbedPane1.addTab(resourceMap.getString("jPanel5.TabConstraints.tabTitle"), jPanel5); // NOI18N

    diagnosticsPanel.setName("diagnosticsPanel"); // NOI18N

    Keep_log_ChkBx.setSelected(true);
    Keep_log_ChkBx.setText(resourceMap.getString("Keep_log_ChkBx.text")); // NOI18N
    Keep_log_ChkBx.setName("Keep_log_ChkBx"); // NOI18N
    Keep_log_ChkBx.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            Keep_log_ChkBxActionPerformed(evt);
        }
    });

    Audible_Tone_ChkBx.setText(resourceMap.getString("Audible_Tone_ChkBx.text")); // NOI18N
    Audible_Tone_ChkBx.setName("Audible_Tone_ChkBx"); // NOI18N
    Audible_Tone_ChkBx.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            Audible_Tone_ChkBxActionPerformed(evt);
        }
    });

    showOutputChkBx.setText(resourceMap.getString("showOutputChkBx.text")); // NOI18N
    showOutputChkBx.setName("showOutputChkBx"); // NOI18N
    showOutputChkBx.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            showOutputChkBxActionPerformed(evt);
        }
    });

    jPanel11.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jPanel11.border.title"))); // NOI18N
    jPanel11.setName("jPanel11"); // NOI18N

    jLabel3.setText(resourceMap.getString("jLabel3.text")); // NOI18N
    jLabel3.setName("jLabel3"); // NOI18N

    jLabel4.setText(resourceMap.getString("jLabel4.text")); // NOI18N
    jLabel4.setName("jLabel4"); // NOI18N

    jButton1.setText(resourceMap.getString("jButton1.text")); // NOI18N
    jButton1.setName("jButton1"); // NOI18N
    jButton1.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            jButton1ActionPerformed(evt);
        }
    });

    jLabel5.setForeground(resourceMap.getColor("jLabel6.foreground")); // NOI18N
    jLabel5.setText(resourceMap.getString("jLabel5.text")); // NOI18N
    jLabel5.setName("jLabel5"); // NOI18N

    jLabel6.setForeground(resourceMap.getColor("jLabel6.foreground")); // NOI18N
    jLabel6.setText(resourceMap.getString("jLabel6.text")); // NOI18N
    jLabel6.setName("jLabel6"); // NOI18N

    jSeparator1.setName("jSeparator1"); // NOI18N

    jLabel8.setText(resourceMap.getString("jLabel8.text")); // NOI18N
    jLabel8.setName("jLabel8"); // NOI18N

    jLabel9.setForeground(resourceMap.getColor("jLabel9.foreground")); // NOI18N
    jLabel9.setText(resourceMap.getString("jLabel9.text")); // NOI18N
    jLabel9.setName("jLabel9"); // NOI18N

    javax.swing.GroupLayout jPanel11Layout = new javax.swing.GroupLayout(jPanel11);
    jPanel11.setLayout(jPanel11Layout);
    jPanel11Layout.setHorizontalGroup(
        jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addComponent(jSeparator1, javax.swing.GroupLayout.DEFAULT_SIZE, 1066, Short.MAX_VALUE)
        .addGroup(jPanel11Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jLabel8)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(jLabel9, javax.swing.GroupLayout.PREFERRED_SIZE, 61, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap(801, Short.MAX_VALUE))
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel11Layout.createSequentialGroup()
            .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel11Layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(jButton1, javax.swing.GroupLayout.PREFERRED_SIZE, 182, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGroup(jPanel11Layout.createSequentialGroup()
                    .addGap(14, 14, 14)
                    .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 78, Short.MAX_VALUE))
                    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                    .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 94, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel6, javax.swing.GroupLayout.DEFAULT_SIZE, 409, Short.MAX_VALUE))))
            .addGap(559, 559, 559))
    );
    jPanel11Layout.setVerticalGroup(
        jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel11Layout.createSequentialGroup()
            .addContainerGap()
            .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 23, Short.MAX_VALUE)
                .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel5)
                .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(jButton1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
            .addGap(18, 18, 18)
            .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addGap(37, 37, 37)
            .addGroup(jPanel11Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel8)
                .addComponent(jLabel9, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addGap(28, 28, 28))
    );

    jPanel11Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton1, jLabel3, jLabel4, jLabel5, jLabel6});

    jPanel11Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jLabel8, jLabel9});

    javax.swing.GroupLayout diagnosticsPanelLayout = new javax.swing.GroupLayout(diagnosticsPanel);
    diagnosticsPanel.setLayout(diagnosticsPanelLayout);
    diagnosticsPanelLayout.setHorizontalGroup(
        diagnosticsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, diagnosticsPanelLayout.createSequentialGroup()
            .addContainerGap()
            .addGroup(diagnosticsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addComponent(jPanel11, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(Audible_Tone_ChkBx, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)
                .addComponent(Keep_log_ChkBx, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 412, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(showOutputChkBx, javax.swing.GroupLayout.Alignment.LEADING))
            .addContainerGap())
    );
    diagnosticsPanelLayout.setVerticalGroup(
        diagnosticsPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(diagnosticsPanelLayout.createSequentialGroup()
            .addGap(15, 15, 15)
            .addComponent(Keep_log_ChkBx)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(Audible_Tone_ChkBx)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
            .addComponent(showOutputChkBx)
            .addGap(18, 18, 18)
            .addComponent(jPanel11, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap(323, Short.MAX_VALUE))
    );

    jTabbedPane1.addTab(resourceMap.getString("diagnosticsPanel.TabConstraints.tabTitle"), diagnosticsPanel); // NOI18N

    jPanel3.setName("jPanel3"); // NOI18N

    jScrollPane1.setName("jScrollPane1"); // NOI18N

    jTextArea1.setColumns(20);
    jTextArea1.setRows(5);
    jTextArea1.setName("jTextArea1"); // NOI18N
    jScrollPane1.setViewportView(jTextArea1);

    jRadioButton1.setSelected(true);
    jRadioButton1.setText(resourceMap.getString("jRadioButton1.text")); // NOI18N
    jRadioButton1.setName("jRadioButton1"); // NOI18N

    jRadioButton2.setText(resourceMap.getString("jRadioButton2.text")); // NOI18N
    jRadioButton2.setName("jRadioButton2"); // NOI18N
    jRadioButton2.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            jRadioButton2ActionPerformed(evt);
        }
    });

    pwdTxtField.setText(resourceMap.getString("pwdTxtField.text")); // NOI18N
    pwdTxtField.setName("pwdTxtField"); // NOI18N

    unlockBtn.setText(resourceMap.getString("unlockBtn.text")); // NOI18N
    unlockBtn.setName("unlockBtn"); // NOI18N
    unlockBtn.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            unlockBtnActionPerformed(evt);
        }
    });

    jLabel14.setText(resourceMap.getString("jLabel14.text")); // NOI18N
    jLabel14.setName("jLabel14"); // NOI18N

    jButton4.setText(resourceMap.getString("jButton4.text")); // NOI18N
    jButton4.setName("jButton4"); // NOI18N
    jButton4.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            jButton4ActionPerformed(evt);
        }
    });

    javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
    jPanel3.setLayout(jPanel3Layout);
    jPanel3Layout.setHorizontalGroup(
        jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addComponent(jLabel14, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 1088, Short.MAX_VALUE)
                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel3Layout.createSequentialGroup()
                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addGroup(jPanel3Layout.createSequentialGroup()
                            .addGap(10, 10, 10)
                            .addComponent(jRadioButton1, javax.swing.GroupLayout.DEFAULT_SIZE, 945, Short.MAX_VALUE))
                        .addGroup(jPanel3Layout.createSequentialGroup()
                            .addContainerGap()
                            .addComponent(pwdTxtField, javax.swing.GroupLayout.DEFAULT_SIZE, 842, Short.MAX_VALUE)
                            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                            .addComponent(jButton4, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGap(133, 133, 133))
                .addGroup(javax.swing.GroupLayout.Alignment.LEADING, jPanel3Layout.createSequentialGroup()
                    .addContainerGap()
                    .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jRadioButton2, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)))
                .addGroup(jPanel3Layout.createSequentialGroup()
                    .addContainerGap()
                    .addComponent(unlockBtn, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)))
            .addContainerGap())
    );
    jPanel3Layout.setVerticalGroup(
        jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel3Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jRadioButton1)
            .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
            .addComponent(jLabel14)
            .addGap(4, 4, 4)
            .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(pwdTxtField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(unlockBtn)
                .addComponent(jButton4))
            .addGap(27, 27, 27)
            .addComponent(jRadioButton2)
            .addGap(7, 7, 7)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 171, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addGap(357, 357, 357))
    );

    jPanel3Layout.linkSize(javax.swing.SwingConstants.VERTICAL, new java.awt.Component[] {jButton4, pwdTxtField, unlockBtn});

    jTabbedPane1.addTab(resourceMap.getString("jPanel3.TabConstraints.tabTitle"), jPanel3); // NOI18N

    jPanel4.setName("jPanel4"); // NOI18N

    jButton3.setText(resourceMap.getString("jButton3.text")); // NOI18N
    jButton3.setName("jButton3"); // NOI18N
    jButton3.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            jButton3ActionPerformed(evt);
        }
    });

    javax.swing.GroupLayout jPanel4Layout = new javax.swing.GroupLayout(jPanel4);
    jPanel4.setLayout(jPanel4Layout);
    jPanel4Layout.setHorizontalGroup(
        jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel4Layout.createSequentialGroup()
            .addContainerGap()
            .addComponent(jButton3, javax.swing.GroupLayout.DEFAULT_SIZE, 1078, Short.MAX_VALUE)
            .addContainerGap())
    );
    jPanel4Layout.setVerticalGroup(
        jPanel4Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(jPanel4Layout.createSequentialGroup()
            .addGap(360, 360, 360)
            .addComponent(jButton3, javax.swing.GroupLayout.PREFERRED_SIZE, 51, javax.swing.GroupLayout.PREFERRED_SIZE)
            .addContainerGap())
    );

    jTabbedPane1.addTab(resourceMap.getString("jPanel4.TabConstraints.tabTitle"), jPanel4); // NOI18N

    upperpanel.add(jTabbedPane1);

    menuBar.setName("menuBar"); // NOI18N

    fileMenu.setText(resourceMap.getString("fileMenu.text")); // NOI18N
    fileMenu.setName("fileMenu"); // NOI18N

    javax.swing.ActionMap actionMap = org.jdesktop.application.Application.getInstance(secureip.SecureIPApp.class).getContext().getActionMap(SecureIPView.class, this);
    exitMenuItem.setAction(actionMap.get("quit")); // NOI18N
    exitMenuItem.setName("exitMenuItem"); // NOI18N
    fileMenu.add(exitMenuItem);

    menuBar.add(fileMenu);

    jMenu1.setText(resourceMap.getString("jMenu1.text")); // NOI18N
    jMenu1.setName("jMenu1"); // NOI18N

    jMenuItem1.setText(resourceMap.getString("jMenuItem1.text")); // NOI18N
    jMenuItem1.setName("jMenuItem1"); // NOI18N
    jMenuItem1.addActionListener(new java.awt.event.ActionListener() {
        public void actionPerformed(java.awt.event.ActionEvent evt) {
            jMenuItem1ActionPerformed(evt);
        }
    });
    jMenu1.add(jMenuItem1);

    menuBar.add(jMenu1);

    helpMenu.setText(resourceMap.getString("helpMenu.text")); // NOI18N
    helpMenu.setName("helpMenu"); // NOI18N

    aboutMenuItem.setAction(actionMap.get("showAboutBox")); // NOI18N
    aboutMenuItem.setName("aboutMenuItem"); // NOI18N
    helpMenu.add(aboutMenuItem);

    menuBar.add(helpMenu);

    statusPanel.setBorder(javax.swing.BorderFactory.createEtchedBorder());
    statusPanel.setName("statusPanel"); // NOI18N
    statusPanel.setLayout(new java.awt.GridLayout(1, 0));

    progressBar.setName("progressBar"); // NOI18N
    statusPanel.add(progressBar);

    jScrollPane2.setBorder(javax.swing.BorderFactory.createTitledBorder(resourceMap.getString("jScrollPane2.border.title"))); // NOI18N
    jScrollPane2.setName("jScrollPane2"); // NOI18N

    statusArea.setEditable(false);
    statusArea.setName("statusArea"); // NOI18N
    jScrollPane2.setViewportView(statusArea);

    setComponent(upperpanel);
    setMenuBar(menuBar);
    setStatusBar(statusPanel);
    }// </editor-fold>//GEN-END:initComponents

    private void jMenuItem1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jMenuItem1ActionPerformed
        RequestPW rpw = new RequestPW(null, true);
        rpw.setLocationRelativeTo(this.getFrame());
        Image icon2 = Toolkit.getDefaultToolkit().getImage(SecureIPApp.class.getResource("resources/login_icon.gif"));
        rpw.setIconImage(icon2);
        rpw.setVisible(true);
    }//GEN-LAST:event_jMenuItem1ActionPerformed


     private boolean checkForValidity() {
            File temp = new File(advProp.getProperty("Hex Path", ""));
            if(temp.exists()==false){
                setStatus("Hex file not available at the specified location...", Color.red, true);
                return false;
            }
//            if(get_Current_ibtn_serial() ==null){
//                setStatus("No iButtons detected", Color.RED, false);
//                return false;
//            }
            if(advProp.getProperty("Temp Hex Path","").equals("")){
                JOptionPane.showMessageDialog(this.getRootPane(), "Please provide password to decrypt the hex file.\nContact advanced user.", "Security conflict",  JOptionPane.ERROR_MESSAGE);
                return false;
            }
            return true;
        }


       private byte[] getproper(byte[] passk) {
        byte[] dat = new byte[16];
        for(int h=0;h<16;h++){
           dat[h] = (byte) (passk[h] & 0xF);

        }
        return dat;
    }

    private void refreshUI() {

        for(int m=0;m<10;m++){
            if(All_buttons.isEmpty() == false ){
            String serial = All_buttons.get(m);
            if(serial.startsWith("000000")==false){
              iBtn_panels.get(m).setBackground(Color.yellow);
              iBtn_labels.get(m).setText(serial);
            }else{
              iBtn_panels.get(m).setBackground(disabled_color);
              iBtn_labels.get(m).setText("iButton not connected");
            }
            }
            if(All_MCUs.isEmpty() == false ){
            String devID = All_MCUs.get(m);
            if(devID.contains("00000000")==false){
              MCU_panels.get(m).setBackground(Color.yellow);
              String toDisplay = "Device ID:"+devID.substring(0,4) + " Revision:" + devID.substring(4, 8);
              MCU_labels.get(m).setText(toDisplay);
            }else{
              MCU_panels.get(m).setBackground(disabled_color);
              MCU_labels.get(m).setText("PIC MCU not connected");
            }
            }
        }
    }


    private enum PageTypes{
        SCRATCH_PAD,
        DATA_MEMORY,
        PASSWORD
    }


    public class Full_Info{
        public JPanel ibtn_panel;
        public JLabel ibtn_label;
        public JLabel MCU_label;
        public JPanel mcu_panel;
        public File boot_hex;
        public byte[] aes_key_random = new byte[16];
        public byte[] ibtn_serial_key = new byte[16];
        public byte[] ibtn_full_key = new byte[8];
        public byte[] ibtn_read_key = new byte[8];        
        public Full_Info(){

        }
    }
    
    
     public PhysicalMemory getMemory(Assembly session,Class cMemory)
    {
        MemoryModel Mem=null;
        PhysicalMemory physicalmemory = null;
        Assembly assembly=session;
        if(assembly!=null){
            if((Mem = (MemoryModel)assembly.getLookup().lookup(cMemory)) != null)
            {
                memModel = Mem;
                if(Mem == null) return null;
                else {
                    physicalmemory = Mem.GetPhysicalMemory();
                    memoryObserver =  new MemoryObserver();
                    ((Subject)physicalmemory).Attach(memoryObserver, null);
                }
            }
        }
        return physicalmemory;
    }

    
    private void StartBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_StartBtnActionPerformed
        Thread checksum = new Thread(new Runnable() {
        public void run  ()
        {   
           controlAllButtons(false);
           int count = Math.min(All_MCUs.size(),All_buttons.size());
           for(Pair_index=1;Pair_index<count+1;Pair_index++){
           boolean val = true; 
           blink = true;
           byte[] random_FA_lock_data = new byte[16];
           random.nextBytes(random_FA_lock_data);
           random.nextBytes(aes_key);
           aes_key = getproper(aes_key);
           System.arraycopy(random_FA_lock_data, 0, lock_data, 2, 16);
           String ibtn = get_Current_ibtn_serial();          
           ibtn_serial = get_Serial_Key_in_bytes(ibtn);           
           
           if(checkForValidity() && Boolean.parseBoolean(advProp.getProperty("only.mcu","false"))==false && hexFileParser()){
           setStatus("Programming iButton - "+Pair_index+"/"+count+".\n", Color.BLUE, val);
           DataFrame df = new DataFrame();
           df.Command = PgmIbtn;
           val = SendPacketRecieveResponse(df);  
           if(val){
            df = new DataFrame();
            df.Command = LockIbtn;
            df.Payload = lock_data;
            val = SendPacketRecieveResponse(df); 
            write_to_header(val);
           }           
           } 
           if(val && Boolean.parseBoolean(advProp.getProperty("only.ibutton","false"))==false && BoothexFileParser()){
           setStatus("Programming MCU - "+Pair_index+"/"+count+".\n", Color.BLUE,false);
           DataFrame df = new DataFrame();
           df.Command = PgmMCU;
           val = SendPacketRecieveResponse(df);
           if(val==false){
               iBtn_panels.get(Pair_index-1).setBackground(Color.RED);
               MCU_panels.get(Pair_index-1).setBackground(Color.RED);
           }
           } 
           blink = false;
           if(val==false){
              String fail = advProp.getProperty("fail count","0");
              long f = Long.parseLong(fail, 10);
              advProp.setProperty("fail count",Long.toString(f+1, 10));
              iBtn_panels.get(Pair_index-1).setBackground(Color.RED);
              MCU_panels.get(Pair_index-1).setBackground(Color.RED);
           }else{
              String pass = advProp.getProperty("pass count","0");
              long  p = Long.parseLong(pass, 10);
              advProp.setProperty("pass count",Long.toString(p+1, 10));
              iBtn_panels.get(Pair_index-1).setBackground(Color.GREEN);
              MCU_panels.get(Pair_index-1).setBackground(Color.GREEN); 
           }
           if(Boolean.parseBoolean(advProp.getProperty("audible.tone","false"))){
               sharedData.sound(3000, 500, 1.0);
           }
        }
           //timer.cancel();           
           //Blinker_Task.cancel();

           controlAllButtons(true);
        }});
        checksum.start();       
    }//GEN-LAST:event_StartBtnActionPerformed

    private void hexBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hexBtnActionPerformed
        String path =  System.getProperty("user.home");
        final JFileChooser projectChooser = new JFileChooser(path);
        ExtensionFileFilter filter1 =  new ExtensionFileFilter("hex file", new String[] {"hex"});
        projectChooser.setFileFilter(filter1);
        projectChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int status=projectChooser.showOpenDialog(null);
        if(status==JFileChooser.APPROVE_OPTION) {
            hexFilePath.setText( projectChooser.getSelectedFile().getAbsolutePath());
            advProp.setProperty("Hex Path", hexFilePath.getText());
            sharedData.setGlobalProps(advProp);
        } else if(status==JFileChooser.CANCEL_OPTION){
            setStatus("No hex file selected.", Color.RED,false);
        }
}//GEN-LAST:event_hexBtnActionPerformed

    private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton3ActionPerformed
        advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        advProp.setProperty("both.as.pair", Boolean.toString(rbtnBoth.isSelected()));
        advProp.setProperty("only.mcu", Boolean.toString(rbtnonlyMCU.isSelected()));
        advProp.setProperty("only.ibutton", Boolean.toString(rbtnonlyIbtn.isSelected()));
        sharedData.setGlobalProps(advProp);
        pse.saveToFile(advProp);
        jTabbedPane1.setVisible(false);
        upperpanel.add(MainDialog);
        upperpanel.remove(jTabbedPane1);
    }//GEN-LAST:event_jButton3ActionPerformed

    private void jTabbedPane1StateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jTabbedPane1StateChanged
        //if(diagnosticsPanel.isShowing()){
            jLabel4.setText(advProp.getProperty("pass count","0"));
            jLabel6.setText(advProp.getProperty("fail count","0"));
            showOutputChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("show.output","false")));
            Keep_log_ChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("keep.log.header", "false")));
            Audible_Tone_ChkBx.setSelected(Boolean.parseBoolean(advProp.getProperty("audible.tone", "false")));
            jLabel9.setText(advProp.getProperty("failed.attempts","0"));
            pwdChangeAlert.setSelected(Boolean.parseBoolean(advProp.getProperty("alert.change", "false")));
            thisKeyCount.setText(advProp.getProperty("this.key.count","10"));

        //}
    }//GEN-LAST:event_jTabbedPane1StateChanged

    private void unlockBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_unlockBtnActionPerformed

        Thread unlock = new Thread(new Runnable() {

        public void run() {
        controlAllButtons(false);
        String pwd = pwdTxtField.getText();
        String[] pfg = new String[8];
        byte[] pass = new byte[8];
        pfg = pwd.split(",");
        String[] temp = new String[8];

        int tem = 7;
        for(int x=0; x<8;x++){
            temp[tem] = pfg[x];
            tem--;
        }
        //pfg = temp;
        try{
        for(int m=0;m<8;m++){
            pfg[m] = pfg[m].trim();
            if(pfg[m].contains("0x")){
                pfg[m] = pfg[m].replace("0x", "");
            }
            pass[m] = (byte) Long.parseLong(pfg[m], 16);
        }}
        catch(Exception m){
            System.out.print(m.getMessage());
        }

        DataFrame df = new DataFrame();
        df.Command = IbtnRecovery;
        df.Length =10;
        df.Payload = new byte[10];
        df.Payload[0] = 0;
        df.Payload[1] = 0x1;
        System.arraycopy(pass, 0, df.Payload, 2, 8);
        SendPacketRecieveResponse(df);
        df.Command = EraseIbtn;
        df.Payload = new byte[2];
        df.Length = 2;
        df.Payload[0] = 0;
        df.Payload[1] = 0x1;
        SendPacketRecieveResponse(df);
        controlAllButtons(true);
        }});
        unlock.start();
       
    }//GEN-LAST:event_unlockBtnActionPerformed

    private void jRadioButton2ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jRadioButton2ActionPerformed
        if(jRadioButton2.isSelected()){
        String path =  System.getProperty("user.home");
        final JFileChooser projectChooser = new JFileChooser(path);
        ExtensionFileFilter filter1 =  new ExtensionFileFilter("txt (Text File)", new String[] {"txt"});
        projectChooser.setFileFilter (filter1);
        projectChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int status=projectChooser.showOpenDialog(null);
        if(status==JFileChooser.APPROVE_OPTION)
        {
        RandomAccessFile history=null;
        byte[] full = null;
            try {
                history = new RandomAccessFile(projectChooser.getSelectedFile(), "rw");
                full = new byte[(int)history.length()];
                history.readFully(full);
                DesEncrypter des = new DesEncrypter("i14746");
                jTextArea1.setText(des.decrypt(new String(full)));//des.decrypt(new String(full)), Color.BLACK, false);

            } catch (Exception ex) {
                jTextArea1.setText("Failed to decrypt the header file");
                Exceptions.printStackTrace(ex);
            }


        }
        else if(status==JFileChooser.CANCEL_OPTION){
            setStatus("History file not selected\n", Color.RED,false);
        }
        }
    }//GEN-LAST:event_jRadioButton2ActionPerformed

    private void DeviceCmbBxItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_DeviceCmbBxItemStateChanged
        if(evt.getStateChange()!=ItemEvent.SELECTED) return;
        if(initialSeting==false){
        advProp.setProperty("Device", (String)evt.getItem());        
        }
    }//GEN-LAST:event_DeviceCmbBxItemStateChanged

    private void Audible_Tone_ChkBxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Audible_Tone_ChkBxActionPerformed
       advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        sharedData.setGlobalProps(advProp);
    }//GEN-LAST:event_Audible_Tone_ChkBxActionPerformed

    private void Ext_drive_ChkBxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Ext_drive_ChkBxActionPerformed
        advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        sharedData.setGlobalProps(advProp);
    }//GEN-LAST:event_Ext_drive_ChkBxActionPerformed

    private void internet_ChkBxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_internet_ChkBxActionPerformed
       advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        sharedData.setGlobalProps(advProp);
    }//GEN-LAST:event_internet_ChkBxActionPerformed

    private void Keep_log_ChkBxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_Keep_log_ChkBxActionPerformed
        advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        sharedData.setGlobalProps(advProp);
    }//GEN-LAST:event_Keep_log_ChkBxActionPerformed

    private void showOutputChkBxActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_showOutputChkBxActionPerformed
        advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        sharedData.setGlobalProps(advProp);
    }//GEN-LAST:event_showOutputChkBxActionPerformed

    private void DecryptHexBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_DecryptHexBtnActionPerformed
        doDecrypt();
        
    }//GEN-LAST:event_DecryptHexBtnActionPerformed

    private void pwdChangeAlertActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_pwdChangeAlertActionPerformed
        advProp.setProperty("detect.internet", Boolean.toString(internet_ChkBx.isSelected()));
        advProp.setProperty("alert.change", Boolean.toString(pwdChangeAlert.isSelected()));
        advProp.setProperty("this.key.count", thisKeyCount.getText());
        advProp.setProperty("detect.external.drive", Boolean.toString(Ext_drive_ChkBx.isSelected()));
        advProp.setProperty("show.output", Boolean.toString(showOutputChkBx.isSelected()));
        advProp.setProperty("audible.tone", Boolean.toString(Audible_Tone_ChkBx.isSelected()));
        advProp.setProperty("keep.log.header", Boolean.toString(Keep_log_ChkBx.isSelected()));
        sharedData.setGlobalProps(advProp);
    }//GEN-LAST:event_pwdChangeAlertActionPerformed

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
       advProp.setProperty("pass count", "0");
       advProp.setProperty("fail count", "0");
       sharedData.setGlobalProps(advProp);
       jLabel4.setText(advProp.getProperty("pass count","0"));
       jLabel6.setText(advProp.getProperty("fail count","0"));
    }//GEN-LAST:event_jButton1ActionPerformed

    private void BtnRefreshActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_BtnRefreshActionPerformed
        Thread refresh = new Thread(new Runnable() {   
        public void run() {
        controlAllButtons(false);
        boolean retval = false;
        DataFrame df = new DataFrame();
        df.Command = FetchPgmrID;
        setStatus("Fetching Programmer ID...", Color.BLUE, false);
        retval = SendPacketRecieveResponse(df);
        if(retval){
            df = new DataFrame();
            df.Command = FetchIbtn;
            setStatus("Updating iButtons list...", Color.BLUE, false);
            retval = SendPacketRecieveResponse(df);
        }      
        if(retval){
            df = new DataFrame();
            df.Command = FetchDevID;
            setStatus("Updating Microcontrollers list...", Color.BLUE, false);
            SendPacketRecieveResponse(df);
        }
        setStatus("User interface rendering complete!", Color.BLUE, false);
        controlAllButtons(true);
        }});
        refresh.start();
    }//GEN-LAST:event_BtnRefreshActionPerformed

private void hexBtn1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_hexBtn1ActionPerformed
        String path =  System.getProperty("user.home");
        final JFileChooser projectChooser = new JFileChooser(path);
        ExtensionFileFilter filter1 =  new ExtensionFileFilter("hex file", new String[] {"hex"});
        projectChooser.setFileFilter(filter1);
        projectChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int status=projectChooser.showOpenDialog(null);
        if(status==JFileChooser.APPROVE_OPTION) {
            BootHexPath.setText( projectChooser.getSelectedFile().getAbsolutePath());
            advProp.setProperty("Boot Hex Path", BootHexPath.getText());
            sharedData.setGlobalProps(advProp);
        } else if(status==JFileChooser.CANCEL_OPTION){
           // setStatus("No hex file selected.", Color.RED,false);
        }
}//GEN-LAST:event_hexBtn1ActionPerformed

    private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton4ActionPerformed
         File backup_copy = new File(System.getProperty("user.home") + "/Preceptor/all_keys/"+All_buttons.get(0) +".txt");
        if(backup_copy.exists()==false){
            JOptionPane.showMessageDialog(this.getFrame(), "Backup file for this ibutton is not found", "Error", JOptionPane.ERROR_MESSAGE);
        }else{
            try {
                RandomAccessFile ra = new RandomAccessFile(backup_copy, "rw");
                byte[] copy = new byte[(int)ra.length()];
                ra.readFully(copy);
                String d = new String(copy);
                d = d.substring(d.lastIndexOf("iButtonPasswordFULL[8] = {"), d.lastIndexOf("iButtonPasswordFULL[8] = {")+65);
                d =d.replace("iButtonPasswordFULL[8] = {", "");
                pwdTxtField.setText(d);
            } catch (IOException ex) {
                Exceptions.printStackTrace(ex);
            }
        }
    }//GEN-LAST:event_jButton4ActionPerformed

    private void rbtnonlyIbtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rbtnonlyIbtnActionPerformed
       advProp.setProperty("only.ibutton",Boolean.toString(rbtnonlyIbtn.isSelected()));
       advProp.setProperty("only.mcu","false");
//       for(int p=0;p<10;p++){
//           iBtn_panels.get(p).setVisible(true);
//           MCU_panels.get(p).setVisible(false);
//           jPanel1.setLayout(new java.awt.BorderLayout(5,5));
//           
//       }
    }//GEN-LAST:event_rbtnonlyIbtnActionPerformed

    private void rbtnonlyMCUActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rbtnonlyMCUActionPerformed
       advProp.setProperty("only.mcu",Boolean.toString(rbtnonlyMCU.isSelected()));
       advProp.setProperty("only.ibutton","false");
//       for(int p=0;p<10;p++){
//           MCU_panels.get(p).setVisible(true);
//           iBtn_panels.get(p).setVisible(false);
//           jPanel1.setLayout(new java.awt.BorderLayout(5,5));
//           this.getFrame().validate();
//       }
    }//GEN-LAST:event_rbtnonlyMCUActionPerformed

    private void rbtnBothActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rbtnBothActionPerformed
        advProp.setProperty("pair.as.both",Boolean.toString(rbtnBoth.isSelected()));
        advProp.setProperty("only.ibutton","false");
        advProp.setProperty("only.mcu","false");    
//        for(int p=0;p<10;p++){
//           iBtn_panels.get(p).setVisible(true);
//           MCU_panels.get(p).setVisible(true);
//           jPanel1.setLayout(new java.awt.GridLayout(10, 2, 5, 5));
//           this.getFrame().validate();
//       }
    }//GEN-LAST:event_rbtnBothActionPerformed

    private void doDecrypt(){
        String pass = jPasswordField1.getText();
        advProp.setProperty("key", pass);
        if(Decrypt(pass) == false){
           int failed= Integer.parseInt(advProp.getProperty("failed.attempts","0"));
           advProp.setProperty("failed.attempts", Integer.toString(failed+1));
           if(failed>3){
               pse.saveToFile(advProp);
               JOptionPane.showMessageDialog(this.getRootPane(), "Decrypting hex file attempts have failed more than 3 times.\nPlease contact super user.", "Error",  JOptionPane.ERROR_MESSAGE);
           }
        }
         else{

         if(advProp.getProperty("key").compareTo(jPasswordField1.getText())!=0){
             advProp.setProperty("key.usage", "0");
         }
         
         JOptionPane.showMessageDialog(this.getRootPane(), "Successfully unlocked the hex file.", "Success",JOptionPane.INFORMATION_MESSAGE);
         }
    }
    private boolean Decrypt(String passkey){
        File temp = null;
        boolean retVal = true;
        try {
            AESCrypt aes = new AESCrypt(passkey);
            String destPath  =sharedData.getWD()+"/temp.hex";
            aes.decrypt(hexFilePath.getText(), destPath);
            advProp.setProperty("Temp Hex Path", destPath);
        } catch (GeneralSecurityException ex) {
            JOptionPane.showMessageDialog(this.getRootPane(), ex.getMessage(), "Error",  JOptionPane.ERROR_MESSAGE);
            retVal = false;
        } catch (UnsupportedEncodingException ex) {
            JOptionPane.showMessageDialog(this.getRootPane(), ex.getMessage(), "Error",  JOptionPane.ERROR_MESSAGE);
            retVal = false;
        } catch (IOException ex) {
             JOptionPane.showMessageDialog(this.getRootPane(), ex.getMessage(), "Error",  JOptionPane.ERROR_MESSAGE);
             retVal = false;
        }
        return retVal;
    }

     private void controlAllButtons(boolean b) {
        if(b==false){
            progressBar.setIndeterminate(true);
        }
        else{
            progressBar.setIndeterminate(false);
        }
          StartBtn.setEnabled(b);
          unlockBtn.setEnabled(b);
          BtnReset.setEnabled(b);
          BtnRefresh.setEnabled(b);
     }

     private String getMakeFilePath() {
        String makeFile = null;
        makeFile = advProp.getProperty("Install Path", null);
        makeFile = makeFile.replace("\\", "/");
        makeFile = makeFile.replace("mplab_ide/bin/mplab_ide.exe", "gnuBins/GnuWin32/bin/make.exe");
        return makeFile;
    }

    private String getBinPath(){
        String makeFile = null;
        makeFile = advProp.getProperty("Install Path", null);
        makeFile = makeFile.replace("\\", "/");
        makeFile = makeFile.replace("mplab_ide/bin/mplab_ide.exe", "mplab_ide/bin/");
        return makeFile;
    }

    private boolean hexFileParser(){

       if(Decrypt(jPasswordField1.getText()) == false){
            JOptionPane.showMessageDialog(this.getRootPane(), "Decryption failed", "Error",  JOptionPane.ERROR_MESSAGE);
            return false;
       }
     else{
        //if(advProp.getProperty("key").compareTo(jPasswordField1.getText())==0){
            int usage = Integer.parseInt(advProp.getProperty("key.usage", "0")) + 1;
            advProp.setProperty("key.usage", Integer.toString(usage));
            sharedData.setGlobalProps(advProp);
            pse.saveToFile(advProp);
            long thisKey = Long.parseLong(advProp.getProperty("this.key.count", "0"));

            if(Boolean.parseBoolean(advProp.getProperty("alert.change","false"))){
                if(usage>=thisKey){
                    JOptionPane.showMessageDialog(this.getRootPane(), "Password has been same since "+thisKey+" successful programming attempts.\nPlease contact advanced user.", "Change Password",  JOptionPane.ERROR_MESSAGE);
                    //System.exit(0);
                    return false;
                }
            }
     }
       if((advProp.getProperty("Temp Hex Path", null).contains(".hex") || advProp.getProperty("Hex Path", null).contains(".HEX"))==false ) return false;
       AssemblyFactory af = Lookup.getDefault().lookup(AssemblyFactory.class);
       //setStatus("Creating memory map for the target device - "+advProp.getProperty("Device", "dsPIC30F2010"), Color.BLUE, true);
       TARGET_DEVICE = advProp.getProperty("Device", "dsPIC30F2010");
       Assembly session = af.Create(TARGET_DEVICE);
       sharedData.setAssemblySession(session);//mdbSession.getLookup().lookup(Loader.class);
       Loader loader = session.getLookup().lookup(Loader.class);
       ArrayList<String> files = new ArrayList<String>();
        files.add(advProp.getProperty("Temp Hex Path", null));
        try {
        loader.Load(files, new Loader.Output() {

            @Override
            public void PrintMessage(String msg) {
              //setStatus(msg, Color.BLUE, true);
            }

            public void PrintError(String msg) {
            }
        });
        } catch (LoadException ex) {
            Exceptions.printStackTrace(ex);
        }
       File temp = new File(advProp.getProperty("Temp Hex Path", null));
       temp.delete();
       //setStatus("Encrypting the target hex file...", Color.BLUE, true);
       DataChunk dataC = new DataChunk();
       aes_key = getproper(aes_key);
       dataC.create_aes_object(new String(aes_key));
       dataC.fill_data_chunk();
       dataC.encrypt_chunks();
       //setStatus("Completed encrypting the target hex file.", Color.BLUE, true);
       sharedData.setEncryptedData(dataC.data_list);
       return true;
    }

     private boolean BoothexFileParser(){

       if((advProp.getProperty("Boot Hex Path", null).contains(".hex"))==false ) return false;
       AssemblyFactory af = Lookup.getDefault().lookup(AssemblyFactory.class);
       //setStatus("Creating memory map for the target device - "+advProp.getProperty("Device", "dsPIC30F2010"), Color.BLUE, true);
       TARGET_DEVICE = advProp.getProperty("Device", "dsPIC30F2010");
       Assembly session = af.Create(TARGET_DEVICE);
       sharedData.setAssemblySession(session);//mdbSession.getLookup().lookup(Loader.class);
       Loader loader = session.getLookup().lookup(Loader.class);
       ArrayList<String> files = new ArrayList<String>();
        files.add(advProp.getProperty("Boot Hex Path", null));
        try {
        loader.Load(files, new Loader.Output() {

            @Override
            public void PrintMessage(String msg) {
              //setStatus(msg, Color.BLUE, true);
            }

            public void PrintError(String msg) {
            }
        });
        } catch (LoadException ex) {
            Exceptions.printStackTrace(ex);
        }
//       File temp = new File(advProp.getProperty("Boot Hex Path", null));
//       temp.delete();
       PhysicalMemory pm = getMemory(session, ProgramMemory.class);
//       pm.Write(0x3d6a, 8, full_Access);
//       for(int n=0;n<16;){
//           byte[] dummy = new byte[4];
//           System.arraycopy(aes_key, n, dummy, 2, 4);
//           pm.Write(0x850+n/2,4, dummy);           
//       }
       byte[] dummy = new byte[3];
       System.arraycopy(lock_data, 10, i_key_read, 0, 8);
       System.arraycopy(i_key_read, 0, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3fd8, 3, dummy);
       System.arraycopy(i_key_read, 2, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3fda, 3, dummy);
       System.arraycopy(i_key_read, 4, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3fdc, 3, dummy);
       System.arraycopy(i_key_read, 6, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3fde, 3, dummy);
       
       System.arraycopy(aes_key, 0, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fe0, 3, dummy);
       System.arraycopy(aes_key, 2, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fe2, 3, dummy);
       System.arraycopy(aes_key, 4, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fe4, 3, dummy);
       System.arraycopy(aes_key, 6, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fe6, 3, dummy);
       System.arraycopy(aes_key, 8, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fe8, 3, dummy);
       System.arraycopy(aes_key, 10, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fea, 3, dummy);
       System.arraycopy(aes_key, 12, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fec, 3, dummy);
       System.arraycopy(aes_key, 14, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3fee, 3, dummy);
       
       System.arraycopy(ibtn_serial, 6, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3ff0, 3, dummy);
       System.arraycopy(ibtn_serial, 4, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3ff2, 3, dummy);
       System.arraycopy(ibtn_serial, 2, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3ff4, 3, dummy);
       System.arraycopy(ibtn_serial, 0, dummy, 1, 2);
       dummy = Reverse(dummy);
       pm.Write(0x3ff6, 3, dummy);
       
       System.arraycopy(lock_data, 2, full_Access, 0, 8);
       System.arraycopy(full_Access, 0, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3ff8, 3, dummy);
       System.arraycopy(full_Access, 2, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3ffa, 3, dummy);
       System.arraycopy(full_Access, 4, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3ffc, 3, dummy);
       System.arraycopy(full_Access, 6, dummy, 1, 2);
       dummy = Reverse_locks(dummy);
       pm.Write(0x3ffe, 3, dummy);
       
//       pm.Write(0x2b00,16,aes_key);
//       if(All_buttons.size()==0){
//          setStatus("No IButton available. Failed to fuse the ibutton serial name into Bootloader hex file.", Color.RED, false);
//          return false;
//       }
//       else {
//            pm.Write(0x3d52, 8, ibtn_serial);
//        }
       pm.CommitToTarget();
        try {
            loader.Save(System.getProperty("user.home")+"/saved.hex");
        } catch (LoadException ex) {
            Exceptions.printStackTrace(ex);
        }
       sharedData.setAssemblySession(session);
       DataChunk dataC = new DataChunk();
       dataC.create_aes_object(new String(actual_key));
       dataC.fill_Boot_data_chunk();       
       return true;
    }
    
     private byte[] Reverse(byte[] arr){
         byte dummy = arr[2];
         byte dummy1 = arr[1];
         arr[0] = dummy;
         arr[1] = dummy1;
         arr[2] = 0;
         return arr;
     }
     
      private byte[] Reverse_locks(byte[] arr){
         byte dummy = arr[2];
         byte dummy1 = arr[1];
         arr[1] = dummy;
         arr[0] = dummy1;
         arr[2] = 0;
         return arr;
     }
     
    private void PrepareIBtnData(){
     
       File temp = new File(advProp.getProperty("Temp Hex Path", null));
       temp.delete();
       setStatus("Encrypting the target hex file...", Color.BLUE, true);
       DataChunk dataC = new DataChunk();
       dataC.create_aes_object(new String(actual_key));
       dataC.fill_data_chunk();
       dataC.encrypt_chunks();
       setStatus("Completed encrypting the target hex file.", Color.BLUE, true);
       sharedData.setEncryptedData(dataC.data_list);

    }
     private String getHexPath(){
        String makeFile = null;
        makeFile = advProp.getProperty("Project Path", null);
        makeFile = makeFile.replace("\\", "/");
        String dummy = makeFile.substring(makeFile.lastIndexOf("/"), makeFile.length())+".production.hex";
        makeFile ="\""+makeFile+"/dist/default/production"+dummy+"\"";
        return makeFile;
     }

    private String join_serial (String array, String joinChar) {
        String joinedString = "";
        boolean firstFlag = true;
        int p =15;
        for ( p =16; p > 0;) {

        if (firstFlag) {
            joinedString += "0x"+array.substring(p-2,p);
            firstFlag = false;
        }
        else
            joinedString += joinChar + "0x"+array.substring(p-2,p);
        p = p - 2;

        }
    return joinedString;

}
    
    private byte[] get_Serial_Key_in_bytes (String array) {
        byte[] serial_key = new byte[8];
        int p =15;
        int i=0;
        for ( p =16; p > 0;) {
           String  joinedString = array.substring(p-2,p);  
//           long d = Long.parseLong(joinedString,16);
//           joinedString = Long.toString(d);
           //joinedString = Long.toString(d, 16);
           serial_key[i++] = (byte) (Integer.parseInt(joinedString, 16) & 0xFF);
           p = p - 2;

        }
        return serial_key;
    

}

    private String join_key (byte[] array, String joinChar) {
    String joinedString = "";
    boolean firstFlag = true;
    int p =0;
    for (p =0; p < 16;) {

        if (firstFlag) {
            joinedString += getMSBLSB_int(array[p+1],array[p]);
            firstFlag = false;
        }
        else
            joinedString += joinChar + getMSBLSB_int(array[p+1],array[p]);
        p = p + 2;
    }

    return joinedString;

    }

    private String join_password (byte[] array, String joinChar) {
    String joinedString = "";
    boolean firstFlag = true;
    int p =0;
    for (p =0; p < 8;p++) {

        if (firstFlag) {
            joinedString += "0x"+String.format("%02X", array[p]).trim();
            firstFlag = false;
        }
        else
            joinedString += joinChar + "0x"+String.format("%02X", array[p]).trim();
    }
    return joinedString;

    }

   private String join_serial_numbers (byte[] array, String joinChar) {
    String joinedString = "";
    boolean firstFlag = true;
    int p =0;
    for (p =0; p < 8;p++) {

        if (firstFlag) {
            joinedString +=String.format("%02X", array[p]).trim();
            firstFlag = false;
        }
        else
            joinedString += joinChar +String.format("%02X", array[p]).trim();
    }

    return joinedString;

    }

   private String join_MCU_dev_ID (byte[] array, String joinChar) {
    String joinedString = "";
    boolean firstFlag = true;
    int p =0;
    for (p =0; p < 4;p++) {

        if (firstFlag) {
            joinedString +=String.format("%02X", array[p]).trim();
            firstFlag = false;
        }
        else
            joinedString += joinChar +String.format("%02X", array[p]).trim();
    }
    return joinedString;

    }
   
     public String getMSBLSB_int(byte msb,byte lsb)
    {
        return "0x"+String.format("%02X", msb).trim()+String.format("%02X", lsb).trim();
    }



    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JCheckBox Audible_Tone_ChkBx;
    private javax.swing.JTextField BootHexPath;
    private javax.swing.JButton BtnRefresh;
    private javax.swing.JButton BtnReset;
    private javax.swing.JPanel ConfigurePanel;
    private javax.swing.JButton DecryptHexBtn;
    private javax.swing.JComboBox DeviceCmbBx;
    private javax.swing.JCheckBox Ext_drive_ChkBx;
    private javax.swing.JCheckBox Keep_log_ChkBx;
    public javax.swing.JPanel MainDialog;
    public javax.swing.JButton StartBtn;
    private javax.swing.JLabel StatusLbl;
    private javax.swing.ButtonGroup buttonGroup1;
    private javax.swing.JPanel diagnosticsPanel;
    private javax.swing.JButton hexBtn;
    private javax.swing.JButton hexBtn1;
    private javax.swing.JTextField hexFilePath;
    private javax.swing.JLabel ibtn10Lbl;
    private javax.swing.JLabel ibtn1Lbl;
    private javax.swing.JLabel ibtn2Lbl;
    private javax.swing.JLabel ibtn3Lbl;
    private javax.swing.JLabel ibtn4Lbl;
    private javax.swing.JLabel ibtn5Lbl;
    private javax.swing.JLabel ibtn6Lbl;
    private javax.swing.JLabel ibtn7Lbl;
    private javax.swing.JLabel ibtn8Lbl;
    private javax.swing.JLabel ibtn9Lbl;
    private javax.swing.JCheckBox internet_ChkBx;
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButton3;
    private javax.swing.JButton jButton4;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel14;
    private javax.swing.JLabel jLabel19;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel20;
    private javax.swing.JLabel jLabel21;
    private javax.swing.JLabel jLabel22;
    private javax.swing.JLabel jLabel23;
    private javax.swing.JLabel jLabel24;
    private javax.swing.JLabel jLabel25;
    private javax.swing.JLabel jLabel26;
    private javax.swing.JLabel jLabel27;
    private javax.swing.JLabel jLabel28;
    private javax.swing.JLabel jLabel29;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenuItem jMenuItem1;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel10;
    private javax.swing.JPanel jPanel11;
    private javax.swing.JPanel jPanel12;
    private javax.swing.JPanel jPanel13;
    private javax.swing.JPanel jPanel14;
    private javax.swing.JPanel jPanel15;
    private javax.swing.JPanel jPanel16;
    private javax.swing.JPanel jPanel17;
    private javax.swing.JPanel jPanel18;
    private javax.swing.JPanel jPanel19;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel20;
    private javax.swing.JPanel jPanel21;
    private javax.swing.JPanel jPanel22;
    private javax.swing.JPanel jPanel23;
    private javax.swing.JPanel jPanel24;
    private javax.swing.JPanel jPanel25;
    private javax.swing.JPanel jPanel26;
    private javax.swing.JPanel jPanel27;
    private javax.swing.JPanel jPanel28;
    private javax.swing.JPanel jPanel29;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel30;
    private javax.swing.JPanel jPanel31;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JPanel jPanel6;
    private javax.swing.JPanel jPanel7;
    private javax.swing.JPanel jPanel8;
    private javax.swing.JPanel jPanel9;
    private javax.swing.JPasswordField jPasswordField1;
    private javax.swing.JRadioButton jRadioButton1;
    private javax.swing.JRadioButton jRadioButton2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSeparator jSeparator1;
    public javax.swing.JTabbedPane jTabbedPane1;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JMenuBar menuBar;
    private javax.swing.JLabel pgmrIDlabel;
    private javax.swing.JProgressBar progressBar;
    private javax.swing.JCheckBox pwdChangeAlert;
    private javax.swing.JTextField pwdTxtField;
    private javax.swing.JRadioButton rbtnBoth;
    private javax.swing.JRadioButton rbtnonlyIbtn;
    private javax.swing.JRadioButton rbtnonlyMCU;
    private javax.swing.JCheckBox showOutputChkBx;
    private javax.swing.JTextPane statusArea;
    private javax.swing.JTextPane statusArea1;
    private javax.swing.JPanel statusPanel;
    private javax.swing.JTextField thisKeyCount;
    private javax.swing.JButton unlockBtn;
    public javax.swing.JPanel upperpanel;
    // End of variables declaration//GEN-END:variables

    //private final Timer messageTimer;
//    private final Timer busyIconTimer;
//    private final Icon idleIcon;
//    private final Icon[] busyIcons = new Icon[15];
//    private int busyIconIndex = 0;

    private JDialog aboutBox;

    private String get_Current_ibtn_serial() {
       String ibtn = "";
       if(All_buttons.size()==0){
           ibtn = "12345678abcdef00";
       }
       else{
           int index = Pair_index -1;
           if(index==-1){
               index = 0;
           }
           ibtn = All_buttons.get(index);
       }
       return ibtn;      
    }

    private boolean setStatus(String x, Color clr, boolean b) {
        SimpleAttributeSet textDoc = new SimpleAttributeSet();
        StyleConstants.setForeground(textDoc, clr);
        try {

            statusText.insertString(statusArea1.getDocument().getLength(),x+"\n", textDoc);
        } catch (BadLocationException ex) {
        }
        statusArea1.setCaretPosition(statusArea1.getDocument().getLength());
        return true;
    }


 


//    void dataRecieved(byte[] buffer) {
//        DF_recieved = new DataFrame();
//        System.arraycopy(buffer, 1, DF_recieved.DestAddrs, 0, 2);
//        System.arraycopy(buffer, 3, DF_recieved.Command, 0, 2);
//        System.arraycopy(buffer, 5, DF_recieved.FrameNo, 0, 2);
//        DF_recieved.Length = buffer[7];
//        DF_recieved.Payload = new byte[DF_recieved.Length];
//        System.arraycopy(buffer, 8, DF_recieved.Payload, 0, DF_recieved.Length);
//    }

    //String keyPath = "SYSTEM\\CurrentControlSet\\Enum\\USB\\VID_04D8&PID_000A\\";
    //VID_04D8&PID_000A
    public static String getFriendlyName(String registryKey) {
    if (registryKey == null || registryKey.isEmpty()) {
        throw new IllegalArgumentException("'registryKey' null or empty");
    }
    try {
        int hkey = WinRegistry.HKEY_LOCAL_MACHINE;
        return WinRegistry.readString(hkey, registryKey, "FriendlyName");
    } catch (Exception ex) { 
        System.err.println(ex.getMessage());
        return null;
    }
}

    private boolean SendData(DataFrame frame){
        byte[] data_to_send = getArrayFromPacket(frame);
       // setStatus(Arrays.toString(data_to_send), Color.BLUE, false);
       // return true;
        if(serialPortWrite(data_to_send) == false){
            return false;
        }else{
            return wait_for_resp();
        }
    }
    
    private boolean wait_for_resp(){
        boolean retval = false;
        while (sharedData.dataRecievedFlag==false){
            Thread.yield();
        }
        sharedData.dataRecievedFlag = false;
        DF_recieved = sharedData.DF_recieved;
        int cmd = DF_recieved.Command[0] | DF_recieved.Command[1];
        switch(cmd){
            case 1:
            String addrs = null;
            addrs = String.format("%2X", DF_recieved.DestAddrs[0]).concat(String.format("%2X", DF_recieved.DestAddrs[1]));
            pgmrIDlabel.setText(addrs);            
            retval = true;
            break;
            case 2:  
            All_buttons.clear();
            byte[] ibtn = new byte[8];
            for(int i =0;i<80;i=i+8){
            System.arraycopy(DF_recieved.Payload, i, ibtn, 0, 8);
            String ibutton =join_serial_numbers(ibtn, "");
            All_buttons.add(ibutton);            
            }
            refreshUI();
            retval = true;
            break;
            case 3:
            All_MCUs.clear();
            byte[] MCUs = new byte[4];
            for(int i =0;i<40;i=i+4){
            System.arraycopy(DF_recieved.Payload, i, MCUs, 0, 4);
            String mcu =join_MCU_dev_ID(MCUs, "");
            All_MCUs.add(mcu);            
            }
            refreshUI();
            retval = true;       
            break;
            case 9:
            case 12:
            if(DF_recieved.Payload[0]==0x0
                  ||DF_recieved.Payload[0]==0x1){
                //setStatus("Programmed MCU row", Color.BLUE, false);
                retval = true;
            }else{
                if(cmd==9){
                    setStatus("Failed to program MCU..", Color.RED, false);
                }else{
                    setStatus("Failed to program configuration values..", Color.RED, false);
                }
                retval = false;
            }
            break;
            case 5:
            if(DF_recieved.Payload[0]==0x1){
                setStatus("iButton is locked sucessfully.", Color.BLUE, false);
                retval = true;
            }else{
                setStatus("Failed to lock iButton", Color.RED, false);
                retval = false;
            }
            break;
            case 8:
            if(DF_recieved.Payload[0]==0x3){
                setStatus("iButton is locked.", Color.RED, false);
                retval = false;
            }
                else if(DF_recieved.Payload[0] == 0x0) {
                //setStatus("Programmed the ibutton row", Color.BLUE, false);
                retval = true;
            }
                else if(DF_recieved.Payload[0] == 0x1) {
                setStatus("Failure in communicating with iButton.", Color.RED, false);
            }
                else if(DF_recieved.Payload[0] == 0x3) {
                setStatus("IButton is locked, cannot program.", Color.RED, false);
            }
                else if(DF_recieved.Payload[0] == 0x4) {
                setStatus("iButton read fail.", Color.BLUE, false);
            }
                else if(DF_recieved.Payload[0] == 0x5) {
                setStatus("IButton Write failure.", Color.RED, false);
            }
            break;
            case 7:
            if(DF_recieved.Payload[0]==0x0){
                setStatus("iButton is erased sucessfully.", Color.BLUE, false);
                retval = true;
            }else{
                setStatus("Failed to erase iButton", Color.RED, false);
                retval = false;
            }
            break;
            case 4:
            if(DF_recieved.Payload[0]==0x0){
                setStatus("iButton is unlocked sucessfully.", Color.BLUE, false);
                retval = true;
            }else{
                setStatus("Failed to unlock iButton", Color.RED, false);
                retval = false;
            }
            break;
            case 10:
            if(DF_recieved.Payload[0]==0x0){
                setStatus("Successfully completed operation!", Color.BLUE, false);
            }
                else if(DF_recieved.Payload[0] == 0x1) {
                setStatus("Failure in communicating with iButton.", Color.RED, false);
            }
                else if(DF_recieved.Payload[0] == 0x2) {
                setStatus("Target MCU not detected.", Color.RED, false);
            }
                else if(DF_recieved.Payload[0] == 0x3) {
                setStatus("IButton is locked, cannot program.", Color.RED, false);
            }
                else if(DF_recieved.Payload[0] == 0x4) {
                setStatus("iButton read fail.", Color.BLUE, false);
            }
                else if(DF_recieved.Payload[0] == 0x5) {
                setStatus("IButton Write failure.", Color.RED, false);
            }
                else if(DF_recieved.Payload[0] == 0x6) {
                setStatus("MCU programming failed.", Color.RED, false);
            }
            retval = true;
            break;
        }
        return retval;
    }
    
         private void write_to_header(boolean val){
        try {
            actual_key = getproper(aes_key);
            System.arraycopy(actual_key, 0, aes_first_half, 0, 8);
            System.arraycopy(actual_key, 8, aes_sec_half, 0, 8);
            for(int k=0;k<8;){
                byte temp  =aes_first_half[k];
                aes_first_half[k] = aes_first_half[k+1];
                aes_first_half[k+1] = temp;
                k = k+2;
            }
            File header = new File(System.getProperty("user.home") + "/preceptor_temp.txt");
            if(header.exists()) header.delete();
            header.createNewFile();
            RandomAccessFile header_writer = null;
            header_writer = new RandomAccessFile(header, "rw");
            header_writer.seek(0);
            header_writer.writeBytes("//\n\n\n\n************ DO_NOT_DISTURB_THIS_FILE**************\n\n");
            header_writer.writeBytes("//This ibutton was programmed on "+sharedData.getDateTime()+"\n");
            header_writer.writeBytes("//This file will not be generated if programming to ibutton fails.\n");
            byte[] da = new byte[16];
            Random rand = new Random();
            byte[] ran = new byte[8];
            rand.nextBytes(ran);
            System.arraycopy(ran, 0, da, 0, 8);
            System.arraycopy(aes_sec_half, 0, da, 8, 8);
            String result = join_key(aes_key, ",");
            header_writer.writeBytes("int __attribute__((space(data), address (0x850))) AESKey[8] = {"+result+"};\n");
            //iBtn_serial = get_Current_ibtn_serial().getBytes();
            result = join_serial(get_Current_ibtn_serial(), ",");
            header_writer.writeBytes("unsigned char __attribute__((space(data), address (0x910))) iButtonSerialKey[8] = {"+result+"};\n");
            System.arraycopy(lock_data, 2, i_key_full, 0, 8);
            result = join_password(i_key_full, ",");
            header_writer.writeBytes("unsigned char __attribute__((space(data), address (0x918))) iButtonPasswordFULL[8] = {"+result+"};\n");
           // random.nextBytes(i_key);
            System.arraycopy(lock_data, 10, i_key_read, 0, 8);
            result = join_password(i_key_read, ",");
            header_writer.writeBytes("unsigned char __attribute__((space(data), address (0x920))) iButtonPasswordREAD[8] = {"+result+"};\n");
            if(sharedData.isFactoryUse() || Boolean.parseBoolean(advProp.getProperty("keep.log.header","false"))){
            File dirs = new File(System.getProperty("user.home") + "/Preceptor/all_keys");
            dirs.mkdirs();
            File backup_copy = new File(System.getProperty("user.home") + "/Preceptor/all_keys/"+get_Current_ibtn_serial()+".txt");

            backup_copy.createNewFile();
            byte[] full_data = new byte[(int)header_writer.getFilePointer()];
            header_writer.seek(0);
            header_writer.readFully(full_data);
            RandomAccessFile backup = new RandomAccessFile(backup_copy, "rw");
            backup.seek(backup.length());
            backup.writeBytes(new String(full_data)); 
            backup.close();
            }
            header_writer.close();

        } catch (IOException ex) {
            Exceptions.printStackTrace(ex);
        }
    }
         
         
    private boolean SendPacketRecieveResponse(DataFrame df){
        boolean retval  = false;
        DataFrame sending_packet = df;
        int cmd = sending_packet.Command[0] | sending_packet.Command[1];
        int pointer =0;
        LinkedList data_ibtn = sharedData.getIbtnData();
        byte[] total_data = new byte[51];
        switch(cmd){
            case 1:
            //sending_packet.Command = Command;
            sending_packet.Length = 0;
            sending_packet.Payload = new byte[0];
            retval=SendData(sending_packet);
            break;
            case 5:
            //sending_packet.Command = Command;
            sending_packet.Length = 18;
            retval=SendData(sending_packet);
            break;
            case 2:
            //sending_packet.Command = Command;
            sending_packet.Length = 0;
            sending_packet.Payload = new byte[0];
            retval=SendData(sending_packet);
            break;
            case 4:
            retval=SendData(sending_packet);
            break;
            case 3:
           // sending_packet.Command = Command;
            sending_packet.Length = 0;
            sending_packet.Payload = new byte[0];
            retval=SendData(sending_packet);
            break;
            case 7:
            //sending_packet.Command = Command;
            sending_packet.Length = 2;
            byte[] dataport = new byte[2];
            dataport[0] = 0;
            dataport[1] =1;
            sending_packet.Payload = dataport;
            retval=SendData(sending_packet);
            break;

            case 9:
           // sending_packet.Command = Command;
            boolean first_run = true;
            data_ibtn = sharedData.getBootList();
            for(int m=0;m<data_ibtn.size();m++){

            data_core dc = (data_core) data_ibtn.get(m);
            sending_packet.Length = 53;
            total_data = new byte[53];
            System.arraycopy(dc.first_chunk, 0, total_data, 2, 51);
            total_data[0] = 0;
            total_data[1] = (byte) Pair_index;
            pointer = pointer +64;
            sending_packet.Payload = total_data;
            if(retval||first_run){
            retval=SendData(sending_packet);
            first_run = false;
            }
            else{
                setStatus("Stopped writing to MCU becasue of previous failure.", Color.RED, false);
                return retval;
            }
            total_data = new byte[48];
            sending_packet.Length = 48;
            System.arraycopy(dc.second_chunk, 0, total_data, 0, 48);
            pointer = pointer +64;
            sending_packet.Payload = total_data;
            if(retval){
            retval=SendData(sending_packet);
            }
            else{
                setStatus("Stopped writing to MCU becasue of previous failure.", Color.RED, false);
                return retval;
            }
           }
           df = new DataFrame();
           df.Command = SendCfg;
           df.Length = 16;
           df.Payload = cfg_data;
           //if(retval){
            setStatus("Parsing bootloader configuration values...",Color.BLUE,false);
            retval=SendData(df);
           //}
           //5B 0001 000C 0001 16 0001 0707 0013 87B2 310F 330F 0007 C003 5D
           setStatus("Completed programming bootloader to MCU",Color.BLUE,false);
           break;
           
            case 8:
            first_run = true;
            //sending_packet.Command = Command;
            for(int m=0;m<data_ibtn.size();m++){

            data_core dc = (data_core) data_ibtn.get(m);
            
            sending_packet.Length = 16;
            total_data = new byte[16];            
            System.arraycopy(dc.addrs, 0, total_data, 0, 16);
            sending_packet.Payload = total_data;
            if(first_run || retval){
                retval=SendData(sending_packet);
                first_run = false;
            }else{
                setStatus("Stopped writing to iButton becasue of previous failure.", Color.RED, false);
                return retval;
            }
            
            sending_packet.Length = 52;
            total_data = new byte[52];
            total_data[0] = (byte) ((byte) ((pointer) >> 8) & 0xFF);
            total_data[1] = (byte) ((pointer) & 0xFF);
            total_data[2] = 0;
            total_data[3] = (byte) Pair_index;
            pointer = pointer + 1;
            System.arraycopy(dc.first_chunk, 0, total_data, 4, 48);
            sending_packet.Payload = total_data;
            if(retval){
                retval=SendData(sending_packet);
                first_run = false;
            }else{
                setStatus("Stopped writing to iButton becasue of previous failure.", Color.RED, false);
                return retval;
            }
            total_data = new byte[52];
            sending_packet.Length = 52;
            total_data[0] = (byte) ((byte) ((pointer) >> 8) & 0xFF);
            total_data[1] = (byte) ((pointer) & 0xFF);
            total_data[2] = 0;
            total_data[3] = (byte) Pair_index;
            pointer = pointer + 1;
            System.arraycopy(dc.second_chunk, 0, total_data, 4, 48);
            
            
            sending_packet.Payload = total_data;
            if(retval){
                retval=SendData(sending_packet);
            }else{
                setStatus("Stopped writing to iButton becasue of previous failure.", Color.RED, false);
                return retval;
            }
          }
            total_data = new byte[48];
            sending_packet.Length = 48;
            System.arraycopy(aes_key, 0, total_data, 4, 16);

            total_data[0] = (byte) ((byte) ((0x7f80/64) >> 8) & 0xFF);
            total_data[1] = (byte) ((0x7f80/64) & 0xFF);
            total_data[2] = 0;
            total_data[3] = (byte) Pair_index;
            total_data[20]= (byte) ((byte) ((pointer) >> 8) & 0xFF);
            total_data[21] = (byte) ((pointer) & 0xFF);
            sending_packet.Payload = total_data;
            sending_packet.Command = WritetCredentials;
            retval=SendData(sending_packet);
            setStatus("Completed programming iButton",Color.BLUE,false);
            return true;        
        }       
        return retval;
    }
    
    private byte[] getArrayFromPacket(DataFrame df){
        byte[] array_data  = new byte[df.Length + 9];
        System.arraycopy(df.SOF, 0, array_data, 0, 1);
        System.arraycopy(df.DestAddrs, 0, array_data, 1, 2);
        System.arraycopy(df.Command, 0, array_data, 3, 2);
        System.arraycopy(df.FrameNo, 0, array_data, 5, 2);
        array_data[7] = (byte) ((byte) df.Length & 0xFF);
        //System.arraycopy(df.Length, 0, array_data, 7, 1);
        System.arraycopy(df.Payload, 0, array_data, 8, df.Length);
        System.arraycopy(df.Stop, 0, array_data, df.Length+8, 1);
        return array_data;
    }

    private boolean com_connect(){
        boolean retval = false;
        try {
                sh.disconnect();
                setStatus("Connecting to port for the first time. Please wait...", Color.blue, false);
                if(sh.connect("COM5", 9600)){
                    return true;
                }
        } catch (IOException ex) {
            retval = false;
            setStatus("Port was not found or in use...", Color.red, false);
        }
        return retval;//9538363877
    }

   class ConnectThread implements Runnable
    {

        public void run()
        {
            while(true){
               // is_com_available = Check_Availability();
            }
        }

    }

   class RefreshBtnThread implements Runnable
    {

        public void run()
        {
            
        }

    }
   
   protected synchronized boolean  Check_Availability()
    {
       boolean port_seen = false;
       SerialHelper serial = sh;
       String[] ports = serial.getSerialPorts();
       String com_port = "COM"+getComNumber("SYSTEM\\CurrentControlSet\\Enum\\USB\\VID_04D8&PID_000A\\5&51be3a4&0&2");//5&51be3a4&0&2
            for(String port : ports){
                if(port.equals(com_port)){
                    port_seen = true;
                    this.com_port = com_port;
                    return true;
                }
            }
        com_port = "COM"+getComNumber("SYSTEM\\CurrentControlSet\\Enum\\USB\\VID_04D8&PID_000A\\5&51be3a4&0&1");//5&51be3a4&0&2
           for(String port : ports){
                if(port.equals(com_port)){
                    port_seen = true;
                    this.com_port = com_port;
                    return true;
                }
            }

        return port_seen;
    }
   public static int getComNumber(String registryKey) {
    String friendlyName = getFriendlyName(registryKey);

    if (friendlyName != null && friendlyName.indexOf("COM") >= 0) {
        String substr = friendlyName.substring(friendlyName.indexOf("COM"));
        Matcher matchInt = Pattern.compile("\\d+").matcher(substr);
        if (matchInt.find()) {
            return Integer.parseInt(matchInt.group());
        }
    }
    return -1;
}
    private boolean serialPortWrite(byte[] data){
        boolean retval = false;
        try {
            if(sh.getSerialOutputStream() == null){
               if(com_connect()){
               sh.getSerialOutputStream().write(data);
               retval =  true;
            }
            else retval = false;
            }
            else{
               sh.getSerialOutputStream().write(data);
               retval =  true;
            }
        } catch (IOException ex) {
            setStatus("Port was not found or in use...", Color.red, false);
            retval = false;
            Logger.getLogger(SimpleSerialPort.class.getName()).log(Level.SEVERE, null, ex);
        }
        return retval;
    }
}


/*
 *
 *
 *

 int __attribute__((space(data), address (0x800))) AESKey[8] = {0x0000,0x0000,0x0000,0x0000,0x060E,0x0C08,0x0300,0x0308};
    unsigned char __attribute__((space(data), address (0x810))) iButtonSerialKey[8] = {0x37,0x2E,0xD8,0x10,0x00,0x00,0x00,0x5A};
    unsigned char __attribute__((space(data), address (0x818))) iButtonPasswordFULL[8] = {0x8E,0xFD,0xE5,0x9A,0xF1,0x37,0xF2,0x3D};
unsigned char __attribute__((space(data), address (0x820))) iButtonPasswordREAD[8] = {0x7D,0xB3,0x31,0xF1,0x30,0xCF,0xD9,0x26};

 */