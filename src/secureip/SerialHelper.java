package secureip;
import java.util.ArrayList;
import javax.swing.JOptionPane;

import gnu.io.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;
import org.openide.util.Exceptions;
import secureip.common.SharedData;

public class SerialHelper implements Runnable , SerialPortEventListener {

    private SerialPort serialPort;
    private static OutputStream outStream;
    private static InputStream inStream;
    private SharedData shareddata = SharedData.getSingletonObject();
    private byte[] buffer = new byte[1024];
    private String comPort;
    final static int SPACE_ASCII = 32;
    final static int DASH_ASCII = 45;
    final static int NEW_LINE_ASCII = 10;
    Thread readThread;
    

    public String[] getSerialPorts() {
        Enumeration ports = CommPortIdentifier.getPortIdentifiers();
        ArrayList portList = new ArrayList();
        String portArray[] = null;
        while (ports.hasMoreElements()) {
            CommPortIdentifier port = (CommPortIdentifier) ports.nextElement();
            if (port.getPortType() == CommPortIdentifier.PORT_SERIAL) {
                portList.add(port.getName());
            }
        }
        portArray = (String[]) portList.toArray(new String[0]);
        return portArray;
    }

    public boolean connect(String portName, int baudRate) throws IOException {
        boolean ret = false;
        this.comPort = portName;
        try {
            // Obtain a CommPortIdentifier object for the port you want to open
            CommPortIdentifier portId = CommPortIdentifier.getPortIdentifier(portName);

            // Get the port's ownership
            if (portId != null) {
                serialPort = (SerialPort) portId.open(this.getClass().getName(), 5000);
            }

            // Open the input and output streams for the connection.
            // If they won't open, close the port before throwing an
            // exception.
            if (serialPort != null) {
                outStream = serialPort.getOutputStream();
                inStream = serialPort.getInputStream();
            }
            try {
                serialPort.addEventListener(this);

            } catch (Exception ex) {
                System.err.println("Excpetion caught:");
            }

            serialPort.notifyOnDataAvailable(true);
            // Set the parameters of the connection.
            setSerialPortParameters(baudRate);
            readThread = new Thread(this);
            readThread.start();
            // successful
            ret = true;

        } catch (NoSuchPortException e) {
            throw new IOException(e.getMessage());
        } catch (PortInUseException e) {
            System.out.println(portName + " in use");
            throw new IOException(e.getMessage());
        } catch (IOException e) {
            serialPort.close();
            throw e;
        }
        return ret;
    }

    public static InputStream getSerialInputStream() {
        return inStream;
    }

    public static OutputStream getSerialOutputStream() {
        return outStream;
    }

    protected void setSerialPortParameters(int baudRate) throws IOException {

        try {
            // Set serial port to 9600-8N1
            if (serialPort != null) {
                serialPort.setSerialPortParams(baudRate, SerialPort.DATABITS_8, SerialPort.STOPBITS_1, SerialPort.PARITY_NONE);
              //  serialPort.setFlowControlMode(SerialPort.);
                serialPort.setRTS(true);
                serialPort.setDTR(true);
                serialPort.setFlowControlMode(SerialPort.FLOWCONTROL_RTSCTS_IN);
            } else {
                JOptionPane.showMessageDialog(null, "Serial port not intialized", "Serial Port Parameters", JOptionPane.ERROR_MESSAGE);
                System.exit(0);
            }

        } catch (UnsupportedCommOperationException ex) {
            throw new IOException("Unsupported serial port parameter");
        }
    }

    public void disconnect() {
        if (serialPort != null) {
            try {
                serialPort.removeEventListener();
                serialPort.close();
                inStream.close();
                outStream.close();
                
            } catch (IOException ex) {
                // don't care
            }
            // Close the port.
            serialPort = null;
        }
    }

    public String getComPort() {
        return comPort;
    }

    public void writeData(byte[] data)
    {
     try
     {
         outStream.write(data);
     }
     catch(Exception ex)
     {
         System.err.println("Exception in writedata");
     }
    }
        public void writeData(byte data)
    {
     try
     {
         outStream.write(data);
         outStream.flush();
     }
     catch(Exception ex)
     {
         System.err.println("Exception in writedata");
     }
    }
        
        public byte read()
        {
            byte ret= 0;
          int data;
          try
          {
          data= inStream.read();
          ret =(byte)data;
          }
          catch(Exception ex)
          {
             
          }
          return ret;
        }
        
         public void run() {
            }
    //what happens when data is received
    //pre: serial event is triggered
    //post: processing on the data it reads
    public void serialEvent(SerialPortEvent evt) {
        int data;
        switch(evt.getEventType())
        {
        case SerialPortEvent.OUTPUT_BUFFER_EMPTY:
        break;
        case SerialPortEvent.DATA_AVAILABLE:
            try
            {   buffer = new byte[1024];
                int len = 0;
                while ( ( data = inStream.read()) > -1 )
                {
                    if ( data == ']' ) {
                        buffer[len++] = (byte) data;
                        break;
                    }
                    buffer[len++] = (byte) data;
                }
                shareddata.dataRecieved(buffer);
                shareddata.dataRecievedFlag = true;
                System.out.print(new String(buffer,0,len));
                break;
            }
            catch ( IOException e )
            {
                e.printStackTrace();
                System.exit(-1);
            }   
              break;
        }
    }
}
