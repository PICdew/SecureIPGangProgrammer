// CDevice.java - Implementation for Accessing Device Database

/*
 ******************************************************************************
 *                                                                            *
 *              (c) Copyright 2010 Microchip Technologies Pvt. Ltd            *
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
 * <dt>Purpose: Device Information Accessing
 * <dd>
 *
 * <dt>Description:
 * <dd> Reads information from the Device Database
 * </dl>
 *
 * @author  Saheed
 * @since   JDK 1.6.21
 */

package secureip;

import com.microchip.crownking.Pair;
import com.microchip.mplab.crownkingx.xPIC;
import secureip.common.SharedData;
import com.microchip.mplab.mdbcore.assemblies.Assembly;
import com.microchip.mplab.mdbcore.memory.MemoryModel;
import com.microchip.mplab.mdbcore.memory.PhysicalMemory;
import com.microchip.mplab.mdbcore.memory.memorytypes.BootMemory;
import com.microchip.mplab.mdbcore.memory.memorytypes.ConfigurationBits;
import com.microchip.mplab.mdbcore.memory.memorytypes.DeviceID;
import com.microchip.mplab.mdbcore.memory.memorytypes.EEData;
import com.microchip.mplab.mdbcore.memory.memorytypes.FlashData;
import com.microchip.mplab.mdbcore.memory.memorytypes.ProgramMemory;
import com.microchip.mplab.mdbcore.memory.memorytypes.UserID;
import com.microchip.mplab.util.observers.Subject;
/**
 *
 * @author i00182
 */
public class CDevice
{
    private xPIC picdevicedb=null;                  //Holds PIC File Info
    private SharedData sharedData;                  //Shared Singleton Class
    private MemoryModel memModel;

    public long auxMemBeginAddr=0;              //Access: Outside of the class
    public long auxMemEndAddr=0;

    private long flashBeginAddress =0;
    private long flashEndAddress =0;

    private long pgmMemBeginAddr = 0;
    private long pgmMemEndAddr = 0;

    private long memoryBeginAddress=0;              //EEMemory Begin Address
    private long memoryEndAddress=0;                //EEMemory End Address

    public long eememoryBeginAddr=0;                //MAGIC ADDRESS USED ON SCREEN
    public long eememoryEndAddr=0;                  //MAGIC ADDRESS USED ON SCREEN

    private long userIDBeginAddr=0;                 //USER ID START
    private long userIDEndAddr=0;                   //END ADDRESS

    private long cfgMemBeginAddress=0;              //Config Memory Begin Address
    private long cfgMemEndAddress=0;                //Config Memory End Address

    private long bootMemBeginAddr=0;
    private long bootMemEndAddr=0;


    private PhysicalMemory programMemory = null;    //Program
    private PhysicalMemory EEMemory=null;           //EPROM Memory
    private PhysicalMemory userID = null;           //User
    private PhysicalMemory configMemory=null;       //Configuration Memory
    private PhysicalMemory flashData = null;        //Flash Memory
    private PhysicalMemory bootMem=null;            //Boot Flash
    private PhysicalMemory deviceID=null;           //Device ID Memory


    /**
    * CDevice Constructor
    *
    * @return     None
    */
    public CDevice()
    {
        sharedData=SharedData.getSingletonObject();
    }

    /**
    * getDeviceInfo  -  Get the DeviceInfo xPIC based on the Device Selected
    *
    * @return       boolean  (True/False) success of the function
    */
    public boolean getDeviceInfo()
    {
        picdevicedb=sharedData.getAssemblySession().GetDevice();
        if(picdevicedb!=null){
            return true;
        }else{
            return false;
        }
    }

    /**
    * getBytesPerWord  -  Get the Byte Per Word
    *
    * @return       int
    */
    public int getBytesPerWord(){
        try{
            long p = picdevicedb.getMemTraits().getCodeWordTraits().getWordSize();
            return (int)p;
        }
        catch(Exception e)
        {
            return -1;
        }
    }

    /**
    * getAddrInc  -  Get the Device Address Inc
    *
    * @return       int
    */
    public int getAddrInc(){
        return (int) picdevicedb.getMemTraits().getCodeWordTraits().getAddrInc();
    }

    /**
    * getProgramMemoryRange  -  Get the Program Memory Range
    *
    * @return       boolean true/false
    */
    public boolean getProgramMemoryRange()
    {
        Pair<Long,Long> ePgmMemRange = picdevicedb.getInstRange();
        if(ePgmMemRange!=null && ePgmMemRange.second!=0)
        {
            pgmMemBeginAddr = ePgmMemRange.first;
            pgmMemEndAddr = ePgmMemRange.second;
//            if(sharedData.getAssemblySession().GetDeviceName().contains("EP"))
//            {
//                pgmMemEndAddr= picdevicedb.getCodeRange().second;
//            }
            return true;
        }
        else{
            return false;
        }
    }



    /**
    * isValidProgramMemoryRange  -  Check Program Memory Range is Valid
    *
    * @param       long start Address
    * @param       long end Address
    *
    * @return       boolean true/false
    */
    public boolean isValidProgramMemoryRange(long sAddr,long eAddr)
    {
        Pair<Long,Long> ePgmMemRange = picdevicedb.getInstRange();
        if(ePgmMemRange!=null && ePgmMemRange.second!=0)
        {
            if(sAddr>=0 && eAddr>0 && sAddr<eAddr )
            {
                if(sAddr>=ePgmMemRange.first && sAddr<ePgmMemRange.second && eAddr>ePgmMemRange.first && eAddr<=ePgmMemRange.second)
                {
                    return true;
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }
        else{
            return false;
        }
    }

    /**
    * isValidEEMemoryRange  -  Check EEMemory Range is Valid
    *
    * @param       long start Address
    * @param       long end Address
    *
    * @return       boolean true/false
    */
    public boolean isValidEEMemoryRange(long sAddr,long eAddr)
    {
        Pair<Long,Long> eEEMemRange = picdevicedb.getMagicEEDataRange();
        if(eEEMemRange!=null && eEEMemRange.second!=0)
        {
            if(sAddr>=0 && eAddr>0 && sAddr<eAddr )
            {
                if(sAddr>=eEEMemRange.first && sAddr<eEEMemRange.second && eAddr>eEEMemRange.first && eAddr<=eEEMemRange.second)
                {
                    return true;
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }
        else{
            return false;
        }
    }

    /**
    * isValidFlashRange  -  Check Flash Range is Valid
    *
    * @param       long start Address
    * @param       long end Address
    *
    * @return       boolean true/false
    */
    public boolean isValidFlashMemoryRange(long sAddr,long eAddr)
    {
        Pair<Long,Long> eEEMemRange = picdevicedb.getFlashDataRange();
        if(eEEMemRange!=null && eEEMemRange.second!=0)
        {
            if(sAddr>=0 && eAddr>0 && sAddr<eAddr )
            {
                if(sAddr>=eEEMemRange.first && sAddr<eEEMemRange.second && eAddr>eEEMemRange.first && eAddr<=eEEMemRange.second)
                {
                    return true;
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }
        else{
            return false;
        }
    }

    /**
    * isValidAuxiliaryRange  -  Check Auxiliary Range is Valid
    *
    * @param       long start Address
    * @param       long end Address
    *
    * @return       boolean true/false
    */
    public boolean isValidAuxiliaryRange(long sAddr,long eAddr)
    {
        Pair<Long,Long> eEEMemRange = picdevicedb.getAuxCodeRange();
        if(eEEMemRange!=null && eEEMemRange.second!=0)
        {
            if(sAddr>=0 && eAddr>0 && sAddr<eAddr )
            {
                if(sAddr>=eEEMemRange.first && sAddr<eEEMemRange.second && eAddr>eEEMemRange.first && eAddr<=eEEMemRange.second)
                {
                    return true;
                }else{
                    return false;
                }
            }else{
                return false;
            }
        }
        else{
            return false;
        }
    }

    /**
    * getPgmTotalMemoryInBytes  -  Get Total Program Memory in Bytes
    *
    * @return       long
    */
    public long getPgmTotalMemoryInBytes()
    {
        long retVal=-1;
        if(getProgramMemoryRange()==true)
        {
            retVal=pgmMemEndAddr-pgmMemBeginAddr;
            if(this.isProgramMemory())
            {
                if(programMemory.GetMemoryModel().WordIncrement()*2 == programMemory.GetMemoryModel().WordSize())
                {
                    retVal=(retVal+pgmMemBeginAddr)*2;
                }
            }
        }
        return retVal;
    }

    public long getPgmMemEndAddrs(){
        long retVal=-1;
        if(getProgramMemoryRange()==true)
        {
            retVal=pgmMemEndAddr;
        }
        return retVal;
    }
    /**
    * getMemory (Physical Memory for the required memory)
    * @Param  Class cMemory
    * @return PhysicalMemory
    */
    public PhysicalMemory getMemory(Class cMemory)
    {
        MemoryModel Mem=null;
        PhysicalMemory physicalmemory = null;
        Assembly assembly=sharedData.getAssemblySession();
        if(assembly != null){
            if((Mem = (MemoryModel)assembly.getLookup().lookup(cMemory)) != null)
            {
                memModel = Mem;
                if(Mem == null) return null;
                else {
                    physicalmemory = Mem.GetPhysicalMemory();
                }
            }
        }
        return physicalmemory;
    }

    /**
    * getProgramMemoryData  -  Get Program Memory in Byte array
    *
    * @return       byte[]
    */
    public byte[] getProgramMemoryData()
    {
        boolean retVal=isProgramMemory();
        int bufferSize=0;
        if(programMemory!=null)
        {
            if(getProgramMemoryRange() == true)
            {
                long memSize = pgmMemEndAddr - pgmMemBeginAddr;
                int offset1 = (int)memSize;
                if(offset1>0){
                   // byte bytes[] = new byte[offset1];
                    if(programMemory.GetMemoryModel().WordIncrement() * 2 == programMemory.GetMemoryModel().WordSize()){
                      bufferSize =  (int) ((offset1 + pgmMemBeginAddr) * 2);
                    }
                 else {
                      bufferSize = (int) (offset1 + pgmMemBeginAddr);
                      if(programMemory.GetMemoryModel().WordIncrement()==4){
                          bufferSize=(int) offset1;
                      }
                 }
                    programMemory.RefreshFromTarget(pgmMemBeginAddr, bufferSize);   //i00182: ENSURE Begin Address
                    byte bytes[]=new byte[bufferSize];
                    if(programMemory.GetMemoryModel().WordIncrement()==4){
                         programMemory.Read(pgmMemBeginAddr, bufferSize, bytes);
                      }else{
                    programMemory.Read(0, bufferSize, bytes);
                    }
                    return bytes;
                }
            }
            return null;

        }
     return null;
    }

    /**
    * getEEBytesPerWord  -  Get the EE Bytes Per Word
    *
    * @return       int (No of Bytes)
    */
    public int getEEBytesPerWord()
    {
      try{
           long p = picdevicedb.getMemTraits().getEEDataWordTraits().getWordSize();
           return (int)p;
       }
      catch(Exception e)
       {
          return -1;
      }
    }

    /**
    * getEEAddrInc  -  Get the EE Address Increment
    *
    * @return       int (Total No of Bytes)
    */
    public int getEEAddrInc()
    {
        return (int) picdevicedb.getMemTraits().getEEDataWordTraits().getAddrInc();//.getCodeWordTraits().getAddrInc();
    }

    /**
    * getEETotalMemoryInBytes  -  Get the Total Memory size
    *
    * @return       long (Total No of Bytes)
    */
    public long getEETotalMemoryInBytes()
    {
        long retVal=-1;
        if(getEPROMMemoryRange()==true){
            retVal=memoryEndAddress-memoryBeginAddress;
        }
        return retVal;
    }

    /**
    * getEPROMMemoryRange  -  Get the Memory Range
    *
    * @return       boolean (true/false)
    */
    public boolean getEPROMMemoryRange()
    {
        Pair<Long, Long> eEDataRange = picdevicedb.getEEDataRange();
        memoryBeginAddress=eEDataRange.first;
        memoryEndAddress=eEDataRange.second;
        return true;
    }

    /**
    * getEEmemoryRange - EE Range with MAGIC (Used for Screen Updates)
    *
    * @return true/false
    */
    public boolean getEEmemoryRange()
    {
        Pair<Long,Long> eMemRange = picdevicedb.getMagicEEDataRange();  //Magic is used for Screen Update
        eememoryBeginAddr= eMemRange.first;
        eememoryEndAddr = eMemRange.second;
        return true;
    }

    /**
    * getEEMemoryData - EPROM Memory Data
    *
    * @return byte[]
    */
    public  byte[] getEEMemoryData()
    {
        byte[] bytes=null;
        if(EEMemory!=null)
        {
            long memDiff=eememoryEndAddr-eememoryBeginAddr;
            int offset=(int)memDiff;   //Work around to get data loss warning
            if(offset>0)
            {
                bytes=new byte[offset];
                EEMemory.RefreshFromTarget(eememoryBeginAddr, offset);
                EEMemory.Read(eememoryBeginAddr, offset, bytes);
            }
        }
        return bytes;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////////////
    /**
    * isEEMemory - Is EPROM Memory Avail
    *
    * @return true/false
    */
    public boolean isEEMemory()
    {
        EEMemory=getMemory(EEData.class);
        if(EEMemory!=null){
            return true;
        }else{
            return false;
        }
    }

    /**
    * isConfigMemory - Check Configuration Memory Exist (THIS IS BAD APPROACH NEED TO USE CROWNING DEVICEDB)
    *
    * @return true/false
    */
    public boolean isConfigMemory()
    {
       try{
        configMemory=getMemory(ConfigurationBits.class);
        }
       catch(Exception v){
           return false;
       }
        if(configMemory!=null){
            return true;
        }else{
            return false;
        }
    }


    /**
    * isProgramMemory - Check Configuration Memory Exist (THIS IS BAD APPROACH NEED TO USE CROWNING DEVICEDB)
    *
    * @return true/false
    */
    public boolean isProgramMemory()
    {
        programMemory = getMemory(ProgramMemory.class);

        if(programMemory!=null){
            return true;
        }else{
            return false;
        }
    }

    /**
    * isDeviceID - Check for Device ID Memory
    *
    * @return true/false
    */
    public boolean isDeviceID()
    {
        deviceID=getMemory(DeviceID.class);
        if(deviceID!=null){
            return true;
        }else{
            return false;
        }
    }

    /**
    * isAuxMem - Check for Aux Memory
    *
    * @return true/false
    */
    public boolean isAuxMem()
    {
        boolean retFlag=false;
        if(picdevicedb!=null)
        {
            retFlag= picdevicedb.hasAuxCode();
        }
        return retFlag;
    }

    /**
    * isUserID - Check User Memory Exist (THIS IS BAD APPROACH NEED TO USE CROWNING DEVICEDB)
    *
    * @return true/false
    */
    public boolean isUserID()
    {
        userID = getMemory(UserID.class);
        if(userID !=null){
            return true;
        }else{
            return false;
        }
    }


    /**
    * isFlashData - Check Flash Memory Exist (THIS IS BAD APPROACH NEED TO USE CROWNING DEVICEDB)
    *
    * @return true/false
    */
    public boolean isFlashData(){
        flashData = getMemory(FlashData.class);
        if(flashData!=null){
            return true;
        }else{
            return false;
        }
    }

    /**
    * getUserIDRange - GetUserIDRange
    *
    * @return true/false
    */
    private boolean getUserIDRange()
    {
        Pair<Long,Long> euserIDRange = picdevicedb.getUserIDRange();
        if(euserIDRange!=null && euserIDRange.second!=0)
        {
            userIDBeginAddr = euserIDRange.first;
            userIDEndAddr = euserIDRange.second;
            return true;
        }
        else{
            return false;
        }
    }

    /**
    * getuserIDTotalBytes - Get Total Bytes
    *
    * @return long
    */
    public long getuserIDTotalBytes()
    {
        long retVal=-1;
        if(getUserIDRange()==true)
        {
            retVal=userIDEndAddr-userIDBeginAddr;
            if(this.isUserID())
            {
                if(userID.GetMemoryModel().WordIncrement() * 2 == userID.GetMemoryModel().WordSize())
                {
                    retVal=(retVal)* 2 ;
                }
            }
        }
        else if(sharedData.getAssemblySession().GetDevice().getFamily().is32Bit())
        {
            retVal = 2;
        }
        return retVal;
    }

    /**
    * getUserIDdata - Get USER ID DATA
    *
    * @return byte[]
    */
    public byte[] getUserIDdata()
    {
        long bufferSize=0;
        if(userID!=null)
        {
            if(getUserIDRange()==true){
                long userIDSize=  (userIDEndAddr - userIDBeginAddr);
                int offset= (int) userIDSize;
                if(offset>0){
                    if(userID.GetMemoryModel().WordIncrement() * 2 == userID.GetMemoryModel().WordSize()){
                      bufferSize =  (int) (offset * 2);
                    }
                    else bufferSize=offset;

                    byte bytes[]=new byte[(int)bufferSize];
                    userID.RefreshFromTarget(userIDBeginAddr, bufferSize);
                    userID.Read(userIDBeginAddr, bufferSize, bytes);
                    return bytes;
                }
            }
        }
        return null;
    }

    /**
    * getConfigMemoryData - Configuration Memory Data
    *
    * @return byte[]
    */
    public  byte[] getConfigMemoryData()
    {
        boolean retVal=isConfigMemory();
        if(configMemory!=null)
        {
            if(getConfigMemoryRange()==true){
                long memDiff=cfgMemEndAddress-cfgMemBeginAddress;
                int offset=(int) ((int) memDiff * picdevicedb.getMemTraits().getConfigFuseWordTraits().getWordSize());  //Work around to get data loss warning
                if(offset>0)
                {
                    byte[] bytes=new byte[(int)offset];                         //was offset
                    int g=configMemory.GetMemoryModel().WordSize();
                    configMemory.RefreshFromTarget(cfgMemBeginAddress, offset); // was offset
                    //if(offset>bytes.length) offset = bytes.length;//temporary until i find wats wrong with midrange - 12f1501 in particular
                    configMemory.Read(cfgMemBeginAddress, offset, bytes);
                    return bytes;
                }
            }
            return null;
        }
        return null;
    }

    /**
    * getConfigMemoryRange  -  Get the Configuration Memory Range
    *
    * @return       boolean (true/false)
    */
    public boolean getConfigMemoryRange()
    {
        Pair<Long, Long> eConfigMemRange = picdevicedb.getDCRRange();
        if(eConfigMemRange!=null){
            cfgMemBeginAddress=eConfigMemRange.first;
            cfgMemEndAddress=eConfigMemRange.second;
            return true;
        }else{
            return false;
        }
    }

    /**
    * getConfigBytesPerWord  -  Get the Configuration Byte Word
    *
    * @return       boolean (true/false)
    */
    public int getConfigBytesPerWord(){
       try{
           long p = picdevicedb.getMemTraits().getEEDataWordTraits().getWordSize();
           return (int)p;
       }
      catch(Exception e)
       {
          return -1;
      }
    }

    /**
    * getUSerIDAdd  -  Get the USer ID Address
    *
    * @return       long
    */
    public long getUSerIDAdd()
    {
        return picdevicedb.getUserIDRange().first;
    }

    /**
    * getFlashDataRange  -  Get the Flash Memory Data Range
    *
    * @return       boolean true/false
    */
    public boolean getFlashDataRange()
    {
        Pair<Long,Long> eFlashData = picdevicedb.getFlashDataRange();
        flashBeginAddress = eFlashData.first;
        flashEndAddress = eFlashData.second;
        return true;
    }

    /**
   * getFlashMemoryData  -  Get the Flash Memory Data array
    *
    * @return      byte[]
    */
    public byte[] getFlashMemoryData()
    {
        boolean retVal=isFlashData();
        if(flashData!=null)
        {
            byte[] bytes = null;
            if(getFlashDataRange()==true)
            {
                long memSize = flashEndAddress-flashBeginAddress;
                int offset = (int)memSize;
                if(offset>0)
                {
                    bytes = new byte[offset];
                    flashData.RefreshFromTarget(flashBeginAddress,offset);
                    flashData.Read(flashBeginAddress, offset, bytes);
                }
            }
            return bytes;
        }
        return null;
    }

    /**
    * getBootMemRange  -  Get the Boot Flash Range
    *
    * @return      boolean
    */
    public boolean getBootMemRange()
    {
        Pair<Long,Long> eBootMemRange = picdevicedb.getBootConfigRange();
        if(eBootMemRange!=null && eBootMemRange.second!=0){
            bootMemBeginAddr=eBootMemRange.first;
            bootMemEndAddr=eBootMemRange.second;
            return true;
        }
         else{
            return false;
        }
    }

    /**
    * getBootMemInBytes  -  Get the Boot Flash Memory Data array
    *
    * @return      long
    */
    public long getBootMemInBytes()
    {
         long retVal=-1;
        if(getBootMemRange()==true){
            retVal=bootMemEndAddr-bootMemBeginAddr;
            if(this.isBootMem()){
            if(bootMem.GetMemoryModel().WordIncrement()*2 == bootMem.GetMemoryModel().WordSize()){
                retVal=(retVal+bootMemBeginAddr)*2;
            }
        }}
        return retVal;
    }

    /**
    * isBootMem  -  Is Boot Flash Memory exists
    *
    * @return      boolean
    */
    public boolean isBootMem()
    {
        bootMem = getMemory(BootMemory.class);
         if(bootMem!=null){
            return true;
        }else{
            return false;
        }
    }

    /**
    * getBootMemData  -  Get Boot Memory Data
    *
    * @return      byte[]
    */
    public byte[] getBootMemData()
    {

        byte[] bytes=null;
        if(bootMem!=null)
        {
            getBootMemRange();
            long memDiff=bootMemEndAddr-bootMemBeginAddr;
            int offset=(int)memDiff;   //Work around to get data loss warning
            if(offset>0)
            {
                bytes=new byte[offset];
                bootMem.RefreshFromTarget(bootMemBeginAddr, offset);
                bootMem.Read(bootMemBeginAddr, offset, bytes);
            }
        }
        return bytes;
    }

    /**
    * getAuxMemRange  -  Get Auxilary Memory Range
    *
    * @return      long size
    */
    public boolean getAuxMemRange()
    {
        Pair<Long,Long> auxMemRange = picdevicedb.getAuxCodeRange();
        if(auxMemRange!=null && auxMemRange.second!=0)
        {
            auxMemBeginAddr = picdevicedb.getAuxCodeRange().first;
            auxMemEndAddr = picdevicedb.getInstRange().second;
            return true;
        }
        else{
            return false;
        }
    }

    /**
    * getAuxMemTotalMemoryInBytes  -  Get Auxilary Memory Total Byte size
    *
    * @return      long size
    */
    public long getAuxMemTotalMemoryInBytes()
    {
          long retVal=-1;
            if(getAuxMemRange()==true){
                retVal=auxMemEndAddr-auxMemBeginAddr;
         }
            return retVal;
     }

    /**
    * getAuxMemData  -  Get Auxilary Memory Data
    *
    * @return      byte[]
    */
    public byte[] getAuxMemData()
    {
         byte[] bytes=null;
        if(programMemory!=null)
        {
           // long memDiff=picdevicedb.getAuxCodeRange().second-picdevicedb.getAuxCodeRange().first;
            long memDiff=auxMemEndAddr-auxMemBeginAddr;

            int offset=(int)memDiff;   //Work around to get data loss warning
            if(offset>0)
            {
                bytes=new byte[offset*2];
                programMemory.RefreshFromTarget(auxMemBeginAddr, offset*2);
                programMemory.Read(auxMemBeginAddr, offset*2, bytes);
            }
        }
        return bytes;
    }

 
    /**
    * getXPICDeviceInfo  -  Get the device info for selected device
    *
    * @return  xPIC
    */
    public xPIC getXPICDeviceInfo()
    {
        return picdevicedb;
    }


    /**
    * getMemModel  -  Get the Memory Model
    *
    * @return  MemoryModel
    */
    public MemoryModel getMemModel(){
        return memModel;
    }

    /**
    * getConfigStart  -  Get the Configuration Start
    *
    * @return  long
    */
    public long getConfigStart()
    {
        return cfgMemBeginAddress;
    }

    /**
    * getConfigSize  -  Get the Config Size
    *
    * @return  long
    */
    public long getConfigSize()
    {
        getConfigMemoryRange();
        return cfgMemEndAddress-cfgMemBeginAddress;
    }


//    public void clearAll() {
//        if(isProgramMemory()) programMemory.Clear();
//        if(isEEMemory()) EEMemory.Clear();
//        if(isConfigMemory())configMemory.Clear();
//        if(isFlashData()) flashData.Clear();
//        if(isUserID()) userID.Clear();
//        if(isBootMem()) bootMem.Clear();
//        IPENotifier.getIPENotifierController().setMemoryChangedNotification();
//    }
//
//    public void setProgramMemory(PhysicalMemory pm) {
//        programMemory = pm;
//        ((Subject)programMemory).Notify(new MemoryEvent(MemoryEvent.EVENTS.MEMORY_CHANGED));
//
//    }
//
//    public void setEEMemory(PhysicalMemory eem){
//        EEMemory = eem;
//        ((Subject)EEMemory).Notify(new MemoryEvent(MemoryEvent.EVENTS.MEMORY_CHANGED));
//    }
//
//    public void setBootMem(PhysicalMemory boot) {
//        bootMem = boot;
//        ((Subject)bootMem).Notify(new MemoryEvent(MemoryEvent.EVENTS.MEMORY_CHANGED));
//    }
//
//    public void setIDMem(PhysicalMemory IDMem) {
//        userID=IDMem;
//        ((Subject)userID).Notify(new MemoryEvent(MemoryEvent.EVENTS.MEMORY_CHANGED));
//    }
//
//    public void setConfigMem(PhysicalMemory configMem) {
//        configMemory=configMem;
//        ((Subject)configMemory).Notify(new MemoryEvent(MemoryEvent.EVENTS.MEMORY_CHANGED));
//    }
//
//    public void setFlashMemory(PhysicalMemory fd){
//        flashData = fd;
//       ((Subject)flashData).Notify(new MemoryEvent(MemoryEvent.EVENTS.MEMORY_CHANGED));
//    }
}
