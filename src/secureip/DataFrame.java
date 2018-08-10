/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package secureip;

/**
 *
 * @author Avi
 */
   public class DataFrame{
        public byte[] SOF  = "[".getBytes();
        public byte[] DestAddrs  = new byte[2];
        public byte[] Command = new byte[2];
        public byte[] FrameNo = new byte[2];
        public int Length;
        public byte[] Payload;
        public byte[] Stop = "]".getBytes();
        public DataFrame(){

        }
    }
