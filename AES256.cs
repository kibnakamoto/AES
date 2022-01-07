using System;

namespace AES
{
    public class OPERATIONS
    {
        public byte InvCipher(byte[] input, byte[] output, byte[] W)
        {
            if(input.Length != 128 || output.Length != 128 || W.Length != 480) {
                throw new ArgumentException("length doesn't match");
            }
            // byte state[,]; // = new byte[4,4] {input};
            // state = input, How? 1 dimentional array to 2 dimentional array
        return 0;
        }
        /*
        (byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
        
        begin
        
        byte state[4,Nb]
        
        state = in
        
        AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4
        
        for round = Nr-1 step -1 downto 1
        
        InvShiftRows(state) // See Sec. 5.3.1
        
        InvSubBytes(state) // See Sec. 5.3.2
        
        AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
        
        InvMixColumns(state) // See Sec. 5.3.3
        
        end for
        
        InvShiftRows(state)
        
        InvSubBytes(state)
        
        AddRoundKey(state, w[0, Nb-1])
        
        out = state
        
        end
         
        */
    }
    
    public class AES256
    {
        public string Encrypt(string input)
        {
            OPERATIONS Oper = new OPERATIONS();
            
            // byte[,] InByte = byte[4,4];
            // return null until there is value to return
            return null;
        }
    }
}
