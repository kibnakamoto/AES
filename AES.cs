/*
 * All AES symmetric encryption/decryption algorithms
 * Copyright (C) 2022 Taha Canturk
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *    You should have received a copy of the GNU General Public License
 *    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


/*
*  Author: Taha Canturk
*   Github: Kibnakamoto
*    Repisotory: AES
*     Start Date: Jan 7, 2022
*       Finalized: Feb 17, 2022
*/

using System;
using System.Text;
using System.Security.Cryptography; // for generating input based key
using System.Linq; // for decryption function. Hex string to bytearray

namespace AES
{
    // operations of aes 256, 128, 192
    public class OPS_AES
    {
        /* ENCRYPTION/DECRYPTION */
        
        // Rijndael's S-box as a 2-dimentional matrix
        private static readonly byte[,] Sbox = new byte[16,16] {
            {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 
            0x2B, 0xFE, 0xD7, 0xAB, 0x76}, {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59,
            0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0}, {0xB7,
            0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 
            0x71, 0xD8, 0x31, 0x15}, {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05,
            0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75}, {0x09, 0x83,
            0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29,
            0xE3, 0x2F, 0x84}, {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
            0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF}, {0xD0, 0xEF, 0xAA,
            0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
            0x9F, 0xA8}, {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
            0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2}, {0xCD, 0x0C, 0x13, 0xEC,
            0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19,
            0x73}, {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE,
            0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB}, {0xE0, 0x32, 0x3A, 0x0A, 0x49,
            0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
            {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4,
            0xEA, 0x65, 0x7A, 0xAE, 0x08}, {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6,
            0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A}, {0x70,
            0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
            0x86, 0xC1, 0x1D, 0x9E}, {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E,
            0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF}, {0x8C, 0xA1,
            0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 
            0x54, 0xBB, 0x16}};
        
        // Rijndael's inverse S-box as a 2-dimentional matrix
        private static readonly byte[,] InvSBox = new byte[16,16] {
            {0x52, 0x9, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0xb,
            0x42, 0xfa, 0xc3, 0x4e}, {0x8, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab,
            0x0, 0x8c, 0xbc, 0xd3, 0xa, 0xf7, 0xe4, 0x58, 0x5, 0xb8, 0xb3, 0x45,
            0x6}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0xf, 0x2, 0xc1, 0xaf, 
            0xbd, 0x3, 0x1, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f,
            0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
            {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37,
            0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29,
            0xc5, 0x89, 0x6f, 0xb7, 0x62, 0xe, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc,
            0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe,
            0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x7, 0xc7,
            0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51,
            0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0xd, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 
            0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
            0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x4,
            0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21,
            0xc, 0x7d}};
        
        // round constant array
        public static readonly byte[] Rcon = new byte[11] {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
            0x20, 0x40, 0x80, 0x1b, 0x36};
        
        // salt for generating key. Salt creates a safer key
        private static readonly byte[] Salt = new byte[] {
            0xf4, 0x32, 0x10, 0x43, 0xff, 0x5a, 0xae, 0x56};
        
        // generate key with salt
        public byte[] CreateKey(string input, int keyBytes)
        {
            const int Iterations = 300;
            var keyGenerator = new Rfc2898DeriveBytes(input, Salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }
        
        // bitwise circular-left-shift operator for rotating by 8 bits.
        public uint RotWord(uint x)
        {
            return (uint)( (x << 8)|(x>>32-8) );
        }
        
        // Galois Field Multipication 2^8
        public byte GF256(byte x, byte y)
        {
            // implemented with bitmasking for efficient cryptographical use.
            byte p=0;
            for(int c=0;c<8;c++) {
                p ^= (byte)(-(y&1)&x);
                x = (byte)((x<<1) ^ (0x11b & -((x>>7)&1)));
                y >>= 1;
            }
            return p;
        }
        
        /* ENCRYPTION */
        
        public byte[,] SubBytes(byte[,] b, byte Nb)
        {
            /* seperates hex byte into 2 4 bits and use them as index to
               sub in values as index of s-box */
            for(int r=0;r<4;r++) {
                for(int c=0;c<Nb;c++) {
                    byte low = (byte)(b[r,c] & 0x0F);
                    byte high = (byte)(b[r,c]>>4);
                    b[r,c] = Sbox[high, low];
                }
            }
            return b;
        }
        
        public byte[,] ShiftRows(byte[,] S, byte Nb)
        {
            // to stop values from overriding, use 2 arrays with the same values
            byte[,] Spre = new byte[4,4];
            for(int r=1;r<4;r++) {
                for(int c=0;c<Nb;c++){
                    Spre[r,c] = S[r,c];
                }
            }
            
            // shifting rows. First row is not changed
            for(int r=1;r<4;r++) {
                for(int c=0;c<Nb;c++) {
                    S[r,c] = Spre[r, (r+c)%4];
                }
            }
            
            return S;
        }
        
        public byte[,] MixColumns(byte[,] S, byte Nb)
        {
                // lambda function xtime
                Func<byte, byte> xtime = delegate (byte x)
                {
                    return (byte)((x<<1) ^ (((x>>7) & 1) * 0x1b));
                };
                
                for(int c=0;c<Nb;c++)
                {
                    // create temporary array to stop overriding
                    byte[] tmpS = new byte[4] {S[0,c], S[1,c], S[2,c], S[3,c]};

                    // MixColumns operation from AES proposal
                    byte Tmp = (byte)(tmpS[0] ^ tmpS[1] ^ tmpS[2] ^ tmpS[3]);
                    byte Tm =  (byte)(tmpS[0] ^ tmpS[1]) ; Tm = xtime(Tm); 
                    S[0,c] ^=  (byte)(Tm ^ Tmp);
                    Tm =       (byte)(tmpS[1] ^ tmpS[2]) ; Tm = xtime(Tm); 
                    S[1,c] ^=  (byte)(Tm ^ Tmp);
                    Tm =       (byte)(tmpS[2] ^ tmpS[3]) ; Tm = xtime(Tm);
                    S[2,c] ^=  (byte)(Tm ^ Tmp);
                    Tm =       (byte)(tmpS[3] ^ tmpS[0]) ; Tm = xtime(Tm);
                    S[3,c] ^=  (byte)(Tm ^ Tmp);
                }
            return S;
        }
        
        public uint SubWord(uint x)
        {
            // lambda function subInt
            Func<uint, uint> subInt = default(Func<uint, uint>);
            subInt = y => Sbox[(y&0xff)>>4, y&0x0F];
            
            return (subInt(x>>24)<<24) | (subInt((x>>16)&0xff)<<16) |
                       (subInt((x>>8)&0xff)<<8) | (subInt(x&0xff));
        }
        
        public byte[,] AddRoundKey(byte[,] state, uint[] w, int round)
        {
            // fix function. not working
            for(int c=0;c<4;c++) {
                uint Windex = w[round*4+c];
                state[0,c] ^= (byte)(Windex >> 24);
                state[1,c] ^= (byte)(Windex >> 16);
                state[2,c] ^= (byte)(Windex >> 8);
                state[3,c] ^= (byte)(Windex);
            }
            return state;
        }
        
        /* DECRYPTION */
        
        public byte[,] InvSubBytes(byte[,] b)
        {
            for(int r=0;r<4;r++) {
                for(int c=0;c<4;c++) {
                    byte low = (byte)(b[r,c] & 0x0F);
                    byte high = (byte)(b[r,c]>>4);
                    b[r,c] = InvSBox[high, low];
                }
            }
            return b;
        }
        
        public byte[,] InvShiftRows(byte[,] S)
        {
            // to stop values from overriding, use 2 arrays with the same values
            byte[,] InvSpre = new byte[4,4];
            for(int r=1;r<4;r++) {
                for(int c=0;c<4;c++)
                    InvSpre[r,c] = S[r,c];
            }
            
            // shifting rows. First row is not changed
            for(int r=1;r<4;r++) {
                for(int c=0;c<4;c++) {
                    S[r,(c+r)%4] = InvSpre[r,c];
                }
            }
            return S;
        }
        
        public byte[,] InvMixColumns(byte[,] S)
        {
            byte[] SMixArr = new byte[4] {0x0e, 0x0b, 0x0d, 0x09};
            for(int c=0;c<4;c++) {
                // to stop matrix from overriding, use temporrary array
                byte[] tmpS = new byte[4] {S[0,c], S[1,c], S[2,c], S[3,c]};
                S[0,c] = (byte)(GF256(tmpS[0], SMixArr[0]) ^
                                GF256(tmpS[1], SMixArr[1]) ^
                                GF256(tmpS[2], SMixArr[2]) ^
                                GF256(tmpS[3], SMixArr[3]));
                S[1,c] = (byte)(GF256(tmpS[0], SMixArr[3]) ^
                                GF256(tmpS[1], SMixArr[0]) ^
                                GF256(tmpS[2], SMixArr[1]) ^
                                GF256(tmpS[3], SMixArr[2]));
                S[2,c] = (byte)(GF256(tmpS[0], SMixArr[2]) ^
                                GF256(tmpS[1], SMixArr[3]) ^
                                GF256(tmpS[2], SMixArr[0]) ^
                                GF256(tmpS[3], SMixArr[1]));
                S[3,c] = (byte)(GF256(tmpS[0], SMixArr[1]) ^
                                GF256(tmpS[1], SMixArr[2]) ^ 
                                GF256(tmpS[2], SMixArr[3]) ^
                                GF256(tmpS[3], SMixArr[0]));
            }
            return S;
        }
                /* KeyExpansion debugged. */
        // KeyExpansion
        protected uint[] KeyExpansion(byte[] key, uint[] w, byte Nb, byte Nk, 
                                      byte Nr)
        {
            OPS_AES Operation = new OPS_AES();
            uint temp;
            int i=0;
            do {
                w[i] = (uint)((key[4*i]<<24) | (key[4*i+1]<<16) |
                             (key[4*i+2]<<8) | key[4*i+3]);
                i++;
            } while(i < Nk);
            i=Nk;
            
            // Rcon values. initialize twice so it doesn't override
            int[] rcon = new int[11];
            for(int c=1;c<11;c++)
            {
                rcon[c] = (byte)OPS_AES.Rcon[c] << 24;
            }
            
            while (i < Nb*(Nr+1)) {
                temp = w[i-1];
                if(i%Nk == 0) { // this part is wrong since 16 mod Nk = 0
                    temp = Operation.SubWord(Operation.RotWord(temp)) ^ (uint)rcon[i/Nk];
                }
                else if(Nk>6 && i%Nk == 4) {
                    temp = Operation.SubWord(temp);
                }
                w[i] = temp ^ w[i-Nk];
                i++;
            }
            
            return w;
        }
        
        protected byte[] Cipher(byte[] Input, byte[] output, uint[] w, byte Nb,
                                byte Nk, byte Nr)
        {
            // declare state matrix
            byte[,] state = new byte[4, Nb];
            
            // put 1-dimentional array values to a 2-dimentional matrix
            for(int r=0;r<4;r++) {
                for(int c=0;c<Nb;c++) {
                    state[r,c] = Input[r+4*c];
                }
            }
            
            // call functions to manipulate state matrix
            AddRoundKey(state, w, 0);
            for(int round=1;round<Nr;round++) {
                SubBytes(state, Nb);
                ShiftRows(state, Nb);
                MixColumns(state, Nb);
                AddRoundKey(state, w, round);
            }
            SubBytes(state, Nb);
            ShiftRows(state, Nb);
            AddRoundKey(state, w, Nr);
            
            // copy state array to output
            for(int r=0;r<4;r++) {
                for(int c=0;c<Nb;c++)
                    output[r+4*c] = state[r,c];
            }
            return output;
        }
        
        public string Encrypt(string UserIn, byte[] key, byte Nb, byte Nk,
                              byte Nr)
        {
            // declare arrays.
            byte[] Input = new byte[4*Nb];
            byte[] output = new byte[4*Nb];
            uint[] w = new uint[Nb*(Nr+1)]; // key schedule

            // append user input to 1-dimentional array
            Input = System.Text.Encoding.ASCII.GetBytes(UserIn);
            
            // call KeyExpansion and Cipher function
            KeyExpansion(key, w, Nb, Nk, Nr);
            Cipher(Input, output, w, Nb, Nk, Nr);
            
            // convert output array to hex string
            StringBuilder hex = new StringBuilder(output.Length<<1);
            foreach(byte c in output)
            {
                   hex.AppendFormat("{0:x2}", c);
            }
            return hex.ToString();
        }
        
        protected byte[] InvCipher(byte[] Input, byte[] output, uint[] w, 
                                   byte Nb, byte Nk, byte Nr)
        {
            byte[,] state = new byte[4,Nb];
            for(int r=0;r<4;r++) {
                for(int c=0;c<Nb;c++) {
                    state[r,c] = Input[r+4*c];
                }
            }
            AddRoundKey(state, w, Nr);
            for(int round=Nr-1;round>0;round--) {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, w, round);
                InvMixColumns(state);
            }
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, w, 0);
            
            for(int r=0;r<4;r++) {
                for(int c=0;c<Nb;c++)
                    output[r+4*c] = state[r,c];
            }
            return output;
        }
        
        public string Decrypt(string UserIn, byte[] key, byte Nb, byte Nk, byte Nr)
        {
            // declare single-dimentional arrays
            byte[] output = new byte[4*Nb];
            byte[] Input = new byte[4*Nb];
            uint[] w = new uint[Nb*(Nr+1)];
            Input = Enumerable.Range(0, UserIn.Length>>1)
                    .Select(x=>Convert.ToByte(UserIn.Substring(x<<1, 2), 16)) 
                    .ToArray(); // converts string hex to bytearray
            
            // create key schedule using given key and de-Cipher
            KeyExpansion(key, w, Nb, Nk, Nr);
            InvCipher(Input, output, w, Nb, Nk, Nr);
            return System.Text.Encoding.Default.GetString(output);
        }
        public string MultiBlockProcessEnc(string UserIn, byte[] key, byte Nb,
                                           byte Nk, byte Nr)
        {
            // pads message so that length is a multiple of 16
            int msgLen = UserIn.Length + 16-(UserIn.Length)%16;
            if(UserIn.Length%16 == 0) {
                msgLen -=16;
            }
            UserIn = UserIn.PadRight(msgLen, '0');
            string[] newInput = new string[msgLen/16];
            int k=-1;
            string FVal = "";
            // seperate message into blocks of 16
            for(int c=0;c<msgLen;c+=16) {
                k++;
                if(k < msgLen/16) {
                    newInput[k] = UserIn.Substring(c, 16);
                }
            }
            for(int c=0;c<msgLen/16;c++) {
                FVal += Encrypt(newInput[c], key, Nb, Nk, Nr);
            }
            return FVal;
        }
        public string MultiBlockProcessDec(string UserIn, byte[] key, byte Nb,
                                   byte Nk, byte Nr)
        {
            string[] newInput = new string[UserIn.Length/32];
            int k=-1;
            string FVal = "";
            
            // seperate message into blocks of 32 bytes
            for(int c=0;c<UserIn.Length;c+=32) {
                k++;
                if(k < UserIn.Length/32) {
                    newInput[k] = UserIn.Substring(c, 32);
                }
            }
            for(int c=0;c<UserIn.Length/32;c++) {
                FVal += Decrypt(newInput[c], key, Nb, Nk, Nr);
            }
            
            return FVal;
        }
    }
    
    public class AES128
    {
        // AES algorithm size for AES128
        protected const byte Nb = 4;
        protected const byte Nr = 10;
        protected const byte Nk = 4;
        public string Encrypt(string UserIn, byte[] key)
        {
            OPS_AES Operation = new OPS_AES();
            return Operation.MultiBlockProcessEnc(UserIn, key, Nb, Nk, Nr);
        }
        public string Decrypt(string UserIn, byte[] key)
        {
            OPS_AES Operation = new OPS_AES();
            return Operation.MultiBlockProcessDec(UserIn, key, Nb, Nk, Nr);
        }
    }

    public class AES192
    {
        // AES algorithm size for AES192
        protected const byte Nb = 4;
        protected const byte Nr = 12;
        protected const byte Nk = 6;
        public string Encrypt(string UserIn, byte[] key)
        {
            OPS_AES Operation = new OPS_AES();
            return Operation.MultiBlockProcessEnc(UserIn, key, Nb, Nk, Nr);
        }
        public string Decrypt(string UserIn, byte[] key)
        {
            OPS_AES Operation = new OPS_AES();
            return Operation.MultiBlockProcessDec(UserIn, key, Nb, Nk, Nr);
        }
    }

    public class AES256
    {
        // AES algorithm size for AES256
        protected const byte Nb = 4;
        protected const byte Nr = 14;
        protected const byte Nk = 8;
        public string Encrypt(string UserIn, byte[] key)
        {
            OPS_AES Operation = new OPS_AES();
            return Operation.MultiBlockProcessEnc(UserIn, key, Nb, Nk, Nr);
        }
        public string Decrypt(string UserIn, byte[] key)
        {
            OPS_AES Operation = new OPS_AES();
            return Operation.MultiBlockProcessDec(UserIn, key, Nb, Nk, Nr);
        }
    }
}
