using AES;
using System;

public class Out
{
    public static void Main(string[] args)
    {
        AES256 Aes256 = new AES256();
        // Console.WriteLine("input what to encrypt using the aes256 encryption method");
        // Console.Write("input: ");
        // string input = Console.ReadLine();
        string input = "asdfghjklqwertyu"; // 00112233445566778899aabbccddeeff
        System.Console.WriteLine("\n" + Aes256.Encrypt(input));
        byte[] key = new byte[4*8] {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                                     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                                     0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                                     0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
        
        // System.Console.WriteLine("\n" + Aes256
        //                          .Decrypt("8ea2b7ca516745bfeafc49904b496089",
        //                                 key));
    }
}
