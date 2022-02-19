using AES;
using System;

public class Out
{
    public static void Main(string[] args)
    {
        /* works no matter the length of input */
        
        AES256 Aes256 = new AES256();
        OPS_AES Operation = new OPS_AES();
        
        Console.WriteLine("input what to encrypt using the aes256 encryption method");
        Console.Write("\ninput: ");
        string input = Console.ReadLine();
        
        // key changes based on input
        byte[] key = new byte[32];
        key = Operation.CreateKey(input, 32); // uses salt
        
        System.Console.WriteLine("\nEnc_AES256: " + Aes256.Encrypt(input, key));
    }
}
