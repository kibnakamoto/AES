using AES;
using System;

public class Out
{
    public static void Main(string[] args)
    {
        AES256 Aes256 = new AES256();
        OPS_AES Operation = new OPS_AES();
        
        // Console.WriteLine("input what to encrypt using the aes256 encryption method");
        // Console.Write("\ninput: ");
        // string input = Console.ReadLine();
        byte[] key = new byte[32];
        string input = "asdfghjklqwertyu";

        // key changes based on input
        key = Operation.CreateKey(input, 32); // uses salt
        // foreach(char c in key) {
        //     Console.Write(c);
        // }


        System.Console.WriteLine("\nEnc_AES256: " + Aes256.Encrypt(input, key));
    }
}
