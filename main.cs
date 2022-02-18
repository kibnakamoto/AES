using AES;
using System;

public class Out
{
    public static void Main(string[] args)
    {
        AES256 Aes256 = new AES256();
        Console.WriteLine("input what to encrypt using the aes256 encryption method");
        Console.Write("\ninput: ");
        string input = Console.ReadLine();
        System.Console.WriteLine("\nEnc_AES256: " + Aes256.Encrypt(input));
    }
}
