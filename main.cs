using AES;
using System;

public class Out
{
    public static void Main(string[] args)
    {
        AES256 Aes256 = new AES256();
        Console.WriteLine("input what to encrypt using the aes256 encryption method");
        Console.Write("input: ");
        string input = Console.ReadLine();
        Aes256.Encrypt(input);
    }
}
