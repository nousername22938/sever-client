//Client
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Client
{
    class Program
    {
        static NetworkStream stream;
        static TcpClient client;
        static Thread thread;
        static byte[] aeskey = GenerateAESkey(256);
        static byte[] aesiv = GenerateAESiv();
        static void Main(string[] args)
        {

            try
            {
                using (TcpClient client2 = new TcpClient())
                {
                    client2.Connect("127.0.0.1", 5555);
                    NetworkStream stream2 = client2.GetStream();
                    stream2.Write(aeskey, 0, aeskey.Length);
                    stream2.Write(aesiv, 0, aesiv.Length);
                    Console.WriteLine("AES key and IV sent to server.");

                    // Close the connection
                    client2.Close();
                    Console.WriteLine("Connection to port 5555 closed.");
                }
                using (client = new TcpClient())
                {
                    client.Connect("127.0.0.1", 180);
                    Console.WriteLine("Connected to server : 127.0.0.1");
                    stream = client.GetStream();
                    Console.WriteLine("Client connected");
                    thread = new Thread(receive);
                    thread.Start();
                    Console.WriteLine("You can begin sending messages");
                    while (true)
                    {
                        Console.Write("$ ");
                        byte[] buffer = new byte[1024];
                        //Console.Write("enter your message here : ");
                        string message = Console.ReadLine();
                        if (string.IsNullOrEmpty(message))
                        {
                            continue;
                        }
                        buffer = Encoding.UTF8.GetBytes(message);
                        byte[] bytes = encryption(buffer, aeskey, aesiv);
                        stream.Write(bytes, 0, bytes.Length);
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Environment.Exit(0);
            }


        }
        public static void receive()
        {
            try
            {
                while (true)
                {


                    byte[] buffer = new byte[client.ReceiveBufferSize];
                    int lenght = stream.Read(buffer, 0, buffer.Length);
                    byte[] data = new byte[lenght];
                    Array.Copy(buffer, data, lenght);
                    string message = decryption(data, aeskey, aesiv);
                    Console.Write("server : " + message + "\n$");

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Environment.Exit(0);
            }
        }
        public static byte[] GenerateAESkey(int keysize)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = keysize;
                aes.GenerateKey();
                return aes.Key;
            }
        }
        public static byte[] GenerateAESiv()
        {
            using (var aes = Aes.Create())
            {
                aes.GenerateIV();
                return aes.IV;
            }
        }
        public static byte[] encryption(byte[] plaintext, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plaintext, 0, plaintext.Length);
                        // Get the encrypted bytes from the MemoryStream
                        byte[] encrypted = msEncrypt.ToArray();

                        return encrypted;
                    }
                }

            }
        }
        public static string decryption(byte[] plaintext, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using (MemoryStream msDecrypt = new MemoryStream(plaintext))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        byte[] decryptedBytes = new byte[plaintext.Length];
                        int bytesRead = csDecrypt.Read(decryptedBytes, 0, decryptedBytes.Length);
                        string plaintext2 = Encoding.UTF8.GetString(decryptedBytes, 0, bytesRead);
                        return plaintext2;
                    }
                }

            }


        }

    }
    
}
