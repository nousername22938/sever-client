//Sever
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Server
{
    class Program
    {
        static NetworkStream stream;
        static TcpClient client;
        static Thread thread;
        static byte[] aeskey;
        static byte[] aesiv;
        static void Main(string[] args)
        {
            IPAddress iPAddress = IPAddress.Any;
            var server = new TcpListener(iPAddress, 180);
            var server2 = new TcpListener(iPAddress, 5555);
            try
            {
                TcpListener keyIVListener = new TcpListener(IPAddress.Any, 5555);
                keyIVListener.Start();
                Console.WriteLine("Listening for key and IV on port 5555...");

                // Accept a single connection for receiving the AES key and IV
                TcpClient keyIVClient = keyIVListener.AcceptTcpClient();
                Console.WriteLine("Client connected to port 5555");

                // Handle receiving the AES key and IV
                HandleAESKeyIV(keyIVClient);

                // Close the connection for receiving the AES key and IV
                keyIVClient.Close();
                Console.WriteLine("Connection to port 5555 closed.");
                server.Start();
                Console.WriteLine("Server started");
                client = server.AcceptTcpClient();
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
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
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

                    Console.Write("client : " + message + "\n$");
                }
}
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }

        }
        /*public static byte[] GenerateAESkey(int keysize)
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
        }*/
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
        static void HandleAESKeyIV(TcpClient client)
        {
            try
            {
                // Buffer to store the received AES key and IV
                byte[] keyBytes = new byte[32]; // Assuming AES key length is 32 bytes
                byte[] ivBytes = new byte[16];  // Assuming IV length is 16 bytes

                // Network stream to read data from the client
                NetworkStream stream = client.GetStream();

                // Read the AES key from the stream
                int bytesRead = stream.Read(keyBytes, 0, keyBytes.Length);
                Console.WriteLine("Received AES key from client: " + BitConverter.ToString(keyBytes));
                bytesRead += stream.Read(ivBytes, 0, ivBytes.Length);
                Console.WriteLine("Received IV from client: " + BitConverter.ToString(ivBytes));
                aeskey = keyBytes;
                aesiv = ivBytes;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error handling AES key and IV: " + ex.Message);
            }
        }

    }
}
