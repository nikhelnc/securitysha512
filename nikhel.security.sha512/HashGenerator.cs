using System;
using System.Text;
using System.Security.Cryptography;

public class HashGenerator
{
    private static Encoding encoding = Encoding.UTF8;

    /// <summary>
    /// Compute Hash SHA512
    /// </summary>
    /// <param name="data">Data to hash </param>
    /// <param name="secret">Secret for hash</param>
    /// <returns>The computed hash code</returns>
    static string ComputeHash(string data, string secret)
    {

        var keyByte = PackH(secret);

        using (var hmacsha512 = new HMACSHA512(keyByte))
        {
            hmacsha512.ComputeHash(encoding.GetBytes(data));

            return BytesToString(hmacsha512.Hash);

        }
    }

    /// <summary>
    /// Convert bytes array to String
    /// </summary>
    /// <param name="bytes">Bytes array</param>
    /// <returns></returns>
    static string BytesToString(byte[] bytes)
    {

        string result = "";

        for (int i = 0; i < bytes.Length; i++)
            result += bytes[i].ToString("X2");

        return result;
    }

    /// <summary>
    /// Pack Hex string, high nibble first data into binary string
    /// </summary>
    /// <param name="hexdata">Hexadecimal data</param>
    /// <returns></returns>
    public static byte[] PackH(string hexdata)
    {

        if ((hexdata.Length % 2) == 1)
        {
            hexdata += '0';
        }

        byte[] result = new byte[hexdata.Length / 2];

        for (int i = 0; i < hexdata.Length; i += 2)
        {
            result[i / 2] = Convert.ToByte(hexdata.Substring(i, 2), 16);
        }

        return result;
    }

}

