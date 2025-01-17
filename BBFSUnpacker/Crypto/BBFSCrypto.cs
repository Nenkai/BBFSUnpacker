using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;

namespace BBFSUnpacker.Crypto;

public class BBFSCrypto
{
    public static void Decrypt(Span<byte> dataBytes, uint[] keys, int sizeBytes)
    {
        int size = sizeBytes / 4;
        var data = MemoryMarshal.Cast<byte, uint>(dataBytes.Slice(0, sizeBytes));

        if (size > 1)
        {
            uint currentVal = data[size - 1];
            int i = 0;
            if (size - 1 > 0)
            {
                for (; i < size - 1; i++)
                {
                    data[i] -= (currentVal ^ 0x9E3779B9) +
                                (data[i + 1] ^ keys[((byte)i ^ 0xFE) & 3]) ^
                                (4 * currentVal ^ data[i + 1] >> 5) + (currentVal >> 3 ^ 16 * data[i + 1]);

                    currentVal = data[i];
                }
            }
            data[i] -= (currentVal ^ 0x9E3779B9)
                        + (data[0] ^ keys[((byte)i ^ 0xFE) & 3])
                        ^ (4 * currentVal ^ data[0] >> 5) + (currentVal >> 3 ^ 16 * data[0]);
        }
    }

    public static void DecryptBody(Span<byte> dataBytes, uint[] key, int sizeBytes)
    {
        int size = sizeBytes / 4;
        var data = MemoryMarshal.Cast<byte, uint>(dataBytes.Slice(0, sizeBytes));

        uint v4;
        uint v5;
        uint v6;
        uint v7;
        uint v8;
        bool v9;
        int v10;
        uint v11;

        if (size > 1)
        {
            v4 = data[0];
            v5 = (uint)(-1640531527 * (0x34 / size + 6));
            v11 = v5;
            do
            {
                v6 = (uint)size - 1;
                v10 = (int)(v5 >> 2 & 3);
                if (size != 1)
                {
                    do
                    {
                        data[(int)v6] -= (v11 ^ v4) + (data[(int)v6 - 1] ^ key[v10 ^ v6 & 3]) ^ (4 * v4 ^ data[(int)v6 - 1] >> 5)
                                                                                       + (v4 >> 3 ^ 16 * data[(int)v6 - 1]);
                        v4 = data[(int)v6--];
                    }
                    while (v6 != 0);
                }
                v7 = v4 >> 3 ^ 16 * data[size - 1];
                v8 = 4 * v4 ^ data[size - 1] >> 5;
                data[0] -= (v11 ^ v4) + (data[size - 1] ^ key[v10 ^ v6 & 3]) ^ v8 + v7;
                v4 = data[0];
                v9 = v11 == 0x9E3779B9;
                v5 = v11 + 0x61C88647;
                v11 += 0x61C88647;
            }
            while (!v9);
        }
    }
}
