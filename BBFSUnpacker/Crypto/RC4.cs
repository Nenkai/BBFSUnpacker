using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Buffers.Binary;

namespace BBFSUnpacker.Crypto;

public static class RC4
{
    public static void RC4Init(Span<byte> data, int len, RC4_KEY key)
    {
        // rc4_set_key
        key.x = 0;
        key.y = 0;

        var d = key.data;

        for (int i = 0; i < 256; i++)
            d[i] = (byte)i;

        int id1 = 0;
        int id2 = 0;

        for (int i = 0; i < 256; i += 4)
        {
            SK_LOOP(data, d, i + 0);
            SK_LOOP(data, d, i + 1);
            SK_LOOP(data, d, i + 2);
            SK_LOOP(data, d, i + 3);

            void SK_LOOP(Span<byte> data, Span<byte> d, int n)
            {
                byte tmp = d[n];
                id2 = data[id1] + tmp + id2 & 0xFF;
                if (++id1 == len)
                    id1 = 0;
                d[n] = d[id2];
                d[id2] = tmp;
            }
        }

        // Rest custom
        byte x = 0, y = 0, tx = 0, ty = 0;
        for (int i = 0x80; i > 0; i--)
        {
            // Loop 6 rounds (rc4_enc.c - RC4())
            x = (byte)(x + 1);
            tx = d[x];
            y = (byte)(tx + y);
            d[x] = ty = d[y];
            d[y] = tx;

            x = (byte)(x + 1);
            tx = d[x];
            y = (byte)(tx + y);
            d[x] = ty = d[y];
            d[y] = tx;

            x = (byte)(x + 1);
            tx = d[x];
            y = (byte)(tx + y);
            d[x] = ty = d[y];
            d[y] = tx;

            x = (byte)(x + 1);
            tx = d[x];
            y = (byte)(tx + y);
            d[x] = ty = d[y];
            d[y] = tx;

            x = (byte)(x + 1);
            tx = d[x];
            y = (byte)(tx + y);
            d[x] = ty = d[y];
            d[y] = tx;

            x = (byte)(x + 1);
            tx = d[x];
            y = (byte)(tx + y);
            d[x] = ty = d[y];
            d[y] = tx;
        }

        key.x = x;
        key.y = y;
    }

    public static void RC4Crypt(Span<byte> inData, Span<byte> outData, int len, RC4_KEY key)
    {
        ref int x = ref key.x;
        ref int y = ref key.y;

        Span<byte> d = key.data;

        byte tx = 0, ty = 0;
        if (len > 0)
        {
            for (int i = 0; i < len; i++)
            {
                x = (byte)(x + 1);
                tx = d[x];
                y = (byte)(tx + y);
                d[x] = ty = d[y];
                d[y] = tx;

                outData[i] = (byte)(d[(byte)(tx + ty)] ^ inData[i]);
            }
        }
    }
}

public class RC4_KEY
{
    public int x;
    public int y;
    public byte[] data = new byte[0x100];
}
