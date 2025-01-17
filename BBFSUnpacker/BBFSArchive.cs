using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Buffers.Binary;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;
using BBFSUnpacker.Hashing;
using BBFSUnpacker.Crypto;

namespace BBFSUnpacker;

public class BBFSArchive
{
    public string ArchiveName { get; set; }

    public int HashSize { get; set; }
    public int Version { get; set; }
    public int EntryCount { get; set; }

    public byte[] TocData { get; set; }

    public const int BlockSize = 0x8000;

    public List<(int Offset, int Count)> Hashes = [];

    public void Read(string fileName)
    {
        ArchiveName = fileName;

        var datafs = File.Open(fileName, FileMode.Open);
        var data = datafs.ReadBytes((int)Math.Min(0x200000, datafs.Length));
        datafs.Dispose();

        int pos = 0;
        int i = 0;
        while (pos < data.Length && i < 8)
        {
            int rem = data.Length - pos;
            int length = Math.Min(BlockSize, rem);

            BBFSCrypto.Decrypt(data.AsSpan(pos), BBFSConstants.ArchiveEncryptionLayerKey, length);

            pos += length;
            i++;
        }

        SpanReader sr = new SpanReader(data);

        ReadHeader(data, ref sr);
    }

    private void ReadHeader(byte[] data, ref SpanReader sr)
    {
        if (sr.ReadInt32() != 0x73666262)
            throw new Exception("Invalid magic");

        Version = sr.ReadInt32();
        int tocLengthRaw = sr.ReadInt32();
        int tocLength = (int)((tocLengthRaw & 0x7FFFFFFF) + 3 & 0xFFFFFFFC);
        EntryCount = sr.ReadInt32();

        BBFSCrypto.DecryptBody(data.AsSpan(20), BBFSConstants.keys2, tocLength - 20);

        TocData = data.AsSpan(0).ToArray();

        // Entering TOC
        sr.Position = 0x14;
        HashSize = sr.ReadInt32();

        for (int i = 0; i < HashSize; i++)
            Hashes.Add((sr.ReadInt32(), sr.ReadInt32()));
    }

    public bool TryFindFileInfo(string fileName, out BBFSFileSearchResult result)
    {
        string fileNameLower = fileName.ToLower();
        int index = GetFileNameIndex(fileNameLower);

        var (Offset, Count) = Hashes[index];
        SpanReader sr = new SpanReader(TocData);
        sr.Position = Offset;

        ulong crc64 = CRC64.Checksum(fileNameLower);

        for (int i = 0; i < Count; i++)
        {
            int baseEntryPos = sr.Position;

            byte flag = sr.ReadByte();
            if ((flag & 8) != 0)
            {
                sr.Position = baseEntryPos + 16;
                // Check checksum
                if (sr.ReadUInt64() == crc64)
                {
                    result = new BBFSFileSearchResult(true, fileName, baseEntryPos, this);
                    Console.WriteLine($"{fileName} Found in {Path.GetFileNameWithoutExtension(ArchiveName)} at 0x{baseEntryPos:X8} ({crc64:X})");
                    return true; // Got it
                }
            }
            else
            {

            }

            // Move to next
            sr.Position = baseEntryPos + 2;
            short count = sr.ReadInt16();

            sr.Position = baseEntryPos + count * sizeof(uint) + 0x18;
        }

        result = new BBFSFileSearchResult(false, string.Empty, -1, null);
        return false;
    }

    public void ExtractFile(BBFSFileSearchResult fileResult, RC4_KEY key)
    {
        SpanReader sr = new SpanReader(TocData);
        sr.Position = fileResult.Offset;

        BBFSFileFlag flag = (BBFSFileFlag)sr.ReadInt16();
        sr.Position += 2;

        uint fileOffset = sr.ReadUInt32() ^ BinaryPrimitives.ReadUInt32LittleEndian(key.data.AsSpan(0));
        uint uncompressedSize = sr.ReadUInt32() ^ BinaryPrimitives.ReadUInt32LittleEndian(key.data.AsSpan(4));
        uint compressedSize = sr.ReadUInt32() ^ BinaryPrimitives.ReadUInt32LittleEndian(key.data.AsSpan(8));

        // Proceed to extract - TODO: Try to actually not read the whole file's blocks?
        // Normally the game just reads 0x8000 blocks, and performs XTEA -> RC4 -> Inflate one by one

        uint blockIndex = fileOffset / BlockSize;
        int blockCount = fileOffset % BlockSize > 0 ? 1 : 0;
        blockCount += (int)Math.Round((double)compressedSize / 0x8000, MidpointRounding.ToPositiveInfinity);

        byte[] fileBlockBuffer = new byte[blockCount * BlockSize];
        using var ms = new FileStream(ArchiveName, FileMode.Open);
        // We must first go through the first encryption layer that applies throughout the whole archive
        // In 0x8000 blocks, Read all affected blocks and decrypt them all
        ms.Position = (int)(blockIndex * BlockSize);
        ms.ReadExactly(fileBlockBuffer);
        for (int i = 0; i < blockCount; i++)
            BBFSCrypto.Decrypt(fileBlockBuffer.AsSpan(i * BlockSize), BBFSConstants.ArchiveEncryptionLayerKey, BlockSize);

        // Decrypt the file itself, now
        int firstBlockOffset = (int)(fileOffset % BlockSize);
        Span<byte> fileBuffer = fileBlockBuffer.AsSpan(firstBlockOffset);

        byte[] fileData;
        if (flag.HasFlag(BBFSFileFlag.CompressEncrypted))
        {
            int offset = 0;
            int size = BlockSize - firstBlockOffset;
            for (int i = 0; i < blockCount; i++)
            {
                RC4.RC4Crypt(fileBuffer.Slice(offset), fileBuffer.Slice(offset), size, key);
                offset += size;
                size = BlockSize;
            }


            unsafe
            {
                fixed (byte* pBuffer = &fileBuffer[0])
                {
                    using var stream = new UnmanagedMemoryStream(pBuffer, compressedSize);
                    using (var deflateStream = new DeflateStream(stream, CompressionMode.Decompress))
                    {
                        stream.Position = 2;
                        fileData = new byte[uncompressedSize];
                        deflateStream.ReadExactly(fileData);
                    }

                }
            }
        }
        else
        {
            fileData = fileBuffer.Slice(0, (int)uncompressedSize).ToArray(); // Yikes
        }

        Directory.CreateDirectory(Path.GetDirectoryName(fileResult.FileName));
        File.WriteAllBytes(fileResult.FileName, fileData);

    }

    public int GetFileNameIndex(string fileName)
    {
        byte[] fileNameBytes = Encoding.ASCII.GetBytes(fileName);
        uint crc = CRC32.DoCRC(fileNameBytes, (uint)fileNameBytes.Length, 0);

        return (int)(crc % HashSize);
    }
}
