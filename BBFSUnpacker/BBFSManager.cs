using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Runtime.InteropServices;

using Syroot.BinaryData;
using Syroot.BinaryData.Memory;
using BBFSUnpacker.Crypto;

namespace BBFSUnpacker;

class BBFSManager
{
    public List<(int Offset, int Type)> Hashes = [];

    public List<BBFSArchive> Archives { get; set; } = [];

    public void AddArchive(string fileName)
    {
        var archive = new BBFSArchive();
        archive.Read(fileName);
        Archives.Add(archive);
    }

    public bool ExtractFile(string file)
    {
        if (TryFindFileInfo(file, out BBFSFileSearchResult result))
        {
            RC4_KEY key = GetFileNameKeyTable(file);
            result.Archive.ExtractFile(result, key);
        }
        else
        {
            Console.WriteLine($"Cannot find expected file in BFS, File: {file}");
        }

        return false;
    }

    public bool TryFindFileInfo(string file, out BBFSFileSearchResult result)
    {
        foreach (var archive in Archives)
        {
            if (archive.TryFindFileInfo(file, out result))
                return true;
        }

        result = new BBFSFileSearchResult(false, string.Empty, -1, null);
        return false;
    }

    public RC4_KEY GetFileNameKeyTable(string fileName)
    {
        byte[] fileNameBytes = Encoding.ASCII.GetBytes(fileName.ToLower());

        RC4_KEY key = new RC4_KEY();
        RC4.RC4Init(fileNameBytes, fileNameBytes.Length, key);

        return key;
    }
}
