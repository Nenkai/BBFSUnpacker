using System;
using System.Collections.Generic;
using System.IO;

namespace BBFSUnpacker;

class Program
{
    static void Main(string[] args)
    {
        var bfs = new BBFSManager();
        bfs.AddArchive(@"C:\Gran_Turismo\RPCS3\dev_hdd0\game\BLET70048\USRDIR\RIDGE RACER Driftopia\00__ridge_racer__");
        bfs.AddArchive(@"C:\Gran_Turismo\RPCS3\dev_hdd0\game\BLET70048\USRDIR\RIDGE RACER Driftopia\01___driftopia___");

        var lines = File.ReadAllLines("driftopia.filelist");

        var dict = new List<string>();
        foreach (var line in lines)
        {
            if (string.IsNullOrEmpty(line) || line.StartsWith("//"))
                continue;

            if (line == "[END]")
                break;

            if (!dict.Contains(line))
                dict.Add(line);

            bfs.ExtractFile(line);
        }
    }
}
