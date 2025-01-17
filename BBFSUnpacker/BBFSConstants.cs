using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BBFSUnpacker;

public static class BBFSConstants
{
    public static uint[] ArchiveEncryptionLayerKey = [0xDD12217D, 0x283E4FA6, 0xD93CC350, 0xC9374599];
    public static uint[] keys2 = [0x2EB1D439, 0x40CD499C, 0x8BF71712, 0xB1F443F8];
}
