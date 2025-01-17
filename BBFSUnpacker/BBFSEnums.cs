using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BBFSUnpacker;

[Flags]
public enum BBFSFileFlag
{
    CompressEncrypted = 0x01,
    File = 0x08,
}
