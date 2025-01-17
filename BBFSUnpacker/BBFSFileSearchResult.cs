using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BBFSUnpacker;

public record BBFSFileSearchResult(bool Found, string FileName, int Offset, BBFSArchive Archive);
