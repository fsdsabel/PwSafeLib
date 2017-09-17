using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PwSafeLib.Filesystem
{
    /// <summary>
    /// Implementation of a V4 Password file safe. 
    /// </summary>
    /// <remarks>This is not done yet!</remarks>
    public class PwsFileV4 : PwsFile
    {
        public PwsFileV4(Stream stream, byte[] terminalBlock, FileMode fileMode) : base(stream, terminalBlock, fileMode)
        {
        }

        internal override int TimeFieldLen => 5;
        public override Task OpenAsync()
        {
            throw new NotImplementedException();
        }
    }
}
