using System;
using System.Collections.Generic;
using System.Text;

namespace AESEncryption
{
    public class AESModel
    {
        public byte[] AESKey { get; set; }
        public byte[] AESIV { get; set; }
    }
}
