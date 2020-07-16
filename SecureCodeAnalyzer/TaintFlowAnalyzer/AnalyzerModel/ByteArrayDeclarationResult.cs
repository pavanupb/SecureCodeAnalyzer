using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class ByteArrayDeclarationResult
    {
        public VariableDeclaratorSyntax DeclaratorSyntax { get; set; }
        public bool IsArrayInitializer { get; set; }


    }
}
