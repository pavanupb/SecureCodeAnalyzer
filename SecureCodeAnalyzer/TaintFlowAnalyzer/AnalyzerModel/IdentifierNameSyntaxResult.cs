using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.AnalyzerModels
{
    public class IdentifierNameSyntaxResult
    {
        public IdentifierNameSyntax IdentifierNameSyntaxNode { get; set; }
        public bool IsIdentifierPresent { get; set; }

        public VariableDeclaratorSyntax VariableDeclarator { get; set; }
    }
}
