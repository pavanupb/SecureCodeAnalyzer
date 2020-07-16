using CodeSharpenerCryptoAnalyzer.AnalyzerModels;
using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.Visitors
{
    public interface IArgumentVisitor
    {
        void Visit(SyntaxNode syntaxNode);
        IdentifierNameResult GetResult();
    }
}
