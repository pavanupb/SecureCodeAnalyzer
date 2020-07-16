using CodeSharpenerCryptoAnalyzer.AnalyzerModels;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeSharpenerCryptoAnalyzer.Visitors
{
    public class ArgumentsVisitor : CSharpSyntaxWalker, IArgumentVisitor
    {
        private bool IsIdentiferPresent;
        private IdentifierNameSyntax IdentiferNameNode;

        public ArgumentsVisitor()
        {
            IsIdentiferPresent = false;
        }

        public override void VisitArgumentList(ArgumentListSyntax node)
        {
            base.VisitArgumentList(node);
        }
        public override void VisitIdentifierName(IdentifierNameSyntax node)
        {
            IsIdentiferPresent = true;
            IdentiferNameNode = (IdentifierNameSyntax)node;
        }

        public IdentifierNameResult GetResult()
        {
            IdentifierNameResult identifierNameResult = new IdentifierNameResult
            {
                IsIdentifierNodePresent = IsIdentiferPresent,
                IdentifierNameSyntax = IdentiferNameNode
            };

            return identifierNameResult;
        }

    }
}
