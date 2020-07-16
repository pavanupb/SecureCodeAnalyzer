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
    public class ExpressionStatementVisitor : CSharpSyntaxWalker
    {
        private bool IsStringLiteralExpressionPresent;
        private AssignmentExpressionSyntax AssignmentExpressionSyntax;

        public ExpressionStatementVisitor()
        {
            IsStringLiteralExpressionPresent = false;
        }
        public override void VisitExpressionStatement(ExpressionStatementSyntax node)
        {
            base.VisitExpressionStatement(node);
        }

        public override void VisitAssignmentExpression(AssignmentExpressionSyntax node)
        {
            if (node.Kind().Equals(SyntaxKind.AddAssignmentExpression))
            {
                if (node.Right.Kind().Equals(SyntaxKind.StringLiteralExpression))
                {
                    IsStringLiteralExpressionPresent = true;
                    AssignmentExpressionSyntax = node;
                }
            }

            else if(node.Kind().Equals(SyntaxKind.SimpleAssignmentExpression))
            {
                if(node.Right.Kind().Equals(SyntaxKind.StringLiteralExpression))
                {
                    AssignmentExpressionSyntax = node;
                    IsStringLiteralExpressionPresent = true;                    
                }
            }
        }

        public StringLiteralExpressionResult GetAssignmentExpressionResult()
        {
            StringLiteralExpressionResult stringLiteralExpressionResult = new StringLiteralExpressionResult
            {
                ExpressionSyntax = AssignmentExpressionSyntax,
                IsStringLiteralInitializer = IsStringLiteralExpressionPresent
            };

            return stringLiteralExpressionResult;            
        }
    }
}

        
