using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureCodeAnalyzer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TestHelper;

namespace CodeSharpenerCryptoAnalyzer.Test
{
    [TestClass]
    public class EncryptionTest : DiagnosticVerifier
    {
        /// <summary>
        /// Test Method For String Concat Test
        /// </summary>
        [TestMethod]
        public void ByteArraySimpleHardCodedTest()
        {
            var path = "..//..//..//Targets//ByteArrayTest//ByteArraySimpleHardCoded.cs";
            var test = System.IO.File.ReadAllText(path);

            var expectedTaint1 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 13, 13)
                                    }
            };

            var expectedTaint2 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 14, 13)
                                    }
            };

            var expectedTaint3 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 16, 13)
                                    }
            };

            var expectedTaint4 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 17, 13)
                                    }
            };

            VerifyCSharpDiagnostic(test, expectedTaint1, expectedTaint2, expectedTaint3, expectedTaint4);
        }

        /// <summary>
        /// Test Method For String Concat Test
        /// </summary>
        [TestMethod]
        public void ByteArrayWithNewKeywordTest()
        {
            var path = "..//..//..//Targets//ByteArrayTest//ByteArrayWithNewKeyword.cs";
            var test = System.IO.File.ReadAllText(path);

            var expectedTaint1 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 13, 13)
                                    }
            };

            var expectedTaint2 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 14, 13)
                                    }
            };

            var expectedTaint3 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 16, 13)
                                    }
            };

            var expectedTaint4 = new DiagnosticResult
            {
                Id = "HardCodedKey",
                Message = String.Format("Hard-Coded Key and IV value could lead to Security Vulnerability"),
                Severity = DiagnosticSeverity.Warning,
                Locations =
                                new[] {
                                        new DiagnosticResultLocation("Test0.cs", 17, 13)
                                    }
            };

            VerifyCSharpDiagnostic(test, expectedTaint1, expectedTaint2, expectedTaint3, expectedTaint4);
        }

        protected override DiagnosticAnalyzer GetCSharpDiagnosticAnalyzer()
        {
            return new SecureCodeAnalyzerAnalyzer();
        }
    }
}
