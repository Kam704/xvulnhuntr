using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Encodings.Web;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 2)
        {
            Console.WriteLine("{\"error\":\"Usage: dotnet run <folder-path> <function-or-class-name>\"}");
            return;
        }

        string folderPath = args[0];
        string searchName = args[1];

        if (!Directory.Exists(folderPath))
        {
            Console.WriteLine($"{{\"error\":\"Folder '{folderPath}' not found!\"}}");
            return;
        }

        var csFiles = Directory.GetFiles(folderPath, "*.cs", SearchOption.AllDirectories);

        foreach (var filePath in csFiles)
        {
            string code = File.ReadAllText(filePath);
            SyntaxTree tree = CSharpSyntaxTree.ParseText(code);
            SyntaxNode root = tree.GetRoot();

            var result = ExtractCode(root, searchName);
            if (!string.IsNullOrEmpty(result))
            {
                // Prepare JSON output
                var jsonOutput = new
                {
                    filepath = filePath,
                    source = result
                };

                // Serialize JSON as a single line and escape newlines properly
                string jsonString = JsonSerializer.Serialize(jsonOutput, new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                });

                Console.WriteLine(jsonString);
                return;
            }
        }

        Console.WriteLine($"{{\"error\":\"No matching class or method '{searchName}' found in the project.\"}}");
    }

    static string ExtractCode(SyntaxNode root, string searchName)
    {
        var classNode = root.DescendantNodes()
                            .OfType<ClassDeclarationSyntax>()
                            .FirstOrDefault(c => c.Identifier.Text == searchName);

        if (classNode != null)
        {
            return classNode.ToFullString().Replace("\r", "").Replace("\n", "\\n");
        }

        var methodNode = root.DescendantNodes()
                             .OfType<MethodDeclarationSyntax>()
                             .FirstOrDefault(m => m.Identifier.Text == searchName);

        if (methodNode != null)
        {
            return methodNode.ToFullString().Replace("\r", "").Replace("\n", "\\n");
        }

        return null;
    }
}
