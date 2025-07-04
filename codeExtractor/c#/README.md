## Install .NET SDK

Install .NET SDK - [Installation](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install?tabs=dotnet9&pivots=os-linux-ubuntu-2410) 

## Build

```
dotnet add package Microsoft.CodeAnalysis.CSharp
cd dotnet/codeExtractor
dot net build
```

## Standalone usage (develop/testing)

```
dotnet run bin/Debug/net9.0/codeExtractor <folder-path> <function-or-class-name>
```
