from enum import Enum


class LanguageType(str,Enum):
    PYTHON = "PYTHON"
    CSHARP = "CSHARP"
    JAVA = "JAVA"
    GO = "GO"

languageExtensions = {
    LanguageType.PYTHON : "py",
    LanguageType.CSHARP : "cs",
    LanguageType.JAVA : "java",
    LanguageType.GO: "go"
}

class PromptStep(str,Enum):
    INITIAL_ANALYSIS = "INITIAL_ANALYSIS"
    SECONDARY_ANALYSIS = "SECONDARY_ANALYSIS"
    SUMMARY = "SUMMARY"

class VulnType(str, Enum):
    LFI = "LFI"
    RCE = "RCE"
    SSRF = "SSRF"
    AFO = "AFO"
    SQLI = "SQLI"
    XSS = "XSS"
    IDOR = "IDOR"