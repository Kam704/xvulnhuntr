# xvulnhuntr

<div align="center">

  <img width="250" src="xvulnhuntr.png" alt="xvulnhuntr Logo">

</div>


xvulnhuntr is a fork of [vulnhuntr](https://github.com/protectai/vulnhuntr).

The `x` stands for *extended*, with the following major contributions:
- Additional programming languages:
  - C# - see [README](./codeExtractor/c%23/README.md)
  - Java - see [README](./codeExtractor/java/README.md)
  - Go - see [README](./codeExtractor/go/README.md)
- test suite which allows local development with:
  - reproducibility
  - no API latency
  - no API costs

## Description

xvlnhuntr is a tool to find vulnerabilities in source code. The core idea is to make the LLM request the context code in a multi-step process. In this way, it is possible to analyze large repositories without requiring huge context windows.

See identified vulnerabilities at [Protect AI Vulnhuntr Blog](https://protectai.com/threat-research/vulnhuntr-first-0-day-vulnerabilities)

### Extend to other languages

xvulnhuntr supports arbitrary typed languages in a simple way: when the LLM asks for the code block for a function or class, an external program called `codeExtractor` is invoked to parse the syntax tree and retrieve the corresponding block.

See the [c#](./codeExtractor/c%23/) and [java](./codeExtractor/java/) versions of codeExtractor as a reference.

## Installation

> [!IMPORTANT]
> For python targets xvulnhuntr strictly requires Python 3.10 because of a number of bugs in Jedi which it uses to parse Python code. It will not work reliably if installed with any other versions of Python.

### Miniconda & Poetry (recommended)

Install Miniconda - [Download](https://www.anaconda.com/download/success#miniconda)

Create and activate an environment with python 3.10
```
conda create -n v-xvulnhuntr python=3.10
conda activate v-xvulnhuntr
```

```bash
git clone https://github.com/compasssecurity/xvulnhuntr
cd xvulnhuntr
conda install poetry
poetry lock # update existing poetry.lock
poetry install
```

### pipx
```bash
pipx install git+https://github.com/compasssecurity/xvulnhuntr.git --python python3.10
```

Note that it is up to you how to install python3.10 (e.g. via pyenv)

### Docker (python only)

```bash
docker build -t xvulnhuntr https://github.com/compasssecurity/xvulnhuntr.git#main
```

Python 3.10 is specified in the Dockerfile with `FROM python:3.10-bookworm`

```
docker run --rm -e ANTHROPIC_API_KEY=sk-1234 -v /local/path/to/target/repo:/repo xvulnhuntr:latest -r /repo -a repo-subfolder/target-file.py -l PYTHON
```

> [!IMPORTANT]
> Docker can be used as a convenient way to use Python 3.10 however, when analyzing C#, Java or Go you would have to install dot net, java and go within the docker container, which is possible but imho an overkill.


## Usage

This tool is designed to analyze a repository for potential remotely exploitable vulnerabilities. The tool requires an API key and the local path to a repository. You may also optionally specify a custom endpoint for the LLM service.

```
usage: xvulnhuntr [-h] [-r ROOT] [-a ANALYZE] [--llm {claude,gpt}] [-l {LanguageType.PYTHON,LanguageType.CSHARP,LanguageType.JAVA,LanguageType.GO}] [-v] [-t] [-p PROXY]
                 [-c CERTIFICATE] [-w]

Analyze a repository for vulnerabilities. Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running.

options:
  -h, --help            show this help message and exit

Main parameters:
  -r ROOT, --root ROOT  Path to the root directory of the project
  -a ANALYZE, --analyze ANALYZE
                        Specific path or file within the project to analyze
  --llm {claude,gpt}    LLM client to use (default: claude)
  -l {LanguageType.PYTHON,LanguageType.CSHARP,LanguageType.JAVA,LanguageType.GO}
                        Programming language. Supported: PYTHON, CSHARP, JAVA, GO

Development parameters:
  -v, --verbosity       Increase output verbosity (-v, -vv)
  -t, --test            Run test suite using mock api responses
  -p PROXY, --proxy PROXY
                        In the form http://127.0.0.1:8080
  -c CERTIFICATE, --certificate CERTIFICATE
                        Path to the proxy CA
  -w, --write           Write responses to file (can be reused as tests)
```


**Example.** Analyze the entire repository using Claude:

```bash
export ANTHROPIC_API_KEY="sk-1234"
xvulnhuntr -r /path/to/target/repo/ -l <LANG>
```

**Example.** Analyze the entire repository with GPT
```bash
export OPENAI_API_KEY="sk-1234"
xvulnhuntr -r /path/to/target/repo/ --llm gpt -l <LANG> 
```

> [!TIP]
> Claude is recommended. Testing gave better results with it over GPT.

**Example.** Analyze the `/path/to/target/repo/server.py` file using GPT-4o. It is also possible to specify a subdirectory instead of a file:

```bash
xvulnhuntr -r /path/to/target/repo/ -a server.cs -l CSHARP 
```

> [!CAUTION]
> Always set spending limits or closely monitor costs with the LLM provider you use.

> [!TIP]
> You can monitor the execution by inspecting the log file, e.g.

```
tail -f xvulnhuntr.log
```

## Documentation

<details>
<summary>Capabilities, Logic Flow, Output </summary>

## Capabilities 

- Python, C#, Java and Go codebases are supported.
- Builtin prompts for the following vulnerability classes:
  - Local file include (LFI)
  - Arbitrary file overwrite (AFO)
  - Remote code execution (RCE)
  - Cross site scripting (XSS)
  - SQL Injection (SQLI)
  - Server side request forgery (SSRF)
  - Insecure Direct Object Reference (IDOR)


## Logic Flow
![VulnHuntr logic](https://github.com/user-attachments/assets/7757b053-36ff-425e-ab3d-ab0100c81d49)
- LLM summarizes the README and includes this in the system prompt
- LLM does initial analysis on an entire file and reports any potential vulnerabilities
- Vulnhuntr then gives the LLM a vulnerability-specific prompt for secondary analysis
- Each time the LLM analyzes the code, it requests additional context functions/classes/variables from other files in the project
- It continues doing this until the entire call chain from user input to server processing is complete then gives a final analysis
- The final analysis consists of it's reasoning, a proof of concept exploit, and a confidence score

>[!TIP]
> Generally confidence scores < 7 mean there's unlikely a vulnerability. Confidence scores of 7 mean it should be investigated, and confidence scores of 8+ mean it is very likely to be a valid vulnerability.

## Output

The tool generates a detailed report of the vulnerabilities found in the analyzed files. The report includes:

- Initial assessment results for each file.
- Secondary assessment results with context functions and class references.
- Confidence scores for vulnerabilities found.
- Logs of the analysis process.
- PoC exploit

Below is an example of a Vulnhuntr report describing a 0-day remote code execution vulnerability in [Ragflow](https://github.com/infiniflow/ragflow) (now fixed):

```
scratchpad:
  1. Analyzing the add_llm function in llm_app.py. 2. Identified user input used as keys to access dictionaries: EmbeddingModel, ChatModel, RerankModel,
CvModel, and TTSModel. 3. These dictionaries contain class references, which are instantiated with user-supplied parameters. 4. The factory variable is 
directly used from user input (req['llm_factory']) without proper validation. 5. The llm_name is also derived from user input in most cases. 6. The 
instantiation of these classes occurs in try-except blocks, but exceptions are only used for error messages, not preventing execution. 7. The api_key 
and other sensitive information are passed directly to these instantiated classes. 8. There's no comprehensive input validation or sanitization for the 
factory or llm_name variables. 9. The vulnerability is in a route decorated with @login_required, indicating it's accessible to authenticated users. 10.
Reviewing the EmbeddingModel, ChatModel, RerankModel, CvModel, and TTSModel dictionaries to understand their contents and potential for exploitation.
----------------------------------------

analysis:
  The add_llm function in llm_app.py contains a critical Remote Code Execution (RCE) vulnerability. The function uses user-supplied input 
(req['llm_factory'] and req['llm_name']) to dynamically instantiate classes from the EmbeddingModel, ChatModel, RerankModel, CvModel, and TTSModel 
dictionaries. This pattern of using user input as a key to access and instantiate classes is inherently dangerous, as it allows an attacker to 
potentially execute arbitrary code. The vulnerability is exacerbated by the lack of comprehensive input validation or sanitization on these 
user-supplied values. While there are some checks for specific factory types, they are not exhaustive and can be bypassed. An attacker could potentially
provide a malicious value for 'llm_factory' that, when used as an index to these model dictionaries, results in the execution of arbitrary code. The 
vulnerability is particularly severe because it occurs in a route decorated with @login_required, suggesting it's accessible to authenticated users, 
which might give a false sense of security.
----------------------------------------

poc:
  POST /add_llm HTTP/1.1
  Host: target.com
  Content-Type: application/json
  Authorization: Bearer <valid_token>
  
  {
      "llm_factory": "__import__('os').system",
      "llm_name": "id",
      "model_type": "EMBEDDING",
      "api_key": "dummy_key"
  }
  
  This payload attempts to exploit the vulnerability by setting 'llm_factory' to a string that, when evaluated, imports the os module and calls system. 
The 'llm_name' is set to 'id', which would be executed as a system command if the exploit is successful.
----------------------------------------

confidence_score:
  8
----------------------------------------

vulnerability_types:
  - RCE
----------------------------------------
```
</details>

## Authors
xvulnhuntr fork:
- Nicolò Fornari [@rationalpsyche](https://bsky.app/profile/rationalpsyche.bsky.social)

vulnhuntr:
- Dan McInerney: dan@protectai.com, [@DanHMcinerney](https://x.com/DanHMcInerney)
- Marcello Salvati: marcello@protectai.com, [@byt3bl33d3r](https://x.com/byt3bl33d3r)
