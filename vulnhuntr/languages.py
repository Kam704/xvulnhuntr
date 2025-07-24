import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, Generator, List

from vulnhuntr.enums import *
from vulnhuntr.symbol_finder import SymbolExtractor
from vulnhuntr.utils import get_absolute_path

logger = logging.getLogger("xvulnhuntr")

class BaseRepoOps:

    binary_dir = ""
    binary_path = ""
    relevant_target_files = None

    def __init__(self, langtype: LanguageType,repo_path: Path | str ) -> None:
        self.langtype = langtype
        self.repo_path = Path(repo_path)

    def check_code_extractor_compiled(self):
        if not os.path.isfile(get_absolute_path(self.binary_path)):
            logger.error(f"{self.binary_path} is missing, likely not compiled. Follow README")
            sys.exit(1)

    def get_readme_content(self) -> str:
        # Use glob to find README.md or README.rst in a case-insensitive manner in the root directory
        prioritized_patterns = ["[Rr][Ee][Aa][Dd][Mm][Ee].[Mm][Dd]", "[Rr][Ee][Aa][Dd][Mm][Ee].[Rr][Ss][Tt]"]
        
        search_paths = [self.repo_path, self.repo_path / ".github"]

        for search_path in search_paths:
            # First, look for README.md or README.rst in the root directory with case insensitivity
            for pattern in prioritized_patterns:
                for readme in search_path.glob(pattern):
                    with readme.open(encoding='utf-8') as f:
                        return f.read()
        for search_path in search_paths: 
            # If no README.md or README.rst is found, look for any README file with supported extensions
            for readme in search_path.glob("[Rr][Ee][Aa][Dd][Mm][Ee]*.[Mm][DdRrSsTt]"):
                with readme.open(encoding='utf-8') as f:
                    return f.read()
        
        return

    def get_relevant_target_files(self) -> Generator[Path, None, None]:
        """Gets all files for <langtype> in a repo minus the ones in the exclude list (test, example, doc, docs)"""
        files = []
        for f in self.repo_path.rglob(f"*.{languageExtensions[self.langtype]}"):
            # Convert the path to a string with forward slashes
            f_str = str(f).replace('\\', '/')
            
            # Lowercase the string for case-insensitive matching
            f_str = f_str.lower()

            # Check if any exclusion pattern matches a substring of the full path
            if any(exclude in f_str for exclude in self.to_exclude):
                continue

            # Check if the file name should be excluded
            if any(fn in f.name for fn in self.file_names_to_exclude):
                continue
            
            files.append(f)

        self.relevant_target_files = files
        return files

    def get_files_to_analyze(self, analyze_path: Path | None = None) -> List[Path]:
        path_to_analyze = analyze_path or self.repo_path
        if path_to_analyze.is_file():
            return [ path_to_analyze ]
        elif path_to_analyze.is_dir():
            return [ p for p in path_to_analyze.rglob(f"*.{languageExtensions[self.langtype]}") if not p.name.endswith("test.go") ] # exclude go tests
        else:
            raise FileNotFoundError(f"Specified analyze path does not exist: {path_to_analyze}")

    def get_network_related_files(self, files: List) -> Generator[Path, None, None]:
        logger.debug(f"Analyze {self.repo_path} for network related files based on regex:")
        for target_f in files:
            with target_f.open(encoding='utf-8') as f:
                content = f.read()
            if any(re.search(pattern, content) for pattern in self.compiled_patterns):
                logger.debug(f"Match: {target_f}")
                yield target_f

    # for each programming language, execute the corresponding standalone binary
    # providing function/class name and repo path
    # a json with the matching file name and extracted code block is returned
    def extract(self, cmdline: list, symbol_name: str, config) -> Dict:
        if config["verbosity"] > 1:
            logger.debug(cmdline)
        try:
            if self.binary_dir != "":
                result = subprocess.run(cmdline,cwd=self.binary_dir,capture_output=True, text=True, check=True)
            else:
                result = subprocess.run(cmdline,capture_output=True, text=True, check=True)
            if config["verbosity"] > 1:
                logger.debug(result.stdout)
            extractedCodeObj = json.loads(result.stdout)
            extractedCode = extractedCodeObj.get("source")
            extractedFilePath = extractedCodeObj.get("filepath")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running binary (stderr): {e.stderr.strip()}")
            logger.error(f"Error running binary (stdout): {e.stdout.strip()}")
            sys.exit(1)

        return {'name': symbol_name,
                'context_name_requested': symbol_name,
                'file_path': extractedFilePath,
                'source':extractedCode}

class JavaRepoOps(BaseRepoOps):

    # path to the code extractor utility is hardcoded here, there is no point exposing it to the end user
    code_extractor_cmdline = ["mvn","-q","exec:java","-Dexec.mainClass=com.codeextractor.JavaCodeExtractor"]
    binary_dir = "codeExtractor/java/" # subprocess.run will use this as cwd to find pom.xml

    def get_code_extractor_cmdline(self, symbol_name: str):
        cmdline = []
        for param in self.code_extractor_cmdline:
            cmdline.append(param)
        cmdline.append(f"-Dexec.args={self.repo_path} {symbol_name}")
        return cmdline

    def __init__(self,langtype: LanguageType,repo_path: Path | str):
        super().__init__(langtype, repo_path)
        self.to_exclude = {'/pom.xml', '/example', '/docs'} # /test should be added again BUT handling that targets are within a test folder
        self.file_names_to_exclude = ['test_', 'conftest']
        
        # IMPORTANT: the list below comes straight from ChatGPT as the author does not have C# specific expertise
        self.patterns = [
            # Spring Boot - Identifying REST API Endpoints
            r'@GetMapping\(".*?"\)',
            r'@PostMapping\(".*?"\)',
            r'@PutMapping\(".*?"\)',
            r'@DeleteMapping\(".*?"\)',
            r'@PatchMapping\(".*?"\)',
            r'@RequestMapping\(".*?"\)',
            r'@RestController',
            r'public\s+(ResponseEntity<\w+>|void|\w+)\s+\w+\(.*?\)\s*\{',

            # Jakarta EE (JAX-RS) - Identifying REST API Endpoints
            r'@Path\(".*?"\)',
            r'@GET',
            r'@POST',
            r'@PUT',
            r'@DELETE',
            r'@PATCH',
            r'@Produces\(".*?"\)',
            r'@Consumes\(".*?"\)',
            r'public\s+(Response|ResponseEntity<\w+>|void|\w+)\s+\w+\(.*?\)\s*\{',

            # gRPC (Java)
            r'public\s+class\s+\w+\s+extends\s+\w+Grpc\.\w+ImplBase',
            r'public\s+void\s+\w+\(\w+Request\s+\w+,.*?StreamObserver<\w+Response>\s+\w+\)',

            # WebSocket (Spring Boot and Java EE)
            r'@ServerEndpoint\(".*?"\)',
            r'public\s+class\s+\w+\s+implements\s+WebSocket',
            r'@OnMessage',
            r'@OnOpen',
            r'@OnClose',
            r'@OnError',
            
            # Micronaut - Identifying API Endpoints
            r'@Controller\(".*?"\)',
            r'@Get\(".*?"\)',
            r'@Post\(".*?"\)',
            r'@Put\(".*?"\)',
            r'@Delete\(".*?"\)',
            r'@Patch\(".*?"\)'
        ]

        self.compiled_patterns = [re.compile(pattern) for pattern in self.patterns]

class CSharpRepoOps(BaseRepoOps):

    # path to the code extractor utility is hardcoded here, there is no point exposing it to the end user
    code_extractor_cmdline = ["codeExtractor/c#/bin/Debug/net9.0/codeExtractor"]
    binary_path = "codeExtractor/c#/bin/Debug/net9.0/codeExtractor"

    def get_code_extractor_cmdline(self, symbol_name: str):
        cmdline = []
        for param in self.code_extractor_cmdline:
            cmdline.append(param)
        cmdline.append(self.repo_path)
        cmdline.append(symbol_name)
        return cmdline

    def __init__(self,langtype: LanguageType,repo_path: Path | str):
        super().__init__(langtype, repo_path)
        self.check_code_extractor_compiled()
        self.to_exclude = {'/.csproj', '/example', '/docs'} # /test should be added again BUT handling that targets are within a test folder
        self.file_names_to_exclude = ['test_', 'conftest']
        
        # IMPORTANT: the list below comes straight from ChatGPT as the author does not have C# specific expertise
        self.patterns = [
            # ASP.NET Core MVC - Identifying Controller Actions
            r'\[Http(Get|Post|Put|Delete|Patch)\]\s*',
            r'public\s+(async\s+)?Task<\w+>\s+\w+\(.*?HttpRequest',
            r'public\s+(async\s+)?Task<IActionResult>\s+\w+\(.*?\)',

            # Minimal APIs (ASP.NET Core 6+)
            r'\.Map(Get|Post|Put|Delete|Patch)\(.*?,\s*async?\s*\(',

            # Web API Route Attributes
            r'\[Route\(".*?"\)\]',
            r'\[ApiController\]',

            # SignalR
            r'public\s+class\s+\w+\s*:\s*Hub',
            r'public\s+Task\s+\w+\(.*?Clients\.Caller',

            # gRPC
            r'public\s+class\s+\w+\s*:\s*\w+Base',
            r'public\s+override\s+Task<\w+>\s+\w+\(.*?ServerCallContext'
            ]

        self.compiled_patterns = [re.compile(pattern) for pattern in self.patterns]

class GoRepoOps(BaseRepoOps):

    # path to the code extractor utility is hardcoded here, there is no point exposing it to the end user
    code_extractor_cmdline = ["codeExtractor/go/codeExtractor"]
    binary_path = "codeExtractor/go/codeExtractor" 

    def get_code_extractor_cmdline(self, symbol_name: str):
        cmdline = []
        for param in self.code_extractor_cmdline:
            cmdline.append(param)
        cmdline.append(self.repo_path)
        cmdline.append(symbol_name)
        return cmdline

    def __init__(self,langtype: LanguageType,repo_path: Path | str):
        super().__init__(langtype, repo_path)
        self.check_code_extractor_compiled()
        self.to_exclude = {'/example', '/docs'} # /test should be added again BUT handling that targets are within a test folder
        self.file_names_to_exclude = ['test_', 'conftest']
        
        # IMPORTANT: the list below comes straight from ChatGPT as the author does not have go lang specific expertise
        self.patterns = [
            # Standard net/http - Function handlers
            r'http\.HandleFunc\(".*?",\s*\w+\)',  
            r'http\.Handle\(".*?",\s*\w+\)',  
            r'http\.ListenAndServe\(".*?",\s*\w+\)',

            # Gin framework
            r'router\.(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(".*?",\s*\w+\)',  
            r'engine\.(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(".*?",\s*\w+\)',  

            # Echo framework
            r'e\.(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(".*?",\s*\w+\)',  
            r'echo\.New\(\)\.(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(".*?",\s*\w+\)',  

            # Fiber framework
            r'app\.(?:Get|Post|Put|Delete|Patch|Options|Head)\(".*?",\s*\w+\)',  
            r'fiber\.New\(\)\.(?:Get|Post|Put|Delete|Patch|Options|Head)\(".*?",\s*\w+\)',  

            # Chi framework
            r'r\.Route\(".*?",\s*func\(r\s+\w+\)\s*{',
            r'r\.(?:Get|Post|Put|Delete|Patch|Options|Head)\(".*?",\s*\w+\)',  
        ]

        self.compiled_patterns = [re.compile(pattern) for pattern in self.patterns]

class PythonRepoOps(BaseRepoOps):
    def __init__(self,langtype: LanguageType,repo_path: Path | str):
        super().__init__(langtype, repo_path)
        self.to_exclude = {'/setup.py', '/example', '/docs', '/site-packages', '.venv', 'virtualenv', '/dist'} # /test should be added again BUT handling that targets are within a test folder
        self.file_names_to_exclude = ['test_', 'conftest', '_test.py']
        self.code_extractor = SymbolExtractor(self.repo_path)

        patterns = [
            #Async
            r'async\sdef\s\w+\(.*?request',

            # Gradio
            r'gr.Interface\(.*?\)',
            r'gr.Interface\.launch\(.*?\)',

            # Flask
            r'@app\.route\(.*?\)',
            r'@blueprint\.route\(.*?\)',
            r'class\s+\w+\(MethodView\):',
            r'@(?:app|blueprint)\.add_url_rule\(.*?\)',

            # FastAPI
            r'@app\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)',
            r'@router\.(?:get|post|put|delete|patch|options|head|trace)\(.*?\)',

            # Django
            r'url\(.*?\)', #Too broad?
            r're_path\(.*?\)',
            r'@channel_layer\.group_add',
            r'@database_sync_to_async',

            # Pyramid
            r'@view_config\(.*?\)',

            # Bottle
            r'@(?:route|get|post|put|delete|patch)\(.*?\)',

            # Tornado
            r'class\s+\w+\((?:RequestHandler|WebSocketHandler)\):',
            r'@tornado\.gen\.coroutine',
            r'@tornado\.web\.asynchronous',

            #WebSockets
            r'websockets\.serve\(.*?\)',
            r'@websocket\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',

            # aiohttp
            r'app\.router\.add_(?:get|post|put|delete|patch|head|options)\(.*?\)',
            r'@routes\.(?:get|post|put|delete|patch|head|options)\(.*?\)',

            # Sanic
            r'@app\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',
            r'@blueprint\.(?:route|get|post|put|delete|patch|head|options)\(.*?\)',

            # Falcon
            r'app\.add_route\(.*?\)',

            # CherryPy
            r'@cherrypy\.expose',

            # web2py
            r'def\s+\w+\(\):\s*return\s+dict\(',

            # Quart (ASGI version of Flask)
            r'@app\.route\(.*?\)',
            r'@blueprint\.route\(.*?\)',

            # Starlette (which FastAPI is based on)
            r'@app\.route\(.*?\)',
            r'Route\(.*?\)',

            # Responder
            r'@api\.route\(.*?\)',

            # Hug
            r'@hug\.(?:get|post|put|delete|patch|options|head)\(.*?\)',

            # Dash (for analytical web applications)
            r'@app\.callback\(.*?\)',

            # GraphQL entry points
            r'class\s+\w+\(graphene\.ObjectType\):',
            r'@strawberry\.type',

            # Generic decorators that might indicate custom routing
            r'@route\(.*?\)',
            r'@endpoint\(.*?\)',
            r'@api\.\w+\(.*?\)',

            # AWS Lambda handlers (which could be used with API Gateway)
            r'def\s+lambda_handler\(event,\s*context\):',
            r'def\s+handler\(event,\s*context\):',

            # Azure Functions
            r'def\s+\w+\(req:\s*func\.HttpRequest\)\s*->',

            # Google Cloud Functions
            r'def\s+\w+\(request\):'

            # Server startup code
            r'app\.run\(.*?\)',
            r'serve\(app,.*?\)',
            r'uvicorn\.run\(.*?\)',
            r'application\.listen\(.*?\)',
            r'run_server\(.*?\)',
            r'server\.start\(.*?\)',
            r'app\.listen\(.*?\)',
            r'httpd\.serve_forever\(.*?\)',
            r'tornado\.ioloop\.IOLoop\.current\(\)\.start\(\)',
            r'asyncio\.run\(.*?\.serve\(.*?\)\)',
            r'web\.run_app\(.*?\)',
            r'WSGIServer\(.*?\)\.serve_forever\(\)',
            r'make_server\(.*?\)\.serve_forever\(\)',
            r'cherrypy\.quickstart\(.*?\)',
            r'execute_from_command_line\(.*?\)',  # Django's manage.py
            r'gunicorn\.app\.wsgiapp\.run\(\)',
            r'waitress\.serve\(.*?\)',
            r'hypercorn\.run\(.*?\)',
            r'daphne\.run\(.*?\)',
            r'werkzeug\.serving\.run_simple\(.*?\)',
            r'gevent\.pywsgi\.WSGIServer\(.*?\)\.serve_forever\(\)',
            r'grpc\.server\(.*?\)\.start\(\)',
            r'app\.start_server\(.*?\)',  # Sanic
            r'Server\(.*?\)\.run\(\)',    # Bottle
        ]

        # Compile the patterns for efficiency
        self.compiled_patterns = [re.compile(pattern) for pattern in patterns]