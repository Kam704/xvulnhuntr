import argparse
import json
import os
import sys
import time
from pathlib import Path

import dotenv
import structlog

from vulnhuntr.data_model import *
from vulnhuntr.enums import *
from vulnhuntr.languages import *
from vulnhuntr.LLMs import initialize_llm
from vulnhuntr.logger import configure_logger, logger
from vulnhuntr.mocks import *
from vulnhuntr.prompts import *
from vulnhuntr.utils import *

dotenv.load_dotenv()

structlog.configure(
    processors=[
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.WriteLoggerFactory(
        file=Path('xvulnhuntr').with_suffix(".log").open("wt")
    )
)

import faulthandler

faulthandler.enable()

log = structlog.get_logger("vulnhuntr")

def parse_params():
    parser = argparse.ArgumentParser(description='Analyze a repository for vulnerabilities. Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running.')
    main_group = parser.add_argument_group('Main parameters')
    main_group.add_argument('-r', '--root', type=str, help='Path to the root directory of the project')
    main_group.add_argument('-a', '--analyze', type=str, help='Specific path or file within the project to analyze')
    main_group.add_argument('--llm', type=str, choices=['claude', 'gpt'], default='claude', help='LLM client to use (default: claude)')
    main_group.add_argument('-l',dest="langtype",type=LanguageType,choices=list(LanguageType), help=f"Programming language. Supported: {', '.join([lang.value for lang in LanguageType])}")
    
    dev_group = parser.add_argument_group('Development parameters')
    dev_group.add_argument('-v', '--verbosity', action='count', default=0, help='Increase output verbosity (-v, -vv)')
    dev_group.add_argument('-i', '--inputprompt', type=str, help='Path to a custom user prompt, only this prompt will be executed')
    dev_group.add_argument('-t', '--test', action="store_true", help='Run test suite using mock api responses')
    dev_group.add_argument('-p', '--proxy', type=str, help='In the form http://127.0.0.1:8080')
    dev_group.add_argument('-c', '--certificate', type=str, help='Path to the proxy CA')
    dev_group.add_argument('-w', '--write', action="store_true", help='Write responses to file (can be reused as tests)')
    
    args = parser.parse_args()

    # it would be nicer to handle required parameters conditionally with mutually exclusive parameters groups
    # but at this stage I rather need more flexibility
    if not args.test:
        if not args.root:
            logger.error("Param --root is required")
            sys.exit(0)
        if not args.langtype:
            logger.error("Param --langtype is required")
            sys.exit(0)

    config = vars(args)

    config["certificate"] = get_absolute_path(config.get("certificate", None))
    config["root"] = get_absolute_path(config.get("root", None))
    config["analyze"] = get_absolute_path(config.get("analyze", None))
    config["inputprompt"] = get_absolute_path(config.get("inputprompt", None))
    # internal parameters, overkill to exposes them to the user
    config["retries"] = 4
    config["sleep_between_retries"] = 10
    config["iterations_in_secondary_analysis"] = 7
    config["reporting"] = True # allows to disable reporting to better debug non-reporting issues

    if args.test:
        for test_config in test_suite:
            config_copy = config.copy()
            config_copy.update(test_config)
            run(args, config_copy)
    else:
        run(args, config)

def readme_summary(repo : BaseRepoOps, config : dict):
    llm = initialize_llm(config=config)

    readme_content = repo.get_readme_content()
    if readme_content:
        log.info("Summarizing project README")
        summary = llm.chat(
            (ReadmeContent(content=readme_content).to_xml() + b'\n' +
            Instructions(instructions=README_SUMMARY_PROMPT_TEMPLATE).to_xml()
            ).decode(),step=PromptStep.SUMMARY, config=config
        )
        summary = extract_between_tags("summary", summary)[0]
        log.info("README summary complete", summary=summary)
    else:
        log.warning("No README summary found")
        summary = ''

    # return system prompt with the README summary
    language_specific_system_prompt = f"You are the world's foremost expert in {config['langtype']} security analysis," + SYS_PROMPT_TEMPLATE
    return (Instructions(instructions=language_specific_system_prompt).to_xml() + b'\n' +
                ReadmeSummary(readme_summary=summary).to_xml()
                ).decode()

def initial_analysis(content, target_f, config: dict):
    return (
            FileCode(file_path=str(target_f), file_source=content).to_xml() + b'\n' +
            Instructions(instructions=INITIAL_ANALYSIS_PROMPT_TEMPLATE).to_xml() + b'\n' +
            AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml() + b'\n' +
            PreviousAnalysis(previous_analysis='').to_xml() + b'\n' +
            Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml() + b'\n' +
            ResponseFormat(response_format=json.dumps(Response.model_json_schema(), indent=4
            )
        ).to_xml()
    ).decode()

def secondary_analysis(config: dict, content, target_f, vuln_type, previous_analysis, definitions, iteration):
    return (
        FileCode(file_path=str(target_f), file_source=content).to_xml() + b'\n' +
        definitions.to_xml() + b'\n' +  # These are all the requested context functions and classes
        ExampleBypasses(
            example_bypasses='\n'.join(VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]['bypasses'])
        ).to_xml() + b'\n' +
        Instructions(instructions=VULN_SPECIFIC_BYPASSES_AND_PROMPTS[vuln_type]['prompt']).to_xml() + b'\n' +
        AnalysisApproach(analysis_approach=ANALYSIS_APPROACH_TEMPLATE).to_xml() + b'\n' +
        PreviousAnalysis(previous_analysis=previous_analysis).to_xml() + b'\n' +
        Guidelines(guidelines=GUIDELINES_TEMPLATE).to_xml() + b'\n' +
        ResponseFormat(
            response_format=json.dumps(
                Response.model_json_schema(), indent=4
            )
        ).to_xml()
    ).decode()

def extract_and_store(config, stored_code_definitions, repo, context_code):
    for context_item in context_code:
        # Make sure bot isn't requesting the same code multiple times

        if context_item.name not in stored_code_definitions:
            name = context_item.name
            code_line = context_item.code_line
            if config["langtype"] == LanguageType.PYTHON:
                match = repo.code_extractor.extract(name, code_line, repo.relevant_target_files)
            else:
                cmdline = repo.get_code_extractor_cmdline(name)
                match = repo.extract(cmdline=cmdline, symbol_name=name, config=config)
            if match:
                stored_code_definitions[name] = match

    return stored_code_definitions 

def run(args,config):

    config["project"] = Path(config["root"]).name
    if args.write:
        write_folder = Path("logs") / config["project"] / str(int(time.time()))
        config["write_folder"] = write_folder # to later access the folder
        os.makedirs(write_folder)

    configure_logger(config["verbosity"])
    if not args.test: # not interested in test config with long mock responses
        logger.debug(config)

    match config["langtype"]:
        case LanguageType.CSHARP:
            repo = CSharpRepoOps(LanguageType.CSHARP, config["root"])
        case LanguageType.JAVA:
            repo = JavaRepoOps(LanguageType.JAVA, config["root"])
        case LanguageType.GO:
            repo = GoRepoOps(LanguageType.GO, config["root"])
        case LanguageType.PYTHON:
            repo = PythonRepoOps(LanguageType.PYTHON, config["root"])

        case _:
            logger.error("Language not supported")
            sys.exit(1)

    if config["inputprompt"]:
        global INITIAL_ANALYSIS_PROMPT_TEMPLATE
        INITIAL_ANALYSIS_PROMPT_TEMPLATE = INITIAL_ANALYSIS_PROMPT_TEMPLATE_ALTERNATE

        global SYS_PROMPT_TEMPLATE
        SYS_PROMPT_TEMPLATE = SYS_PROMPT_TEMPLATE_ALTERNATE
        custom_prompt_file = Path(config["inputprompt"])
        with custom_prompt_file.open("r", encoding="utf-8") as f:
            custom_prompt = f.read()
        global VULN_SPECIFIC_BYPASSES_AND_PROMPTS
        VULN_SPECIFIC_BYPASSES_AND_PROMPTS = {
            "CUSTOM": {
                "prompt": custom_prompt,
                "bypasses": []
            }
        }

    files = repo.get_relevant_target_files()
    if config["analyze"]:
        files_to_analyze = repo.get_files_to_analyze(Path(config["analyze"]))
    else:
        files_to_analyze = repo.get_network_related_files(files)
    
    system_prompt_with_readme = readme_summary(repo, config)
    
    llm = initialize_llm(system_prompt=system_prompt_with_readme, config=config)

    target_file_counter = 0 # used to identify the initial_analysis mock response when running tests 
    for target_f in files_to_analyze:
        log.info(f"Performing initial analysis", file=str(target_f))
        logger.info(f"\nAnalyzing {target_f}")
        logger.info('-' * 40 +'\n')

        with target_f.open(encoding='utf-8') as f:
            content = f.read()
            if not len(content):
                continue

            user_prompt = initial_analysis(content, target_f, config)
            initial_analysis_report: Response = llm.chat(user_prompt, response_model=Response, step=PromptStep.INITIAL_ANALYSIS, config=config, file_iteration_counter=target_file_counter)

            if config["inputprompt"]: # override to process only the vulnerability specified in the user supplied prompt
                initial_analysis_report.vulnerability_types = ["CUSTOM"]

            log.info("Initial analysis complete", report=initial_analysis_report.model_dump())
            print_readable(initial_analysis_report, config)

            # Secondary analysis
            if initial_analysis_report.confidence_score > 0 and len(initial_analysis_report.vulnerability_types):

                for vuln_type in initial_analysis_report.vulnerability_types:

                    # Do not fetch the context code on the first pass of the secondary analysis because the context will be from the general analysis
                    stored_code_definitions = {}
                    definitions = CodeDefinitions(definitions=[])
                    same_context = False

                    # Don't include the initial analysis or the first iteration of the secondary analysis in the user_prompt
                    previous_analysis = ''
                    previous_context_amount = 0

                    for i in range(config["iterations_in_secondary_analysis"]):
                        log.info(f"Performing vuln-specific analysis", iteration=i, vuln_type=vuln_type, file=target_f)

                        # Only lookup context code and previous analysis on second pass and onwards
                        if i > 0:
                            previous_context_amount = len(stored_code_definitions)
                            previous_analysis = secondary_analysis_report.analysis

                            stored_code_definitions = extract_and_store(config=config,
                                                                         stored_code_definitions=stored_code_definitions,
                                                                         repo=repo,
                                                                         context_code=secondary_analysis_report.context_code)
                            code_definitions = list(stored_code_definitions.values())
                            definitions = CodeDefinitions(definitions=code_definitions)

                            print_definitions(definitions=definitions, config=config) 

                        vuln_specific_user_prompt = secondary_analysis(config, content, target_f, vuln_type, previous_analysis, definitions, i)
                        # This is really ugly but there is no room for options
                        # While Java, C# and python work just fine, with Go I experience the LLM returning different code context
                        # for the same request, e.g. repository.BookRepository vs repository.NewBookRepository
                        # The ugly work around is to try repeating the request to the LLM if codeExtractor fails
                        # If you have a better idea you can open an issue
                        for j in range(0,3):
                            secondary_analysis_report: Response = llm.chat(user_prompt=vuln_specific_user_prompt, response_model=Response, step=PromptStep.SECONDARY_ANALYSIS, vulnerability_type=vuln_type, iteration=i, config=config)
                            log.info("Secondary analysis complete", secondary_analysis_report=secondary_analysis_report.model_dump())
                            if config["verbosity"] > 1:
                                logger.debug("As sanity check, extract code definitions")
                            try:
                                # use codeExtractor as sanity check if the LLM provided correct code context
                                # note that the return value is discarded (sanity check only)
                                extract_and_store(config=config,
                                                stored_code_definitions={},
                                                repo=repo,
                                                context_code=secondary_analysis_report.context_code)
                                break # sanity check is fine, thus no need to issue other requests
                            except:
                                logger.debug("Sanity check failed, attempt with another request")
                                j=j+1

                        if config["verbosity"] > 0:
                            print_readable(secondary_analysis_report, config)

                        if not len(secondary_analysis_report.context_code):
                            log.debug("No new context functions or classes found")
                            if config["verbosity"] >= 0:
                                print_readable(secondary_analysis_report, config)
                            break
                        
                        # Check if any new context code is requested
                        if previous_context_amount >= len(stored_code_definitions) and i > 0:
                            # Let it request the same context once, then on the second time it requests the same context, break
                            if same_context:
                                log.debug("No new context functions or classes requested")
                                if config["verbosity"] >= 0:
                                    print_readable(secondary_analysis_report, config)
                                break
                            same_context = True
                            log.debug("No new context functions or classes requested")
                    pass
        target_file_counter=target_file_counter+1
if __name__ == '__main__':
    parse_params()
