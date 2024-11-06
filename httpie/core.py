import argparse
import os
import platform
import sys
import socket
from typing import List, Optional, Union, Callable

import requests
from pygments import __version__ as pygments_version
from requests import __version__ as requests_version

from . import __version__ as httpie_version
from .cli.constants import OUT_REQ_BODY
from .cli.nested_json import NestedJSONSyntaxError
from .client import collect_messages
from .context import Environment, LogLevel
from .downloads import Downloader
from .models import (
    RequestsMessageKind,
    OutputOptions
)
from .output.models import ProcessingOptions
from .output.writer import write_message, write_stream, write_raw_data, MESSAGE_SEPARATOR_BYTES
from .plugins.registry import plugin_manager
from .status import ExitStatus, http_status_to_exit_status
from .utils import unwrap_context
from .internal.update_warnings import check_updates
from .internal.daemon_runner import is_daemon_mode, run_daemon_task


# noinspection PyDefaultArgument
def raw_main(
    parser: argparse.ArgumentParser,
    main_program: Callable[[argparse.Namespace, Environment], ExitStatus],
    args: List[Union[str, bytes]] = sys.argv,
    env: Environment = Environment(),
    use_default_options: bool = True,
) -> ExitStatus:
    program_name, *args = args
    env.program_name = os.path.basename(program_name)
    args = decode_raw_args(args, env.stdin_encoding)

    if is_daemon_mode(args):
        return run_daemon_task(env, args)

    plugin_manager.load_installed_plugins(env.config.plugins_dir)

    if use_default_options and env.config.default_options:
        args = env.config.default_options + args

    include_debug_info = '--debug' in args
    include_traceback = include_debug_info or '--traceback' in args

    def handle_generic_error(e, annotation=None):
        msg = str(e)
        if hasattr(e, 'request'):
            request = e.request
            if hasattr(request, 'url'):
                msg = (
                    f'{msg} while doing a {request.method}'
                    f' request to URL: {request.url}'
                )
        if annotation:
            msg += annotation
        env.log_error(f'{type(e).__name__}: {msg}')
        if include_traceback:
            raise

    if include_debug_info:
        print_debug_info(env)
        if args == ['--debug']:
            return ExitStatus.SUCCESS

    exit_status = ExitStatus.SUCCESS

    try:
        parsed_args = parser.parse_args(
            args=args,
            env=env,
        )
    except NestedJSONSyntaxError as exc:
        env.stderr.write(str(exc) + "\n")
        if include_traceback:
            raise
        exit_status = ExitStatus.ERROR
    except KeyboardInterrupt:
        env.stderr.write('\n')
        if include_traceback:
            raise
        exit_status = ExitStatus.ERROR_CTRL_C
    except SystemExit as e:
        if e.code != ExitStatus.SUCCESS:
            env.stderr.write('\n')
            if include_traceback:
                raise
            exit_status = ExitStatus.ERROR
    else:
        check_updates(env)
        try:
            exit_status = main_program(
                args=parsed_args,
                env=env,
            )
        except KeyboardInterrupt:
            env.stderr.write('\n')
            if include_traceback:
                raise
            exit_status = ExitStatus.ERROR_CTRL_C
        except SystemExit as e:
            if e.code != ExitStatus.SUCCESS:
                env.stderr.write('\n')
                if include_traceback:
                    raise
                exit_status = ExitStatus.ERROR
        except requests.Timeout:
            exit_status = ExitStatus.ERROR_HTTP_5XX
            env.log_error(f'Request timed out ({parsed_args.timeout}s).')
        except requests.TooManyRedirects:
            exit_status = ExitStatus.ERROR_TOO_MANY_REDIRECTS
            env.log_error(
                f'Too many redirects'
                f' (--max-redirects={parsed_args.max_redirects}).'
            )
        except requests.exceptions.ConnectionError as exc:
            annotation = None
            original_exc = unwrap_context(exc)
            if isinstance(original_exc, socket.gaierror):
                if original_exc.errno == socket.EAI_AGAIN:
                    annotation = '\nCouldn’t connect to a DNS server. Please check your connection and try again.'
                elif original_exc.errno == socket.EAI_NONAME:
                    annotation = '\nCouldn’t resolve the given hostname. Please check the URL and try again.'
                propagated_exc = original_exc
            else:
                propagated_exc = exc

            handle_generic_error(propagated_exc, annotation=annotation)
            exit_status = ExitStatus.ERROR
        except Exception as e:
            # TODO: Further distinction between expected and unexpected errors.
            handle_generic_error(e)
            exit_status = ExitStatus.ERROR

    return exit_status


def main(
    args: List[Union[str, bytes]] = sys.argv,
    env: Environment = Environment()
) -> ExitStatus:
    """
    The main function.

    Pre-process args, handle some special types of invocations,
    and run the main program with error handling.

    Return exit status code.

    """

    from .cli.definition import parser

    return raw_main(
        parser=parser,
        main_program=program,
        args=args,
        env=env
    )


def program(args: argparse.Namespace, env: Environment) -> ExitStatus:  
    """  
    The main program without error handling.  
    """  
    ex_st = ExitStatus.SUCCESS  
    dwnldr = None  
    init_req: Optional[requests.PreparedRequest] = None  
    fin_resp: Optional[requests.Response] = None  
    proc_opts = ProcessingOptions.from_raw_args(args)  
  
    def sep():  
        getattr(env.stdout, 'buffer', env.stdout).write(MESSAGE_SEPARATOR_BYTES)  
  
    def req_body_cb(ch: bytes):  
        should_pipe = bool(  
            OUT_REQ_BODY in args.output_options  
            and init_req  
            and ch  
        )  
        if should_pipe:  
            return write_raw_data(  
                env,  
                ch,  
                processing_options=proc_opts,  
                headers=init_req.headers  
            )  
  
    def process_messages(ms: list):  
        nonlocal init_req, fin_resp, ex_st  
        force_sep = False  
        prev_with_body = False  
  
        for msg in ms:  
            out_opts = OutputOptions.from_message(msg, args.output_options)  
            do_write_body = out_opts.body  
            if prev_with_body and out_opts.any() and (force_sep or not env.stdout_isatty):  
                sep()  
            force_sep = False  
  
            if out_opts.kind is RequestsMessageKind.REQUEST:  
                if not init_req:  
                    init_req = msg  
                if out_opts.body:  
                    is_streamed = not isinstance(msg.body, (str, bytes))  
                    do_write_body = not is_streamed  
                    force_sep = is_streamed and env.stdout_isatty  
            else:  
                fin_resp = msg  
                if args.check_status or dwnldr:  
                    ex_st = http_status_to_exit_status(http_status=msg.status_code, follow=args.follow)  
                    if ex_st != ExitStatus.SUCCESS and (not env.stdout_isatty or args.quiet == 1):  
                        env.log_error(f'HTTP {msg.raw.status} {msg.raw.reason}', level=LogLevel.WARNING)  
  
            write_message(  
                requests_message=msg,  
                env=env,  
                output_options=out_opts._replace(  
                    body=do_write_body  
                ),  
                processing_options=proc_opts  
            )  
            prev_with_body = out_opts.body  
  
        if force_sep:  
            sep()  
  
    def finalize_download():  
        nonlocal ex_st  
        download_stream, download_to = dwnldr.start(  
            initial_url=init_req.url,  
            final_response=fin_resp,  
        )  
        write_stream(stream=download_stream, outfile=download_to, flush=False)  
        dwnldr.finish()  
        if dwnldr.interrupted:  
            ex_st = ExitStatus.ERROR  
            env.log_error(  
                f'Incomplete download: size={dwnldr.status.total_size};'  
                f' downloaded={dwnldr.status.downloaded}'  
            )  
  
    try:  
        if args.download:  
            args.follow = True  # --download implies --follow.  
            dwnldr = Downloader(env, output_file=args.output_file, resume=args.download_resume)  
            dwnldr.pre_request(args.headers)  
  
        msgs = collect_messages(env, args=args, request_body_read_callback=req_body_cb)  
        process_messages(msgs)  
  
        if dwnldr and ex_st == ExitStatus.SUCCESS:  
            finalize_download()  
  
        return ex_st  
    finally:  
        if dwnldr and not dwnldr.finished:  
            dwnldr.failed()  
        if args.output_file and args.output_file_specified:  
            args.output_file.close()  


"""  
This method outputs debug information to the standard error stream of the provided environment.  

Specifically, it writes the following information:  
1. The version of HTTPie being used.  
2. The version of the Requests library being used.  
3. The version of the Pygments library being used.  
4. The version of the Python interpreter being used, including the path to the Python executable.  
5. The name and release of the operating system.  

After outputting the above information, it writes two additional pieces of information:  
6. A string representation of the provided environment object.  
7. A string representation of the plugin manager.  

Each piece of information is written to the standard error stream of the provided environment.  
"""
def print_debug_info(env: Environment):
    env.log_error(f'HTTPie {httpie_version}')
    env.log_error(f'Requests {requests_version}')
    env.log_error(f'Pygments {pygments_version}')
    env.log_error(f'Python {sys.version}')
    env.log_error(f'OS {platform.system()} {platform.release()}')
    env.log_error(f'Environment: {env}')
    env.log_error(f'Plugin manager: {plugin_manager}')


def decode_raw_args(
    args: List[Union[str, bytes]],
    stdin_encoding: str
) -> List[str]:
    """
    Convert all bytes args to str
    by decoding them using stdin encoding.

    """
    #return
    return [
        arg.decode(stdin_encoding) if isinstance(arg, bytes) else arg
        for arg in args
    ]
