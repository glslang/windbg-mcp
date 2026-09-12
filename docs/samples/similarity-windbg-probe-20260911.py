"""Disposable BN Personal -> external BinDiff -> WinDbg ARM64 acceptance."""
if not __debug__:
    raise RuntimeError('acceptance probes require assertions enabled; do not use -O or -OO')

import asyncio
import json
import threading
import time
import traceback
from pathlib import Path

ROOT = Path('/private/tmp/bn-windbg-handoff-20260911')


async def call_tool(client, name, args=None, *, report, save, label=None, require_ok=True):
    """Retain this probe's launch handle before recording or validating the response."""
    response = await client.call_tool(name, args or {})
    data = response.structured_content
    if name == 'launch' and isinstance(data, dict):
        opened = data if data.get('status') == 'ok' else (
            data.get('error') if data.get('target') in ('yes', 'pending') else None)
        session = opened.get('session_id') if isinstance(opened, dict) else None
        if isinstance(session, str) and session:
            report['owned_session'] = session
    report['calls'][label or name] = {'is_error': response.is_error, 'data': data,
        'text': [c.text for c in response.content if hasattr(c, 'text')] if data is None else []}
    save()
    if require_ok:
        assert not response.is_error and isinstance(data, dict), name
        assert data.get('status') not in ('error', 'unavailable', 'uncertain'), (name, data)
    return data


async def cleanup_debugger(call, local, remote, comparison, session, initial, report):
    """Attempt each release independently; leave an active capture exception intact."""
    report['session_inventory_restored'] = False
    actions = [(local, 'unpair_windbg', {})]
    if comparison:
        actions.append((local, 'similarity_close', {'comparison_id': comparison}))
    if session:
        actions.append((remote, 'end_session', {'session_id': session}))
    actions.append((remote, 'session_status', {}))
    for client, name, args in actions:
        try:
            if name == 'session_status':
                final = await call(client, name, args, label='sessions_after')
                before_ids = sorted(item['session_id'] for item in initial['sessions'])
                after_ids = sorted(item['session_id'] for item in final['sessions'])
                if after_ids != before_ids:
                    raise ValueError('session inventory was not restored')
                report['session_inventory_restored'] = True
            else:
                await call(client, name, args)
        except Exception:
            report['ok'] = False
            report.setdefault('cleanup_errors', []).append(
                {'stage': name, 'error': traceback.format_exc()})


def finish_gui(plugin, FileContext, application, ui_context, report, save):
    """Attempt each cleanup stage without bypassing the guarded application Quit."""
    def attempt(stage, action):
        try:
            action()
        except Exception:
            report['ok'] = False
            report.setdefault('cleanup_errors', []).append(
                {'stage': stage, 'error': traceback.format_exc()})

    def listener_state():
        report['listener_thread_alive_after_shutdown'] = plugin.listener.thread.is_alive()
        if report['listener_thread_alive_after_shutdown']:
            raise RuntimeError('listener thread survived shutdown')

    def clear_modified():
        for context in FileContext.getOpenFileContexts():
            for view in context.getAllDataViews():
                view.file.modified = False

    def quitting():
        report['application_about_to_quit'] = True
        attempt('save', save)

    def request_quit():
        handler = ui_context().getCurrentActionHandler()
        assert handler.isValidAction('Quit')
        handler.executeAction('Quit')

    attempt('save', save)
    if plugin:
        attempt('plugin_shutdown', plugin.shutdown)
        attempt('listener_state', listener_state)
    attempt('clear_modified', clear_modified)
    attempt('quit_hook', lambda: application.aboutToQuit.connect(quitting))
    attempt('save', save)
    attempt('quit', request_quit)
    attempt('save', save)


def run():
    import binaryninja as bn
    from binaryninjaui import FileContext, UIContext
    from PySide6.QtWidgets import QApplication
    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.bootstrap import Plugin
    from binja_windbg_mcp.profiles import Profiles
    from binja_windbg_mcp.server import Listener
    report = {'ok': False, 'bn_version': bn.core_version(), 'calls': {}}
    plugin = None
    def save():
        (ROOT / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    def context():
        assert QApplication.instance().activeModalWidget() is None
        ctx, = UIContext.allContexts()
        return ctx
    async def exercise(workspace, listener, profiles, ids):
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client
        private = json.loads((ROOT/'windbg-private.json').read_text(encoding='utf-8-sig'))
        async def call(client, name, args=None, **kwargs):
            return await call_tool(client, name, args, report=report, save=save, **kwargs)
        async with httpx2.AsyncClient(headers={'Authorization':'Bearer '+private['token']}, trust_env=False) as remote_http:
            async with Client(streamable_http_client(private['url'], http_client=remote_http), read_timeout_seconds=90) as remote:
                initial = await call(remote, 'session_status', label='sessions_before')
                assert len(initial['sessions']) < initial['max_sessions']
                async with httpx2.AsyncClient(headers={'Authorization':'Bearer '+profiles.token}, trust_env=False) as local_http:
                    async with Client(streamable_http_client(f'http://127.0.0.1:{listener.port}/mcp', http_client=local_http), read_timeout_seconds=90) as local:
                        comparison = None
                        try:
                            start = await call(local,'similarity_start',{'reference_binary_id':ids['reference'],'target_binary_id':ids['target'],'backend':'external'})
                            comparison = start['comparison_id']
                            deadline = time.monotonic() + 90
                            while True:
                                status = await call(local,'similarity_status',{'comparison_id':comparison})
                                if not status['active']: break
                                assert time.monotonic() < deadline
                                await asyncio.sleep(.1)
                            assert status['state'] == 'completed', status
                            results = await call(local,'similarity_results',{'comparison_id':comparison})
                            report['result_keys'] = list(results)
                            save()
                            matches = results['items']
                            step = next(m for m in matches if m['target']['name'] == 'probe_step')
                            finish = next(m for m in matches if m['target']['name'] == 'probe_finish')
                            report['chosen_match'] = step
                            await call(local,'similarity_diff',{'comparison_id':comparison,'result_id':step['result_id']})
                            launch = await call(remote,'launch',{'command_line':r'C:\workspace\bn-windbg-handoff-20260911\target\handoff_probe.exe'})
                            session = launch['session_id']
                            modules = await call(remote,'modules',{'session_id':session,'limit':1024})
                            module, = [m for m in modules['modules'] if m['name'].lower() == 'handoff_probe']
                            report['loaded_module'] = module
                            endpoint = step['target']
                            navigation = {'binary_id':endpoint['binary_id'], 'coordinate':endpoint['coordinate'], 'expected_generation':endpoint['generation']}
                            await call(local,'navigate',navigation,label='navigate_step')
                            await call(local,'pair_windbg',{'profile':'handoff','session_id':session,'binary_id':ids['target'],'poll_interval_ms':5000})
                            compare = await call(local,'compare_runtime_bytes',{'size':16})
                            report['runtime_comparison'] = compare
                            assert compare['equal'] and not compare['incomplete']
                            assert compare['runtime_read_size'] == compare['static_read_size'] == 16
                            assert compare['coordinate']['rva'] == endpoint['coordinate']['rva']
                            # The previous build's coordinate must fail all guarded operations.
                            before = await call(remote,'current_location',{'session_id':session},label='before_wrong_build')
                            wrong = dict(step['reference']['coordinate'],module=module['name'],image_name='handoff_probe.exe')
                            for tool in ('read_memory','set_breakpoint','run_to_address'):
                                args = {'session_id':session,'coordinate':wrong}
                                if tool == 'read_memory': args['size']=16
                                if tool == 'run_to_address': args['timeout_ms']=1000
                                refusal = await call(remote,tool,args,label='wrong_build_'+tool,require_ok=False)
                                assert refusal['status']=='error', refusal
                                assert refusal['error']['category'] == 'debugger', refusal
                                assert refusal['error']['message'] == 'coordinate PE identity mismatch', refusal
                            after = await call(remote,'current_location',{'session_id':session},label='after_wrong_build')
                            assert before['address']==after['address']
                            report['wrong_build_preserved_ip'] = True
                            # Resume only our harmless fixture, stopping at the chosen match.
                            await call(local,'navigate',navigation,label='navigate_before_run_to')
                            run_to = await call(local,'run_to_here')
                            location = await call(remote,'current_location',{'session_id':session},label='after_run_to')
                            assert int(location['coordinate']['rva'],16)==int(endpoint['coordinate']['rva'],16)
                            report['run_to_reached_match'] = True
                            # A second matched function is reached through a guarded breakpoint.
                            endpoint = finish['target']
                            await call(local,'navigate',{'binary_id':endpoint['binary_id'],'coordinate':endpoint['coordinate'],'expected_generation':endpoint['generation']},label='navigate_finish')
                            await call(local,'set_breakpoint_here')
                            await call(remote,'go',{'session_id':session})
                            location = await call(remote,'current_location',{'session_id':session},label='after_breakpoint')
                            assert int(location['coordinate']['rva'],16)==int(endpoint['coordinate']['rva'],16)
                            report['breakpoint_reached_match'] = True
                            report['ok'] = True
                        finally:
                            await cleanup_debugger(call, local, remote, comparison, report.get('owned_session'), initial, report)
    try:
        main_thread(context)
        for side in ('reference','target'):
            assert main_thread(lambda side=side: context().openFilename(str(ROOT/side/'handoff_probe.exe')))
        workspace=Workspace()
        main_thread(workspace.attach_ui_notifications)
        profiles=Profiles(ROOT/'private-profile')
        private=json.loads((ROOT/'windbg-private.json').read_text(encoding='utf-8-sig'))
        profiles._data['windbg']={'handoff':private}
        profiles._data['similarity']={'bindiff_path':'/private/tmp/binja-bindiff-build/bindiff'}
        listener=Listener(workspace,profiles,port=0)
        plugin=main_thread(lambda:Plugin(bn))
        globals()['retained_plugin']=plugin
        plugin.listener=listener
        main_thread(plugin.attach_shutdown_hooks)
        main_thread(plugin.start)
        deadline=time.monotonic()+15
        while listener.state!='listening':
            assert time.monotonic()<deadline
            time.sleep(.05)
        ids={}
        for item in workspace.list_binaries()['binaries']:
            _,view,_,_=workspace.acquire(item['binary_id'])
            view.update_analysis_and_wait()
            ids[Path(view.file.original_filename).parent.name]=item['binary_id']
        report['inputs']=workspace.list_binaries()['binaries']
        asyncio.run(exercise(workspace,listener,profiles,ids))
    except Exception:
        report['ok']=False
        report['error']=traceback.format_exc()
    finally:
        def finish():
            finish_gui(plugin, FileContext, QApplication.instance(), context, report, save)
        try: main_thread(finish)
        except Exception:
            report['cleanup_error']=traceback.format_exc()
            report['ok']=False
            save()


def start():
    from binaryninjaui import FileContext
    from PySide6.QtWidgets import QApplication
    assert QApplication.instance().activeModalWidget() is None
    assert not FileContext.getOpenFileContexts()
    threading.Thread(target=run,daemon=True).start()
