"""Opt-in lifecycle acceptance in one empty, disposable BN6 Personal GUI."""

if not __debug__:
    raise RuntimeError('acceptance probes require assertions enabled; do not use -O or -OO')

import asyncio
import json
import socket
import threading
import time
import traceback
from pathlib import Path


def finish_gui(timer, observer, plugin, FileContext, UIContext, application, ui_context, report, save):
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
    if timer:
        attempt('timer_stop', timer.stop)
    if observer:
        attempt('observer_unregister', lambda: UIContext.unregisterNotification(observer))
    if plugin:
        attempt('plugin_shutdown', plugin.shutdown)
        attempt('listener_state', listener_state)
    attempt('clear_modified', clear_modified)
    attempt('quit_hook', lambda: application.aboutToQuit.connect(quitting))
    attempt('save', save)
    attempt('quit', request_quit)
    attempt('save', save)


def run(case, reference, target, bindiff, output):
    import binaryninja as bn
    from binaryninjaui import FileContext, UIContext, UIContextNotification
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    from binja_windbg_mcp.adapter import Workspace, main_thread
    from binja_windbg_mcp.bootstrap import Plugin
    from binja_windbg_mcp.profiles import Profiles
    from binja_windbg_mcp.server import Listener

    output = Path(output)
    report = {'case': case, 'bn_version': bn.core_version(), 'ok': False, 'events': []}
    plugin = None
    captured = []
    heartbeats = []
    observer = None
    timer = None
    job = None
    active_run = None

    def save():
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')

    def wait(predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.01)
        raise TimeoutError('lifecycle condition timed out')

    def ui_context():
        assert QApplication.instance().activeModalWidget() is None, 'modal dialog active'
        context, = UIContext.allContexts()
        return context

    def open_sessions():
        return sorted({v.file.session_id for f in FileContext.getOpenFileContexts()
                       for v in f.getAllDataViews()})

    def resource_state(active):
        p = active.process
        return {'export_thread_alive': bool(active.thread and active.thread.is_alive()),
                'temporary_directory_exists': active.root.exists(),
                'process_created': p is not None,
                'process_returncode': p.process.poll() if p else None,
                'output_reader_alive': p.reader.is_alive() if p else False}

    def assert_clean(active):
        state = resource_state(active)
        assert not state['export_thread_alive'] and not state['temporary_directory_exists']
        assert not state['output_reader_alive']
        assert not state['process_created'] or state['process_returncode'] is not None
        return state

    def selection():
        frame = ui_context().getCurrentViewFrame()
        if frame is None:
            return None
        view = frame.getCurrentBinaryView()
        return {'session_id': view.file.session_id, 'image_base': view.start,
                'offset': frame.getCurrentOffset()}

    async def mcp_status(listener, profiles):
        import httpx2
        from mcp import Client
        from mcp.client.streamable_http import streamable_http_client
        async with httpx2.AsyncClient(headers={'Authorization': 'Bearer ' + profiles.token},
                                     trust_env=False) as http:
            async with Client(streamable_http_client(
                    f'http://127.0.0.1:{listener.port}/mcp', http_client=http)) as client:
                response = await client.call_tool('similarity_status')
                assert not response.is_error
                return response.structured_content

    try:
        main_thread(ui_context)
        for path in (reference, target):
            assert main_thread(lambda path=path: ui_context().openFilename(path))
        workspace = Workspace()
        main_thread(workspace.attach_ui_notifications)
        profiles = Profiles(output / 'private-profile')
        profiles._data['similarity'] = {'bindiff_path': bindiff}
        listener = Listener(workspace, profiles, port=0)
        plugin = main_thread(lambda: Plugin(bn))
        globals()['retained_plugin'] = plugin
        plugin.listener = listener
        main_thread(plugin.attach_shutdown_hooks)
        main_thread(plugin.start)
        wait(lambda: listener.state == 'listening')
        report['mcp_before'] = asyncio.run(mcp_status(listener, profiles))
        ids = {}
        for item in workspace.list_binaries()['binaries']:
            _, view, _, _ = workspace.acquire(item['binary_id'])
            view.update_analysis_and_wait()
            ids[Path(view.file.original_filename).resolve()] = item['binary_id']
        reference_id, target_id = ids[Path(reference).resolve()], ids[Path(target).resolve()]
        _, target_view, _, _ = workspace.acquire(target_id)
        target_session = target_view.file.session_id
        old_base = target_view.start
        old_coordinate = workspace.coordinate(target_view, target_view.entry_point)
        report['inputs'] = workspace.list_binaries()['binaries']
        report['target_session'] = target_session
        report['sessions_before'] = main_thread(open_sessions)

        class Observe(UIContextNotification):
            def record(self, name):
                report['events'].append({'event': name, 'stage': active_run.stage if active_run else None,
                                         'job_done': job.done.is_set() if job else None,
                                         'sessions': open_sessions()})
            def OnAfterCloseFile(self, *args):
                self.record('after_close_file')
            def OnDataViewReplaced(self, *args):
                self.record('data_view_replaced')
            def OnViewReplaced(self, *args):
                self.record('view_replaced')

        observer = Observe()
        main_thread(lambda: UIContext.registerNotification(observer))
        backend = workspace.similarity.backend.backends['external']
        prepare = backend.prepare
        def observe_prepare(*args, **kwargs):
            active = prepare(*args, **kwargs)
            captured.append(active)
            return active
        backend.prepare = observe_prepare
        def start_timer():
            heartbeat = QTimer(QApplication.instance())
            heartbeat.timeout.connect(lambda: heartbeats.append(time.monotonic()))
            heartbeat.start(20)
            return heartbeat
        timer = main_thread(start_timer)
        comparison_id = workspace.similarity.start(reference_id, target_id, backend='external')['comparison_id']
        job = workspace.similarity._jobs[comparison_id]
        active_run = wait(lambda: captured and captured[0])
        stage = 'matching' if case == 'restart' else 'exporting'
        wait(lambda: active_run.stage == stage and active_run.thread.is_alive()
             and (stage != 'matching' or (active_run.process and active_run.process.process.poll() is None)))

        def act():
            context = ui_context()
            report['before_action'] = workspace.similarity.status(comparison_id)
            report['active_resources_before'] = resource_state(active_run)
            report['selection_before'] = selection()
            assert report['before_action']['active'] and active_run.stage == stage
            assert active_run.thread.is_alive()
            save()
            if case == 'restart':
                plugin.stop()
            elif case == 'rebase':
                assert selection()['session_id'] == target_session
                report['rebase_returned'] = context.rebaseCurrentView(old_base + 0x1000000)
                assert report['rebase_returned']
            elif case == 'close_view':
                tab = context.getTabForSessionId(target_session)
                assert tab is not None
                context.closeTab(tab)
            else:
                raise ValueError(case)
        old_listener_thread = listener.thread
        main_thread(act)
        if case == 'close_view':
            wait(lambda: target_session not in main_thread(open_sessions))
            report['sessions_after_close'] = main_thread(open_sessions)
            assert len(report['sessions_after_close']) == len(report['sessions_before']) - 1
            assert any(e['event'] == 'after_close_file' and not e['job_done']
                       for e in report['events'])
        # Do not enumerate Workspace views while waiting: that could mask missed UI notifications.
        wait(job.done.is_set)
        report['job_reason'] = job.reason
        report['job_phase'] = job.phase
        report['resources_after'] = assert_clean(active_run)
        if case in ('rebase', 'close_view'):
            assert job.reason == 'stale', job.reason
            report['results_after'] = workspace.similarity.results(comparison_id, limit=1)
            assert report['results_after']['state'] == 'stale'
            if case == 'rebase':
                report['selection_after_rebase'] = main_thread(selection)
                assert report['selection_after_rebase']['image_base'] == old_base + 0x1000000
            before_navigation = main_thread(selection)
            try:
                workspace.navigate(target_id, old_coordinate,
                                   expected_generation=report['before_action']['snapshots']['target']['generation'])
            except ValueError as error:
                report['stale_navigation_refusal'] = str(error)
                expected = 'view generation changed' if case == 'rebase' else 'unambiguous open PE'
                assert expected in str(error)
            else:
                raise AssertionError('stale navigation accepted')
            assert before_navigation == main_thread(selection)
            report['refused_navigation_preserved_selection'] = True
        else:
            assert job.reason == 'listener_stopped', job.reason
            wait(lambda: not old_listener_thread.is_alive())
            report['stopped_state'] = listener.state
            report['old_comparison_removed'] = comparison_id not in workspace.similarity._jobs
            assert report['old_comparison_removed']
            try:
                with socket.create_connection(('127.0.0.1', listener.port), timeout=.5):
                    raise AssertionError('stopped listener still accepts connections')
            except ConnectionRefusedError:
                report['stopped_port_refused'] = True
            main_thread(plugin.start)
            wait(lambda: listener.state == 'listening')
            report['new_listener_thread'] = listener.thread is not old_listener_thread
            assert report['new_listener_thread']
            report['mcp_after_restart'] = asyncio.run(mcp_status(listener, profiles))
            new_id = workspace.similarity.start(reference_id, target_id, backend='external')['comparison_id']
            new_job = workspace.similarity._jobs[new_id]
            wait(new_job.done.is_set)
            new_run = captured[-1]
            report['new_comparison'] = workspace.similarity.status(new_id)
            assert report['new_comparison']['match_count'] > 0
            assert report['new_comparison']['state'] in ('partial', 'completed')
            assert new_job.reason is None and new_job.error is None
            report['new_comparison_cleanup'] = assert_clean(new_run)
            assert report['new_comparison_cleanup']['process_returncode'] == 0
            workspace.similarity.close(new_id)
        workspace.similarity.close(comparison_id)
        report['heartbeat_count'] = len(heartbeats)
        assert heartbeats
        report['ok'] = True
    except Exception:
        report['error'] = traceback.format_exc()
    finally:
        def finish():
            finish_gui(timer, observer, plugin, FileContext, UIContext,
                       QApplication.instance(), ui_context, report, save)
        try:
            main_thread(finish)
        except Exception:
            report['cleanup_error'] = traceback.format_exc()
            report['ok'] = False
            save()


def start(case, reference, target, bindiff, output):
    from binaryninjaui import FileContext
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    assert QApplication.instance().activeModalWidget() is None
    assert not FileContext.getOpenFileContexts()
    Path(output).mkdir(mode=0o700, parents=True, exist_ok=False)
    QTimer.singleShot(100, lambda: threading.Thread(
        target=run, args=(case, reference, target, bindiff, output), daemon=True).start())
