from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from edr.core import event


def run(config, stop, emit, interval):
    class Handler(FileSystemEventHandler):
        def on_any_event(self, item):
            if item.event_type in ('created', 'modified', 'deleted', 'moved') and not item.is_directory:
                emit(event('files', 'file_' + item.event_type,
                           {'path': item.src_path, 'destination': getattr(item, 'dest_path', None)}))
    observer = Observer()
    for folder in config['paths']:
        if not Path(folder).is_dir():
            raise ValueError(f'Watch directory does not exist: {folder}')
        observer.schedule(Handler(), folder, recursive=True)
    observer.start()
    try:
        stop.wait()
    finally:
        observer.stop()
        observer.join()
