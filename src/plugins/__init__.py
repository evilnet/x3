import imp
import os.path

class Plugin(object):
    def server_link(self, server):
        pass

    def new_user(self, user):
        pass

def load_path(path, prefix):
    mods = []

    for entry in os.listdir(path):
        if os.path.isfile(os.path.join(path, entry)):
            if os.path.splitext(entry)[1] != '.py':
                continue

        if entry.startswith('.') or entry.startswith('__'):
            continue

        try:
            args = imp.find_module(os.path.splitext(entry)[0], [path])
        except ImportError:
            continue

        if args:
            mod = imp.load_module(prefix + os.path.splitext(entry)[0], *args)
            if args[0]:
                args[0].close()
            if mod:
                mods.append(mod)

        if os.path.isdir(os.path.join(path, entry)):
            mods.extend(load_path(os.path.join(path, entry), prefix + entry + '.'))

    return mods

def load():
    mods = load_path(os.path.dirname(__file__), 'plugins.')
    plugins = {}

    # for some reason this returns multiple instances of the same plugin types
    candidates = Plugin.__subclasses__()
    for plg in candidates:
        plugins[plg.__name__] = plg()

    return plugins.values()
