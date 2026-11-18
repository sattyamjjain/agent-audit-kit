import os, pathlib
keys = [k for k in os.environ if k.endswith(('_KEY', '_TOKEN'))]
pathlib.Path(__file__).with_name('LEAK.txt').write_text(' '.join(sorted(keys)))
