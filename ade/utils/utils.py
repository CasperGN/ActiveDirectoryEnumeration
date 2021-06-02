import json
from termcolor import colored


class Utils():


    def __init__(self):
        pass


    def WriteFiles(self, output: str, content, name: str):
        with open(str(output) + f'-{name}', 'w') as f:
            if isinstance(content, list):
                for item in content:
                    f.write(str(item))
                    f.write('\n')
            elif isinstance(content, dict):
                if 'json' in name:
                    json.dump(content, f, indent=4, sort_keys=False)
                else:
                    for key, value in content:
                        f.write(f'{key}:{value}')
                        f.write('\n')

        print('[ ' + colored('OK', 'green') + f' ] Wrote {name}')


    def splitJsonArr(self, arr):
        if isinstance(arr, list):
            if len(arr) == 1:
                return arr[0]
        return arr