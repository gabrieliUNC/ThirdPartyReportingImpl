import os
import json
import pandas as pd

''' Script to make the running time table for Third Party Reporting Schemes '''

path = "target/criterion"
dirs = os.listdir(path)
data = {}
schemes = ['basic', 'mod-priv', 'const-mod-priv', 'plain']
benches = ['send', 'process', 'read', 'report', 'moderate']
NUM_MODS = ['2 ', '64 ']

for dir in dirs:
    scheme = dir[:dir.find('.')]
    bench = dir[dir.find('.') + 1:-2]

    if scheme in schemes:
        sub_dirs = os.listdir(path + '/' + dir)
        for sub_dir in sub_dirs:
            if sub_dir == 'report':
                continue
            num_mods = '1 '
            for num in NUM_MODS:
                if num in sub_dir:
                    num_mods = num

            if 'plain' not in sub_dir and num_mods == '1 ':
                continue
            fname = path + '/' + dir + '/' + sub_dir + '/base/estimates.json'
            f = open(fname, 'r')
            cur = json.loads(f.read())
            f.close()

            if bench in benches:
                if bench not in data:
                    data[bench] = {}
                
                title = scheme + ' { ' + num_mods + '}'
                if scheme in schemes:
                    data[bench][title] = int(cur['mean']['point_estimate']) / 1e3


print('DataFrame output')
df = pd.DataFrame(data)
df = df[benches]
#df = df.reindex(['basic', 'mod-priv', 'const-mod-priv', 'plain'])
print(df)
print()


print('CSV output')
print(df.to_csv())
