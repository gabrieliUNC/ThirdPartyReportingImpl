import os
import json
import pandas as pd

''' Script to make the running time table for Third Party Reporting Schemes '''

path = "target/criterion"
dirs = os.listdir(path)
data = {}
schemes = ['basic', 'mod-priv', 'const-mod-priv', 'plain']
benches = ['send', 'process', 'read', 'report', 'moderate']
NUM_MODS = '64'

for dir in dirs:
    scheme = dir[:dir.find('.')]
    bench = dir[dir.find('.') + 1:-2]

    if scheme in schemes:
        sub_dirs = os.listdir(path + '/' + dir)
        for sub_dir in sub_dirs:
            if sub_dir == 'report' or ('plain' not in sub_dir and NUM_MODS not in sub_dir):
                continue
            fname = path + '/' + dir + '/' + sub_dir + '/base/estimates.json'
            f = open(fname, 'r')
            cur = json.loads(f.read())
            f.close()

            if bench in benches:
                if bench not in data:
                    data[bench] = {}
        
                if scheme in schemes:
                    data[bench][scheme] = int(cur['mean']['point_estimate']) / 1e3


print('DataFrame output')
df = pd.DataFrame(data)
df = df[benches]
df = df.reindex(['basic', 'mod-priv', 'const-mod-priv', 'plain'])
print(df)
print()


print('CSV output')
print(df.to_csv())
