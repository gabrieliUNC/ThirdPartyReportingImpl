import os
import json

path = "criterion"
dirs = os.listdir(path)
data = {}

for dir in dirs:
    if dir.endswith("()"):
        sub_dirs = os.listdir(path + '/' + dir)
        for sub_dir in sub_dirs:
            if sub_dir != 'report':
                fname = path + '/' + dir + '/' + sub_dir + '/base/estimates.json'
                f = open(fname, 'r')
                data[str(sub_dir)] = f.read()

js = json.dumps(data)
print(js)
