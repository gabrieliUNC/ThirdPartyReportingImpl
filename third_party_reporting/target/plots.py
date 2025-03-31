import os
import json
import pandas as pd
import matplotlib.pyplot as plt

''' Script to make plots for moderator scaling '''

path = "criterion"
dirs = os.listdir(path)

process = {'mod-priv' : {}, 'basic' : {}, 'const-mod-priv' : {}}
mod_priv = {}
const_mod_priv = {}

schemes = ['basic', 'mod-priv', 'const-mod-priv']
benches = ['send', 'process', 'read', 'report', 'moderate']


# Plot Moderator Privacy Scale Plot
for dir in dirs:
    scheme = dir[:dir.find('.')]
    bench = dir[dir.find('.') + 1:-2]

    # Do work for process
    if scheme in schemes:
        sub_dirs = os.listdir(path + '/' + dir)
        for sub_dir in sub_dirs:
            if sub_dir == 'report':
                continue

            fname = path + '/' + dir + '/' + sub_dir + '/base/estimates.json'
            f = open(fname, 'r')
            cur = json.loads(f.read())
            f.close()

            if bench == 'process':
                num_moderators = int(sub_dir.split()[-2])
                process[scheme][num_moderators] = int(cur['mean']['point_estimate']) / 1e3


    # Do work for mod-priv plot
    if scheme == 'mod-priv':
        sub_dirs = os.listdir(path + '/' + dir)
        for sub_dir in sub_dirs:
            if sub_dir.startswith('mod-priv') == False:
                continue

            fname = path + '/' + dir + '/' + sub_dir + '/base/estimates.json'
            f = open(fname, 'r')
            cur = json.loads(f.read())
            f.close()

            if bench in benches:
                if bench not in mod_priv:
                    mod_priv[bench] = {}
                
                num_moderators = int(sub_dir.split()[-2])
                mod_priv[bench][num_moderators] = int(cur['mean']['point_estimate']) / 1e3
            
    
    # Do work const-mod-priv plot
    if scheme == 'const-mod-priv':
        sub_dirs = os.listdir(path + '/' + dir)
        for sub_dir in sub_dirs:
            if sub_dir.startswith('const-mod-priv') == False:
                continue

            fname = path + '/' + dir + '/' + sub_dir + '/base/estimates.json'
            f = open(fname, 'r')
            cur = json.loads(f.read())
            f.close()

            if bench in benches:
                if bench not in const_mod_priv:
                    const_mod_priv[bench] = {}
                
                num_moderators = int(sub_dir.split()[-2])
                const_mod_priv[bench][num_moderators] = int(cur['mean']['point_estimate']) / 1e3
    


'''
print('Mod-Priv-1 Scaling DataFrame output')
print()
df = pd.DataFrame(mod_priv)
df = df[benches]
df = df.sort_index()
print(df)
print()


print('Mod-Priv-1 Scaling PyPlot')
print()
df.plot(title='Mod-Priv-1 Scaling PyPlot')
plt.show()
print()
'''


print('Mod-Priv-2 Scaling DataFrame output')
print()
df = pd.DataFrame(const_mod_priv)
df = df[benches]
df = df.sort_index()
print(df)
print()


print('Mod-Priv-2 Scaling PyPlot')
print()
df.plot(title='Mod-Priv-2 Scaling PyPlot')
plt.show()
print()



print('Process Scaling DataFrame output')
print()
df = pd.DataFrame(process)
df = df.sort_index()
print(df)
print()


print('Process Scaling PyPlot')
print()
df.plot(title='Process Scaling PyPlot')
plt.show()
print()
