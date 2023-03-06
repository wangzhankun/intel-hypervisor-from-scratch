# %%
import os
import sys

#%%
def split_machinecode(line):
    # 使用\t分割
    line = line.split('\t')[1:3]

    codes = line[0].split(' ')
    codes = ['0x' + i +', ' for i in codes if i != '']

    codes.append('//' + line[1])

    # codes 拼接成字符串
    codes = ''.join(codes)

    return codes


# %%

def make_machinecode(intput_file):
    # 调用shell编译test.s文件
    os.system('as ' + intput_file + ' -o test.o\n'
              'objcopy -O binary test.o test.bin\n'
              )

    # 获取shell命令的输出
    output = os.popen('objdump -D  -b binary -mi386 test.bin').read()


    # 找到机器码的起始位置
    start = output.find('<.data>:')
    # 截取机器码
    output = output[start:]
    # 使用\n分割字符串
    output = output.split('\n')[1:] # 删除 <.data>:
    # 删除空行
    output = [i for i in output if i != '']

    codes = ""
    for i in output:
        codes = codes + split_machinecode(i) + '\n'
    
    print(codes)

    # print(output)


    os.system('rm test.o test.bin')

#%%

if __name__ == '__main__':
    # get param from shell
    make_machinecode(sys.argv[1])

# %%
