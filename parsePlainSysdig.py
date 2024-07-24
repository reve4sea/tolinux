# parameter for sysdig log (DepImpact Dataset)
SYSCALL_TYPE = 6
SYSCALL_DIR = 5
PROC_ID = 4
PROC_NAME = 3
TIME = 1

target_type = ['read', 'write', 'readv', 'writev', 'execve', 'fork', 'clone', 'sendto', 'recvfrom', 'recvmsg',
               'sendmsg', 'accept', 'fcntl', 'rename', 'renameat2', 'open', 'openat','vfork','newfstatat','access','mkdir']
event_list = []

#extract the info in fd
def extract_fd(log: str):
    fd = log[log.index('fd='):].split(" ")[0]
    
    path = ''
    for index, char in enumerate(fd):
        if char == '>':
            path = fd[index + 1:len(fd) - 1]
            if '(' in path:
                path = path[path.index('(') + 1:len(path) - 1]
            break

        
    return path

#extract next for switch
def extract_next(log:str):
    next = log[log.index('next='):].split(" ")[0]
    next = next.replace("(","").replace(")","")
    return next

#extract data
def extract_name(log:str):
    name = log[log.index('name='):].split(" ")[0]
    name = name[5:]
    return name

#extract path
def extract_path(log:str):
    path = log[log.index('path='):].split(" ")[0]
    path = path[5:]
    return path

#judge whether it is a process or file or network
def get_entity_type(entity):
    if len(entity.split('.')) >= 6 and len(entity.split(':')) >= 2:
        return 'network'
    if '/' in entity:
        return 'file'
    else:
        return 'process'

#extract result
def extract_res(log: str):
    res = log[log.index('res=') + 4:].split(" ")[0]
    if res[0] != '-':
        if '(' in res:
            res = res.split('(')[0]
        return res
    return '-1'


# filter out irrelevant events and generate event list
def log_filter(log_path, output_path):
    count = 0 
    try:
        with open(log_path) as f:
            primary_log = f.readlines()
            f.close()
        

    except:
        print("Error when read log files")
        return

    # filter out target syscall event
    
    primary_log = list(filter(lambda x: x.split(' ')[SYSCALL_TYPE] in target_type, primary_log))
   
    event_num = 0
    for index, value in enumerate(primary_log):
        syscall_type = value.split(' ')[SYSCALL_TYPE]
        #if syscall_type == 'switch':
            #print(1)
        syscall_dir = value.split(' ')[SYSCALL_DIR]
        proc_id = value.split(' ')[PROC_ID]
        if syscall_dir == '>':
            couple = [value.split(' ')]
        
            
            
            i = 0
            while True:
                i += 1
                if (index+i >= len(primary_log)):
                   break
                new_type = primary_log[index + i].split(' ')[SYSCALL_TYPE]
                new_dir = primary_log[index + i].split(' ')[SYSCALL_DIR]
                new_proc = primary_log[index + i].split(' ')[PROC_ID]
                if (new_type == syscall_type) and (new_dir == '<') and syscall_type == 'execve':
                    couple.append(primary_log[index + i].split(' '))
                    break
                if (new_type == syscall_type) and (new_dir == '<') and new_proc == proc_id:
                    couple.append(primary_log[index + i].split(' '))
                    break
                if i >= 20:
                    break
            # get the couple of an event
            
            if len(couple) == 2 or syscall_type == 'switch':
                #if syscall_type == 'switch':
                    #print(1)
                '''
                try:
                
                    res = extract_res(' '.join(couple[1]))
                    res_num = int(res)
                    # delete event with response number less than 0
                    if res_num < 0:
                        # del primary_log[index]
                        # del primary_log[index+i]
                        continue
                except:
                    print(syscall_type)
                '''    

                # generate event list
                # Network / file to process
                if syscall_type in ['read', 'readv', 'recvfrom', 'recvmsg', 'fcntl']:
                    source = extract_fd(' '.join(couple[0]))
                    
                    if source == '':
                        
                        continue
                    if syscall_type in ['recvfrom', 'recvmsg', 'fcntl'] and get_entity_type(source) != 'network':
                        
                        continue
                    destination = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    continue
                
                if syscall_type in ['access']:
                    source = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    destination = extract_name(' '.join(couple[1]))
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    continue

                if syscall_type in ['mkdir']:
                    destination = extract_path(' '.join(couple[1]))
                    if destination == '':
                        continue
                    source = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    continue

                if syscall_type in ['newfstatat']:
                    destination = extract_fd(' '.join(couple[1]))
                    if destination == '':
                        continue
                    source = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    continue

                if syscall_type in ['open', 'openat']:
                    destination = extract_fd(' '.join(couple[1]))
                    if destination == '':
                        continue
                    source = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    event_num += 1
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    continue
                

                # Process to F/N
                if syscall_type in ['write', 'writev', 'sendto', 'sendmsg']:
                    source = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    destination = extract_fd(' '.join(couple[0]))
                    if destination == '':
                        continue
                    if syscall_type in ['sendto', 'sendmsg'] and get_entity_type(destination) != 'network':
                        continue
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    continue

                # if syscall_type in ['recvmsg']:
                #     source = extract_fd(' '.join(couple[0]))
                #     if source == '':
                #         continue
                #     destination = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                #     size = res
                #     start_time = couple[0][TIME]
                #     end_time = couple[1][TIME]
                #     if source != '':
                #         event_num += 1
                #         event_list.append([event_num, source, destination, syscall_type, size, start_time, end_time])
                #     continue

                if syscall_type in ['execve']:
                    tmp_log = ' '.join(couple[1])
                    source = tmp_log[tmp_log.index('ptid=') + 5:].split(" ")[0]
                    try:
                        [src_pid, src_name] = source[:-1].split('(')
                    except:
                        print(source)
                        continue
                    source = src_pid + src_name
                    destination = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    tmp_log = ' '.join(couple[0])
                    filename = tmp_log[tmp_log.index('filename=') + 9:].split(" ")[0]
                    if '(' in filename:
                        filename = filename[filename.index('(') + 1: -1]
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]

                    event_num += 1
                    event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                    event_num += 1
                    event_list.append([event_num, filename, destination, syscall_type, start_time, end_time])
                    event_num += 1
                    event_list.append([event_num, destination, source, syscall_type, start_time, end_time])
                    continue
                
                if syscall_type in ['clone','vfork']:
                    
                    tmp_log = ' '.join(couple[1])
                    source = tmp_log[tmp_log.index('ptid=') + 5:].split(" ")[0]
                    try:
                        [src_pid, src_name] = source[:-1].split('(')
                    except:
                        print(source)
                        continue
                    source = src_pid + src_name
                    tmp_log = ' '.join(couple[1])
                    des = tmp_log[tmp_log.index('res=') + 4:].split(" ")[0]
                    try:
                        destination = des.split('(')[0] + des.split('(')[1][:-1]
                    except:
                        print(des)
                        continue
                   
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    if destination != '':
                        event_num += 1
                        event_list.append([event_num, source, destination, syscall_type, start_time, end_time])
                        event_num += 1
                        event_list.append([event_num, destination, source, syscall_type, start_time, end_time])
                    continue
                
                # Process to N & N to Process
                if syscall_type in ['accept']:
                    process = couple[1][PROC_ID][1:-1] + couple[1][PROC_NAME]
                    network = extract_fd(' '.join(couple[1]))
                    if network == '':
                        continue
                    
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]

                    event_num += 1
                    event_list.append([event_num, process, network, syscall_type, start_time, end_time])
                    event_num += 1
                    event_list.append([event_num, network, process, syscall_type, start_time, end_time])
                    continue

                #if syscall_type in ['switch']:
                 #   next = extract_next(' '.join(couple[0]))
                  #  if next == '' or '<NA>' in next:
                   #     continue
                    #if couple[0][PROC_NAME] == '<NA>':
                     #   continue
                    #source = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    #start_time = couple[0][TIME]
                   # end_time = start_time
                    #event_num += 1
                    #event_list.append([event_num, source, next, syscall_type, start_time, end_time])
                    #continue

                '''
                if syscall_type in ['rename', 'renameat2']:
                    process = couple[0][PROC_ID][1:-1] + couple[0][PROC_NAME]
                    log = ' '.join(couple[1])
                    old_path = log[log.index('oldpath=') + 8: log.index(" ", log.index('oldpath='))]
                    if '(' in old_path:
                        old_path = old_path[old_path.index('(') + 1:len(old_path) - 1]
                    new_path = log[log.index('newpath=') + 8: log.index(" ", log.index('newpath='))]
                    if '(' in new_path:
                        new_path = new_path[new_path.index('(') + 1:len(new_path) - 1]
                    if old_path[-1] == ')':
                        old_path = old_path[old_path.index('(') + 1: -1]
                    if new_path[-1] == ')':
                        new_path = new_path[new_path.index('(') + 1: -1]
                    
                    start_time = couple[0][TIME]
                    end_time = couple[1][TIME]
                    event_num += 1
                    event_list.append([event_num, old_path, process, syscall_type, start_time, end_time])
                    event_num += 1
                    event_list.append([event_num, process, new_path, syscall_type, start_time, end_time])
                    continue
'''
    try:
        with open(output_path, "w") as f:
            for line in event_list:
                line = str(line).replace("'", '').replace(',', '')[1:-1]
                f.write(line + '\n')
            f.close()
    except Exception as e:
        print(e)
        raise


if __name__ == '__main__':
    SYSCALL_TYPE = 6
    SYSCALL_DIR = 5
    PROC_ID = 4
    PROC_NAME = 3
    TIME = 1
    LOG_PATH = "case3_ninja.log"
    EVENT_PATH = 'case3_ninja.txt'
    log_filter(LOG_PATH, EVENT_PATH)
