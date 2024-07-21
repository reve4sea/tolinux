from queue import Queue

class process_clique:
    def __init__(self,name):
        self.l_set=set()
        self.r_set=set()
        self.l_edges=set()
        self.r_edges=set()
        self.name=name
        self.l_set.add(name)
        self.r_set.add(name)
    def add_l(self,left_node):
        self.l_set.add(left_node)
    def add_r(self,right_node):
        self.r_set.add(right_node)
    def add_ledge(self,edge):
        self.l_edges.add(edge)
    def add_redge(self,edge):
        self.r_edges.add(edge)

def get_clique(input_path,process_list,name_set):
    filer=open(input_path,'r',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line:
            break
        linelist=line.split()
        u=linelist[2]
        v=linelist[3]
        edge=linelist[0]
        u_type=""
        v_type=""
        if '/' in u or 'ffff' in u:
            u_type='file'
        elif '->' in u:
            u_type='ip'
        else:
            u_type='process'
        if '/' in v or 'ffff' in v:
            v_type='file'
        elif '->' in v:
            v_type='ip'
        else:
            v_type='process'
        #u为进程
        if u_type=='process':
            #u未被识别
            if u not in name_set:
                name_set.add(u)
                u_process=process_clique(u)
                u_process.add_r(v)
                u_process.add_redge(int(edge))
                process_list.append(u_process)
            #u已被识别
            elif u in name_set:
                for pros in process_list:
                    if pros.name==u:
                        pros.add_r(v)
                        pros.add_redge(int(edge))
                        break
        #u为文件
        elif u_type=='file':
            #v为文件
            if v_type=='file':
                for pros in process_list:
                    if u in pros.r_set:
                        pros.add_r(v)
                        pros.add_redge(int(edge))
        #v为进程
        if v_type == 'process':
            #v未被识别
            if v not in name_set:
                name_set.add(v)
                v_process=process_clique(v)
                v_process.add_l(u)
                v_process.add_ledge(int(edge))
                process_list.append(v_process)
            elif v in name_set:
                for pros in process_list:
                    if pros.name == v:
                        pros.add_l(u)
                        pros.add_ledge(int(edge))
                        break
    filer.close()
    #one more round
    filer=open(input_path,'r',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line:
            break
        linelist=line.split()
        u=linelist[2]
        v=linelist[3]
        edge=linelist[0]
        u_type=""
        v_type=""
        if '/' in u or 'ffff' in u:
            u_type='file'
        elif '->' in u:
            u_type='ip'
        else:
            u_type='process'
        if '/' in v or 'ffff' in v:
            v_type='file'
        elif '->' in v:
            v_type='ip'
        else:
            v_type='process'
        
        if v_type=='file':
            for pros in process_list:
                if v in pros.l_set:
                    pros.add_l(u)
                    pros.add_ledge(int(edge))
        if u_type=='file' and v_type=='process':
            for pros in process_list:
                if v==pros.name:
                    pros.add_l(u)
                    pros.add_ledge(int(edge))
                if u in pros.r_set:
                    pros.add_r(v)
                    pros.add_redge(int(edge))
            


    filew=open('clique.txt','w',encoding='utf-8')
    for pros in process_list:
        filew.write(pros.name+'\n')
        filew.write('left: '+str(pros.l_set)+'\n')
        filew.write('right: '+str(pros.r_set)+'\n')
        filew.write('l_edges: '+str(pros.l_edges)+'\n')
        filew.write('r_edges: '+str(pros.r_edges)+'\n')
    filew.close()

def head_traverse(input_path,process_list,head):
    marked=set()
    edges_set=set()
    l_set=set()
    r_set=set()
    q=Queue()
    q.put(head)
    marked.add(head)
    while q.qsize() > 0:
        u=q.get()
        for pros in process_list:
            if u==pros.name:
                edges_set=edges_set.union(pros.r_edges)
                l_set=l_set.union(pros.l_set)
                r_set=r_set.union(pros.r_set)
                break
        for pros in process_list:
            if not r_set.isdisjoint(pros.l_set) and pros.name not in marked:
                q.put(pros.name)
                marked.add(pros.name)
    return edges_set

'''
def struct_inverseg(input_path,output_path):
    lines=[]
    filer=open(input_path,'r',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line:
            break
        linelist=line.split()
        line=line[0]+' '+line[1]+' '+line[3]+' '+line[2]+' '+line[4]+' '+line[5]+' '+line[6]
        lines.append(line)
    filer.close()
    lines.reverse()
    filew=open(output_path,'w',encoding='utf-8')
    for line in lines:
        filew.write(line)
    filew.close()
'''

def process_sequence(process_list):
    filew=open('seq.txt','w',encoding='utf-8')
    for u in process_list:
        for v in process_list:
            if u.name != v.name:
                if not u.r_set.isdisjoint(v.l_set):
                    filew.write(u.name+' -> '+v.name+'\n')
    filew.close()

def tail_traverse(input_path,process_list,tail):
    marked=set()
    edges_set=set()
    l_set=set()
    r_set=set()
    q=Queue()
    q.put(tail)
    marked.add(tail)
    while q.qsize() > 0:
        v=q.get()
        for pros in process_list:
            if v == pros.name:
                edges_set=edges_set.union(pros.l_edges)
                l_set=l_set.union(pros.l_set)
                r_set=r_set.union(pros.r_set)
                break
        for pros in process_list:
            if not l_set.isdisjoint(pros.r_set) and pros.name not in marked:
                q.put(pros.name)
                marked.add(pros.name)
    return edges_set

def mid_traverse(input_path,process_list,mid_node):
    pass

def find_head(process_list,evt_name):
    res=[]
    for pros in process_list:
        if evt_name in pros.l_set:
            res.append(pros)
    return res

def find_tail(process_list,evt_name):
    res=[]
    for pros in process_list:
        if evt_name in pros.r_set:
            res.append(pros)
    return res

def fine_mid(process_list,evt_name):
    res=[]
    for pros in process_list:
        if evt_name in pros.r_set or evt_name in pros.l_set:
            res.append(pros)
    return res

def crossset(input_path,a,b):
    res=set()
    seta=set()
    setb=set()
    lista=list(a)
    listb=list(b)
    lista.sort()
    listb.sort()
    wholea=len(lista)
    wholeb=len(listb)
    countera=0
    counterb=0
    filer=open(input_path,'r',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line or (countera==wholea and counterb==wholeb):
            break
        linelist=line.split()
        if countera<wholea and linelist[0]==str(lista[countera]):
            countera+=1
            seta.add(linelist[2]+linelist[3]+linelist[4])
        if counterb<wholeb and linelist[0]==str(listb[counterb]):
            counterb+=1
            setb.add(linelist[2]+linelist[3]+linelist[4])
    filer.close()
    set_cross=seta&setb
    filer=open(input_path,'r',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line:
            break
        linelist=line.split()
        if linelist[2]+linelist[3]+linelist[4] in set_cross:
            res.add(int(linelist[0]))
    filer.close()
    return res

def write_res(forwarding,backwarding,output_path):
    res=list(crossset(input_path,forwarding,backwarding))
    res.sort()
    whole=len(res)
    counter=0
    filer=open(input_path,'r',encoding='utf-8')
    filew=open('res.txt','w',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line or counter==whole:
            break
        linelist=line.split()
        if linelist[0]==str(res[counter]):
            filew.write(line)
            counter+=1

    filer.close()
    filew.close()

def remove(input_path,output_path):
    filer=open(input_path,'r',encoding='utf-8')
    res=[]
    marked=set()
    while True:
        line=filer.readline()
        if not line:
            break
        linelist=line.split()
        if linelist[2]+linelist[3]+linelist[4] not in marked:
            marked.add(linelist[2]+linelist[3]+linelist[4])
            res.append(int(linelist[0]))
    filer.close()
    res.sort()
    counter=0
    whole=len(res)
    filer=open(input_path,'r',encoding='utf-8')
    filew=open(output_path,'w',encoding='utf-8')
    while True:
        line=filer.readline()
        if not line or counter==whole:
            break
        linelist=line.split()
        if linelist[0]==str(res[counter]):
            counter+=1
            filew.write(line)
            
    filer.close()
    filew.close()

if __name__=='__main__':
    input_path='fileedit.txt'
    head='4399bash'
    tail='4921single'
    process_list=[]
    name_set=set()
    get_clique(input_path,process_list,name_set)
    forwarding=head_traverse(input_path,process_list,head)
    backwarding=tail_traverse(input_path,process_list,tail)
    write_res(forwarding,backwarding,'res.txt')
    remove('res.txt','final.txt')
