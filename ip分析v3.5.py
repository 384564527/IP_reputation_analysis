import pandas as pd
import requests
from datetime import datetime
import ipaddress

# 定义全量威胁类型字典
threat_type = {
    'C2': '远控', 'CloudWAF':'云waf','Botnet': '僵尸网络', 'Hijacked': '劫持', 'Phishing': '钓鱼', 'Malware': '恶意软件',
    'Exploit': '漏洞利用', 'Scanner': '扫描', 'Zombie': '傀儡机', 'Spam': '垃圾邮件', 'Suspicious': '可疑',
    'Compromised': '失陷主机', 'Whitelist': '白名单', 'Brute Force': '暴力破解', 'Proxy': '代理',
    'MiningPool': '矿池', 'CoinMiner': '私有矿池', 'suspicious_application': '可疑恶意软件',
    'suspicious_website': '可疑恶意站点', 'Fakewebsite': '仿冒网站', 'Sinkhole C2': '安全机构接管 C2',
    'SSH Brute Force': 'SSH暴力破解', 'FTP Brute Force': 'FTP暴力破解', 'SMTP Brute Force': 'SMTP暴力破解',
    'Http Brute Force': 'HTTP AUTH暴力破解', 'Web Login Brute Force': '撞库', 'HTTP Proxy': 'HTTP Proxy',
    'HTTP Proxy In': 'HTTP代理入口', 'HTTP Proxy Out': 'HTTP代理出口', 'Socks Proxy': 'Socks代理',
    'Socks Proxy In': 'Socks代理入口', 'Socks Proxy Out': 'Socks代理出口', 'VPN': 'VPN代理', 'VPN In': 'VPN入口',
    'VPN Out': 'VPN出口', 'Tor': 'Tor代理', 'Tor Proxy In': 'Tor入口', 'Tor Proxy Out': 'Tor出口', 'Bogon': '保留地址',
    'Full Bogon': '未启用IP', 'Gateway': '网关', 'IDC': 'IDC服务器', 'Dynamic IP': '动态IP', 'Edu': '教育',
    'DDNS': '动态域名', 'Mobile': '移动基站', 'Search Engine Crawler': '搜索引擎爬虫', 'CDN': 'CDN服务器',
    'Advertisement': '广告', 'DNS': 'DNS服务器', 'BTtracker': 'BT服务器', 'Backbone': '骨干网', 'ICP': 'ICP备案',
    'IoT Device': '物联网设备', 'Web Plug Deployed': '部署网站插件', 'Gameserver': '游戏服务器'}
# 定义非恶意威胁类型字典
infos = {'Bogon', 'Full Bogon', 'Gateway', 'IDC', 'Dynamic IP', 'Edu', 'DDNS', 'Mobile', 'Search Engine Crawler', 'CDN',
         'Advertisement', 'DNS', 'BTtracker', 'Backbone', 'ICP', 'IoT Device', 'Web Plug Deployed', 'Gameserver',
         'Whitelist', 'Whitelist', 'Info'}
         
class ThreatType:
    def __init__(self):
        self.threat_type = threat_type
        self.infos = infos
 
    # 威胁类型字典转换
    def get_threat_type(self, original_list):
        # 使用列表推导式将每个元素替换为相应的中文名称
        new_list = [self.threat_type[item] for item in original_list]
        return new_list
 
    # 排除非恶意的类型
    def non_malicious(self, info_type):
        # 去除重复的info_type
        # info_type = list(set(str(info_type)))
        # 遍历info_type、infos中的每个值，对比后删除info_type和infos相同的值
        for info in self.infos:
            if info in info_type:
                info_type.remove(info)
        return info_type
        
# 调用API接口
class ThreatBookApi:
    def __init__(self):
        # 输入key
        self.apikey = 'c7ea95dfe6b94943bd0eb0d8ace696d9213457b03ef1408aa738629f9dd09812'
        # 定义key列表
        self.apikey_box = ['2a5abf1f0b5440108f2f4a21a2ca89babadd15f7cebe415bb768bc79c2570938',
                           '8306d80c2eb6466ab8d3c2470212a8ac91513bb4e27b49cc9de8b98bd9de6285',
                          '4e4826f0f987484880ff4900c8bc965fdf3c1f64eb794bcebc3585b795dd1186',
                          'c65cbe60ae524abf83bea97083dbcedf45dda7f2bf7e44c099eb285dda179d4b',
                           '0a4c221acd1d45e491c110c08d906f5d428e6f1b7ec448f6bdc7b71dcc8555e1',
                           '5c043f7caea94b1da45e693e255447cda486ba405c87466faf20e24c51b519b3',
                          'b9047511d7d643b696588b52de44411f7697c6daf55543e5b06af82efcb9988f',
                          '644e33bfc7014628972e51db627a8477d3682e2898e9443ca5d1ec0d3ed926b7',
                          '33bbe74b7b3c4e219080a9a14cad25f5ae2deb2480704b89a837387c5e3531d4',
                          '122ef2be4f3a4b4a9323f0eb59190a274601f48fc63d4fc0a168770b46ab2f21',
                          '5ea62b3e0cd44fe39edc1c06b68827015ced38e408c94ecdaf76438bb69b8949']
 
    # 状态码判断
    def get_code_query(self, text, re_code):
        re_codes = [-1, -2, -3, -5]
        if re_code in re_codes:
            get_json = {'response_code': re_code}
            if get_json['response_code'] == -1:
                print(str(text) + '查询失败，API权限受限或请求出错.')
            if get_json['response_code'] == -2:
                print(str(text) + '查询失败，请求无效.')
            if get_json['response_code'] == -3:
                print(str(text) + '查询失败，请求参数缺失.')
            if get_json['response_code'] == -5:
                print(str(text) + '查询失败，系统错误.')
        else:
            pass
 
    # IP信誉
    def ip_reputation(self, ip):
        for i in range(len(self.apikey_box)):
            url = "https://api.threatbook.cn/v3/scene/ip_reputation"
            query = {"apikey": self.apikey, "resource": ip}
            response = requests.get(url, params=query)
            if response.json()['response_code'] == -4:
                self.apikey_backup = self.apikey_box[i]
                i -= 1
                query = {"apikey": self.apikey_backup, "resource": ip}
                # self.progress_bar()
                response = requests.get(url, params=query)
                if response.json()['response_code'] == 0:
 
                    return response.json()
                else:
                    continue
            else:
                return response.json()
 
    # IP分析
    def ip_query(self, ip):
        url = "https://api.threatbook.cn/v3/ip/query"
        self.apikey = '2a5abf1f0b5440108f2f4a21a2ca89babadd15f7cebe415bb768bc79c2570938'
        query = {"apikey": self.apikey, "resource": ip}
        response = requests.request("GET", url, params=query)
        if response.json()['response_code'] == -4:
            print('IP分析查询次数已使用完成(共1000次)')
        return response.json()
        
# IP信誉查询
class ThreatReputation:
    def __init__(self, input_ip):
        # 初始化IP
        self.ip = input_ip
        # 调用接口
        self.BookApi = ThreatBookApi()
        # 调用IP信誉函数
        self.ip_json = self.BookApi.ip_reputation(ip=self.ip)
        # # 执行函数
        # self.threat_reputation()
        
    def threat_reputation(self):
        # 调用状态码判断，获取状态码并提示信息
        self.BookApi.get_code_query(text='IP信誉', re_code=self.ip_json['response_code'])
        if 'data' not in self.ip_json:
            print('威胁情报查询结束!')
            return None
        # 按照update_time字段对数据进行排序
        sorted_data = sorted(self.ip_json['data'].values(), key=lambda x: x['update_time'], reverse=True)
        # 获取最新的数据并提取所需的字段
        latest_data = sorted_data[0]
        # 可信度。分"low（低）"，"medium（中）"，"high（高）" 三档来标识
        confidence_level = latest_data['confidence_level']
        # 提取出威胁类型
        judgments = latest_data['judgments']
        # 是否为恶意IP。布尔类型，true代表恶意，false代表非恶意。
        latest_identity = self.ip_json['data'][self.ip]['is_malicious']
        # 取judgments列表第一位、latest_identity、confidence_level综合判断是否为恶意类型
        if (latest_identity is True) and (judgments[0] in threat_type) and (confidence_level == 'high'):
            # 删除无效的非恶意类型
            ThreatType().non_malicious(info_type=judgments)
            # 调用get_threat_type将intel_types翻译为中文
            type_cn = ThreatType().get_threat_type(original_list=set(judgments))
            ipv4="[IP信誉-可信度:{}]-源IP'{}'属于恶意IP，威胁类型包括'{}';".format(confidence_level, self.ip, ','.join(type_cn))
            print(ipv4)
            return ipv4
        else:
            # 调用get_threat_type将intel_types翻译为中文
            # type_cn = ThreatType().get_threat_type(original_list=set(judgments))
            print("[IP信誉-可信度:{}]-源IP'{}'不属于恶意地址.".format(confidence_level, self.ip))
            ipv4="[IP信誉-可信度:{}]-源IP'{}'不属于恶意地址.".format(confidence_level, self.ip)
            return ipv4
            
# IP分析查询
class ThreatQuery:
    def __init__(self, input_ip):
        # 定义变量
        self.ip = input_ip  # 定义IP
        self.BookApi = ThreatBookApi()  # 调用API接口
        self.ip_json = self.BookApi.ip_query(ip=self.ip)  # 调用IP分析函数
        self.threat_type = threat_type
        self.infos = infos
        self.valid_intel = []
        self.valid_box = []
        self.confidence_box = []
        self.intel_types_box = []
        # 执行函数
        self.json_query()
 
    def json_query(self):
        # 调用状态码判断，获取状态码并提示信息
        self.BookApi.get_code_query(text='IP分析', re_code=self.ip_json['response_code'])
        if 'data' not in self.ip_json:
            print('威胁情报查询结束!')
            return None
        # 遍历键值为False(情报有效)的所有信息
        valid_json = self.ip_json['data'][self.ip]["intelligences"]["threatbook_lab"]
        # 当expired为False时，获取包含confidence，intel_types的值
        for j in valid_json:
            if not j['expired']:
                self.valid_intel.append(
                    {'confidence': j['confidence'], 'intel_types': j['intel_types'],
                     'expired': j['expired']})
        for i in range(len(self.valid_intel)):
            valid = (self.valid_intel[i]['expired'])
            self.valid_box.append(valid)
            confidence = (self.valid_intel[i]['confidence'])
            self.confidence_box.append(confidence)
            intel_types = (self.valid_intel[i]['intel_types'])
            self.intel_types_box.append(intel_types)
        # self.valid_box, self.confidence_box, self.intel_types_box = self.get_param(valid_intel=self.valid_intel)
        box_data = [self.valid_box, self.confidence_box, self.intel_types_box]
        new_box = list(box_data)
        # 获取有效性
        new_valid = new_box[0][0]
        # 获取可信度
        new_confidence = max(set(new_box[1]))
        # 获取威胁类型
        intel_types_1 = new_box[2]
        intel_types_2 = list(set([item for sublist in intel_types_1 for item in sublist]))
        # print(new_valid, new_confidence, intel_types_2)
        # 调用Non_Malicious函数去除非恶意类型
        result = ThreatType().non_malicious(info_type=intel_types_2)
        # 用valid、威胁类型长度综合判断
        if new_valid is False and len(result) != 0:
            # 调用get_threat_type将intel_types翻译为中文
            cn_type = ThreatType().get_threat_type(original_list=set(result))
            # print(cn_type)
            print(
                "[IP分析-可信度:{}%]-源IP'{}'属于恶意IP,威胁类型包括'{}';".format(new_confidence, self.ip, ','.join(cn_type)))
        if len(result) == 0:
            print("[IP分析-可信度:{}%]-源IP'{}'不属于恶意地址.".format(new_confidence, self.ip))
            

if __name__=='__main__':
    import argparse

    # 创建解析器对象
    parser = argparse.ArgumentParser(description='Process input and output directories.')

    # 添加输入目录参数
    parser.add_argument('-i', '--input', type=str, help='Input directory path')
    # 解析命令行参数
    args = parser.parse_args()
    df=pd.read_excel(args.input)
    
    df_bai=pd.read_excel('')
    df_hei=pd.read_excel('')
    df_hei=df_hei[(df_hei['状态']=='生效')]
    df_hei.reset_index(drop=True, inplace=True)
    df.dropna(subset=['攻击者'], inplace=True)
    df2 = df.drop_duplicates(subset=['攻击者']).reset_index(drop=True)
    df2['ip信誉分析'] = '待分析'
    # Correcting the regular expression pattern to extract IPv4 addresses with subnet masks
    ipv4_pattern = r'(\d+\.\d+\.\d+\.\d+(/\d+)?)|(\d+\.\d+\.\d+\.\d+)'
    #白名单过滤
    # Extract IPv4 addresses including those with subnet masks
    ipv4_addresses = df_bai['源IP'].dropna().astype(str).str.extract(ipv4_pattern)
    ipv4_addresses = ipv4_addresses[0].dropna().squeeze().unique()
    #黑名单过滤
    hei_ip_list = df_hei['源IP'].tolist()
    # 检查 'XFF' 列中的值是否都是字符串，并且是否至少包含一个逗号
    if df2['XFF'].apply(lambda x: isinstance(x, str)).all():
        # 分割XFF列，按逗号分隔，并扩展到单独的行
        xff_ips = df2['XFF'].str.split(',', expand=True).stack()
        # 丢弃NaN值，重置索引以创建每行一个IP的数据框
        xff_ips_df = xff_ips.dropna()
        is_not_nan = df2['XFF'].notna()
    else:
        # 创建一个与 df2 同样行数的空列表
        empty_list = [None] * len(df2)
        is_not_nan=empty_list
    gover_network = ipaddress.ip_network('19.82.120.0/21')
    Inter_network= ipaddress.ip_network('218.15.144.0/21')
    # 将列表a中的每个元素转换为IPv4Network对象，如果它是一个网络地址
    bai_networks = [ipaddress.ip_network(item) for item in ipv4_addresses if '/' in item]
    for i in range(df2.shape[0]):
        
        if df2['攻击者'][i] in hei_ip_list:
            df2['ip信誉分析'][i]='已经封禁，黑名单'
            continue
        if ',' in df2['攻击者'][i]:
            ipv4_list = df2['攻击者'][i].split(',')
            ips=[]
            xff_ips=[]
            for ip in ipv4_list:
                #print(ip)
                ip_f=ThreatReputation(input_ip=ip)
                ip_to_check = ipaddress.ip_address(ip)
                # 检查源IP地址是否是白名单中的一个具体地址或属于列表中的某个网络范围
                ip_exists_in_networks = ip in ipv4_addresses or any(ipaddress.ip_address(ip) in net for net in bai_networks)       
                # 判断源IP是否在白名单内
                if ip_exists_in_networks or is_not_nan[i]:
                    #print("%s在指定的白名单内。"%(ip))
                    if is_not_nan[i]:
                        for j in range(xff_ips_df[i].shape[0]):
                            try:
                                # 要判断的真实IP地址
                                xff_ip_exists_in_networks=xff_ips_df[i].loc[j] in ipv4_addresses or any(ipaddress.ip_address(xff_ips_df[i].loc[j]) in net for net in bai_networks)
                                # 判断真实IP是否在白名单内
                                if not xff_ip_exists_in_networks:
                                    print("XFF%s在不指定的白名单内。"%(xff_ips_df[i].loc[j]))
                                    if xff_ips_df[i].loc[j] in hei_ip_list:
                                        xff_ips.append(str(xff_ips_df[i].loc[j])+'已经封禁，黑名单')
                                        print(str(xff_ips_df[i].loc[j])+'黑名单')
                                    else:   
                                        try:
                                            xff_ip=ThreatReputation(input_ip=xff_ips_df[i].loc[j])
                                            print(xff_ips_df[i].loc[j])
                                            xff_ips.append(xff_ip.threat_reputation())
                                        except:    
                                            print("重复值")
                                else:
                                    print("XFF%s在指定的白名单内。"%(xff_ips_df[i].loc[j]))
                                    xff_ips.append(str(xff_ips_df[i].loc[j])+'白名单')
                            except Exception as e:
                                # 发生异常时，输出错误信息
                                print(f"发生错误：{e}")
                                continue
                        break                 
                    else:
                        print("源IP%s是白名单。"%(ip))
                        ips.append(ip+'白名单')
                else:
                    print("源IP%s不是白名单。"%(ip))
                    ips.append(ip_f.threat_reputation())
                    
            if  ip_to_check in Inter_network or ip_to_check in gover_network :
                continue
            if is_not_nan[i]:
                df2['ip信誉分析'][i]=xff_ips
                #print(df2['ip信誉分析'][i])
            else:
                df2['ip信誉分析'][i]=ips
                #print(df2['ip信誉分析'][i])            
        else:
            ip=df2['攻击者'][i]
            ip_to_check = ipaddress.ip_address(ip)
            ip_f=ThreatReputation(input_ip=ip)
            # 检查源IP地址是否是白名单中的一个具体地址或属于列表中的某个网络范围
            ip_exists_in_networks = ip in ipv4_addresses or any(ipaddress.ip_address(ip) in net for net in bai_networks)       
            # 判断源IP是否在白名单内
            if ip_exists_in_networks or is_not_nan[i]:
                #print("%s在指定的白名单内。"%(ip))
                if is_not_nan[i]:
                    xff_ips=[]
                    for j in range(xff_ips_df[i].shape[0]):
                        try:
                            # 要判断的真实IP地址
                            xff_ip_exists_in_networks=xff_ips_df[i].loc[j] in ipv4_addresses or any(ipaddress.ip_address(xff_ips_df[i].loc[j]) in net for net in bai_networks)
                            # 判断真实IP是否在白名单内
                            if not xff_ip_exists_in_networks:
                                print("XFF%s不在指定的白名单内。"%(xff_ips_df[i].loc[j]))
                                if xff_ips_df[i].loc[j] in hei_ip_list:
                                    xff_ips.append(str(xff_ips_df[i].loc[j])+'已经封禁，黑名单')
                                    print(str(xff_ips_df[i].loc[j])+'黑名单')
                                else:   
                                    try:
                                        xff_ip=ThreatReputation(input_ip=xff_ips_df[i].loc[j])
                                        print(xff_ips_df[i].loc[j])
                                        xff_ips.append(xff_ip.threat_reputation())
                                    except:    
                                        print("重复值")
                            else:
                                print("XFF%s在指定的白名单内。"%(xff_ips_df[i].loc[j]))
                                xff_ips.append(str(xff_ips_df[i].loc[j])+'白名单')
                        except Exception as e:
                            # 发生异常时，输出错误信息
                            print(f"发生错误：{e}")
                            continue
                            
                else:
                    print("源IP%s是白名单。"%(ip))
                    df2['ip信誉分析'][i]='白名单'
            
            if df2['ip信誉分析'][i]=='白名单' or ip_to_check in Inter_network or ip_to_check in gover_network :
                continue
            if is_not_nan[i]:      
                df2['ip信誉分析'][i]=xff_ips
                #print(df2['ip信誉分析'][i])
            else:
                print(i)
                df2['ip信誉分析'][i]=ip_f.threat_reputation()
                #print(df2['ip信誉分析'][i])

    # 获取当前日期和时间
    now = datetime.now().date()
    df2.to_excel('ip信誉分析-%s.xlsx'%(now),index=False)
