import base64
import json
import re
import urllib.parse
from typing import Dict, List, Tuple


class ParseNode:

  @staticmethod
  def ss(url: str) -> Tuple[str, Dict]:
    try:
      # 先处理 URL 编码
      decoded_url = urllib.parse.unquote(url)
      ss_link = decoded_url[5:]  # 去掉 "ss://"
      
      # 分离认证信息和服务器信息
      if '@' not in ss_link:
        raise ValueError("Invalid SS URL format")
      
      base64_part, server_part = ss_link.split('@', 1)
      
      # Base64 解码处理
      padding = len(base64_part) % 4
      if padding != 0:
        base64_part += '=' * (4 - padding)
      decoded = base64.b64decode(base64_part).decode('utf-8')
      
      # 提取加密方式和密码
      if ':' not in decoded:
        raise ValueError("Invalid SS auth format")
      method, password = decoded.split(':', 1)
      
      # 先分离备注部分
      if '#' in server_part:
        server_part, remarks = server_part.split('#', 1)
        remarks = urllib.parse.unquote(remarks)
      else:
        remarks = f"SS-{server_part.split(':')[0]}"
      
      # 再分离查询参数
      if '?' in server_part:
        server_port_part, query_part = server_part.split('?', 1)
      else:
        server_port_part, query_part = server_part, ''
      
      # 解析服务器地址和端口
      server, port = server_port_part.rsplit(':', 1)
      port = int(port.strip('/'))
      
      # 构建 Clash 配置
      clash_node = {
        "name": remarks.strip(),
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
      }
      
      # 处理 obfs 插件
      if query_part:
        params = urllib.parse.parse_qs(query_part)
        if 'plugin' in params:
          plugin = urllib.parse.unquote(params['plugin'][0])
          if 'obfs-local' in plugin:
            # 解析 obfs 参数
            plugin_opts = {}
            for param in plugin.split(';')[1:]:
              if '=' in param:
                k, v = param.split('=', 1)
                plugin_opts[k] = v
            
            clash_node.update({
              "plugin": "obfs",
              "plugin-opts": {
                "mode": plugin_opts.get('obfs', 'http'),
                "host": plugin_opts.get('obfs-host', '')
              }
            })
      
      return (remarks, clash_node)
    
    except Exception as e:
      raise ValueError(f"Failed to parse SS URL: {str(e)}")

  @staticmethod
  def vless(url: str) -> Tuple[str, Dict]:
    try:
      vless_link = url[8:]  # 去掉 "vless://"      
      # 分离 UUID 和其他信息
      uuid_info, rest_remark = vless_link.split('@', 1)
      uuid = uuid_info      
      # 分离服务器信息和查询参数
      if '#' in rest_remark:
        rest, remarks = rest_remark.split('#', 1)
      else:
        rest = rest_remark
        remarks = ""      
      # 解析主机地址和端口
      if '?' in rest:
        server_info, query = rest.split('?', 1)
      else:
        server_info = rest
        query = ""      
      server, port = server_info.rsplit(":", 1)
      port = int(port)      
      # 解析查询参数
      params = urllib.parse.parse_qs(query)      
      # 获取查询参数
      encryption = params.get('encryption', ['none'])[0]
      security = params.get('security', [''])[0]
      sni = params.get('sni', [''])[0]
      alpn = params.get('alpn', [''])[0]
      fp = params.get('fp', [''])[0]
      type_ = params.get('type', [''])[0]
      host = params.get('host', [''])[0]
      path = params.get('path', [''])[0]      
      # 处理特殊字符的 path
      if path:
        path = urllib.parse.unquote(path[0])      
      # 提取备注
      remarks = urllib.parse.unquote(remarks).strip() if remarks else f"VLESS-{server}:{port}"      
      # 构建 Clash 配置
      clash_node = {
        "type": "vless",
        "name": remarks,
        "server": server,
        "port": port,
        "uuid": uuid,
        "skip-cert-verify": True,
        "udp": True,
        "tls": security == "tls",
        "network": type_ if type_ else "tcp",
        "servername": sni if sni else host,
      }      
      # 添加 WebSocket 选项
      if type_ == "ws":
        ws_opts = {}
        if path:
          ws_opts["path"] = path
        if host:
          ws_opts["headers"] = {"Host": host}
        if ws_opts:
          clash_node["ws-opts"] = ws_opts      
      # 添加 gRPC 选项
      elif type_ == "grpc":
        if path:
          clash_node["grpc-opts"] = {
            "grpc-service-name": path.lstrip('/')
          }      
      return (remarks, clash_node)    

    except Exception as e:
      raise ValueError(f"Failed to parse VLESS URL: {str(e)}")

  @staticmethod
  def trojan(url: str) -> Tuple[str, dict]:
    trojan_link = url[8:]  # 去掉 "trojan://"
    # 分离密码和其他信息
    password_info, rest = trojan_link.split('@')
    password = password_info
    # 解析主机地址和端口
    server_info, query = rest.split('?')
    server, port = server_info.rsplit(":", 1)
    port = int(port.strip('/'))
    
    # 解析查询参数
    params = urllib.parse.parse_qs(query)
    
    # 获取查询参数（如安全性，类型，头部等）
    security = params.get('security', ['tls'])[0]
    header_type = params.get('headerType', ['none'])[0]
    network_type = params.get('type', ['tcp'])[0]
    
    # 提取备注
    remarks = trojan_link.split('#')[-1]  # 备注在 # 后面
    remarks = urllib.parse.unquote(remarks)  # URL 解码
    # 构建 Clash 配置
    clash_node = {
      "name": remarks,
      "server": server,
      "port": port,
      "type": "trojan",
      "password": password,
      "skip-cert-verify": True,  # 跳过证书验证
      "security": security,  # 使用传入的 security 参数
      "headerType": header_type,  # 使用传入的 headerType 参数
      "network": network_type,  # 使用传入的协议类型
    }
    return ( remarks, clash_node )

  @staticmethod
  def vmess(url: str) -> Tuple[str, dict]:
    vmess_link = url[8:]  # 去掉 "vmess://"
    
    # Base64 解码
    decoded = base64.b64decode(vmess_link).decode('utf-8')
    
    # 将解码后的内容转为字典
    vmess_data = json.loads(decoded)
    
    # 提取需要的字段
    remarks = vmess_data.get("ps", "")  # 从 vmess 数据中提取 ps（备注）
    server = vmess_data.get("add", "")
    port = vmess_data.get("port", 0)
    uuid = vmess_data.get("id", "")
    alter_id = vmess_data.get("aid", 0)
    cipher = vmess_data.get("scy", "auto")
    tls = vmess_data.get("tls", "false") == "true"  # 将 tls 设置为布尔值
    remarks = urllib.parse.unquote(remarks).strip()
    
    # 构建 Clash 配置
    clash_node = {
      "name": remarks,
      "server": server,
      "port": port,
      "type": "vmess",
      "uuid": uuid,
      "alterId": alter_id,
      "cipher": cipher,
      "tls": tls
    }
    return ( remarks, clash_node )

  @staticmethod
  def hysteria2(url: str) -> Tuple[str, dict]:
    # 去掉 "hysteria2://" 前缀
    hysteria2_link = url[11:]  # len("hysteria2://") = 11
    # 分离认证信息和剩余部分
    auth_info, rest = hysteria2_link.split('@', 1)    
    # 密码是 auth_info 部分
    password = auth_info    
    # 分离服务器信息和查询参数
    if '?' in rest:
      server_info, query = rest.split('?', 1)
    else:
      server_info, query = rest, ''    
    # 解析服务器地址和端口
    server, port = server_info.rsplit(':', 1)
    port = int(port.strip('/'))    
    # 解析查询参数
    params = urllib.parse.parse_qs(query)    
    # 获取查询参数
    sni = params.get('sni', [''])[0]
    insecure = params.get('insecure', ['0'])[0] == '1'    
    # 提取备注（可能在 # 后面）
    if '#' in query:
      remarks_part = query.split('#')[-1]
      remarks = urllib.parse.unquote(remarks_part)
    else:
      remarks = f"{server}:{port}"    
    # 构建 Clash 配置
    clash_node = {
        "name": remarks,
        "type": "hysteria2",
        "server": server,
        "port": port,
        "password": password,
        "sni": sni,
        "skip-cert-verify": insecure,
    }    
    # 移除空值参数
    clash_node = {k: v for k, v in clash_node.items() if v or k == 'port'}
    return (remarks, clash_node)

  @staticmethod
  def socks5(url: str) -> Tuple[str, Dict]:
    # 兼容 socks5:// 和 socks:// 前缀
    if url.startswith("socks5://"):
      url = url[8:]  # 去掉 "socks5://"
    elif url.startswith("socks://"):
      url = url[7:]  # 去掉 "socks://"
    else:
      raise ValueError("Invalid SOCKS URL format")
    
    # 分离认证信息（如果有）和服务器信息
    if '@' in url:
      auth_info, server_info = url.split('@', 1)
      if ':' in auth_info:
        username, password = auth_info.split(':', 1)
      else:
        username, password = auth_info, ""  # 处理只有用户名的情况
    else:
      server_info = url
      username, password = "", ""  # 无认证信息
    
    # 解析服务器地址和端口
    if '#' in server_info:
      server_part, remarks = server_info.split('#', 1)
      server, port = server_part.rsplit(':', 1)
      remarks = urllib.parse.unquote(remarks)
    else:
      server, port = server_info.rsplit(':', 1)
      remarks = f"SOCKS-{server}:{port}"
    
    port = int(port.strip('/'))
    
    # 构建 Clash 配置
    clash_node = {
      "name": remarks,
      "type": "socks5",
      "server": server,
      "port": port,
    }
    
    # 添加认证信息（如果有）
    if username:
      clash_node["username"] = username
    if password:
      clash_node["password"] = password
    
    return (remarks, clash_node)

class CollectNodes(ParseNode):

  def __init__(self) -> None:
    super().__init__()
    self.nodes = []  
    self.HK_nodes = [] # 香港节点
    self.JP_nodes = [] # 日本节点
    self.US_nodes = [] # 美国节点
    self.TW_nodes = [] # 台湾节点 
    self.SG_nodes = [] # 狮城节点
    self.KR_nodes = [] # 韩国节点

    self.remarks = []  
    self.HK_remarks = [] # 香港节点
    self.JP_remarks = [] # 日本节点
    self.US_remarks = [] # 美国节点
    self.TW_remarks = [] # 台湾节点 
    self.SG_remarks = [] # 狮城节点
    self.KR_remarks = [] # 韩国节点

    self.custom_remarks = {}

    self.node_list = [ "nodes", "HK_nodes", "JP_nodes", "US_nodes", "TW_nodes", "SG_nodes", "KR_nodes" ]
    self.remark_list = [ "remarks", "HK_remarks", "JP_remarks", "US_remarks", "TW_remarks", "SG_remarks", "KR_remarks" ]

    self.keys_map = {}
    self.parse_node = lambda x: x

  def parse_custom_group(self, data: List[Tuple[str]], node_remark: str) -> None:
    for remark, pattern in data:
      if pattern in node_remark:
        self.custom_remarks.setdefault(remark, []).append(node_remark)

  def parse(self, urls: list):
    for url in urls:
      url = url.strip()
      if url == "":
        continue
      elif "edtunnel" in url:
        continue
      elif url.startswith("ss://"):
        self.parse_node = self.ss
      elif url.startswith("vless://"):
        self.parse_node = self.vless
      elif url.startswith("trojan://"):
        self.parse_node = self.trojan
      elif url.startswith("vmess://"):
        self.parse_node = self.vmess
      elif url.startswith("hysteria2://"):
        self.parse_node = self.hysteria2
      elif url.startswith("socks"):
        self.parse_node = self.socks5
      else:
        continue
      try:
        remark, node = self.parse_node(url)
      except Exception as e:
        print("节点转换失败：", e.args)
        print(url)
        continue
      if remark in self.keys_map:
        node["name"] = f"{remark}_{self.keys_map[remark]}"
        self.keys_map[remark] += 1
      else:
        self.keys_map[remark] = 1

      node_str = json.dumps(node, ensure_ascii=False)
      self.nodes.append(node_str)
      remark_with = node["name"]
      if " " in node["name"]:
        remark_with = f'"{remark_with}"'

      self.remarks.append(remark_with)
      
      if re.search(r'HK|香|港|香港|🇭🇰', remark_with, flags=re.I):
        # self.HK_nodes.append(node_str)
        self.HK_remarks.append(remark_with)
      elif re.search(r'JP|日|日本|🇯🇵', remark_with, flags=re.I):
        # self.JP_nodes.append(node_str)
        self.JP_remarks.append(remark_with)
      elif re.search(r'US|UM|美|美国|美國|🇺🇲', remark_with, flags=re.I):
        # self.US_nodes.append(node_str)
        self.US_remarks.append(remark_with)
      elif re.search(r'TW|台|臺|台湾|臺灣|🇨🇳|🇹🇼', remark_with, flags=re.I):
        # self.TW_nodes.append(node_str)
        self.TW_remarks.append(remark_with)
      elif re.search(r'SG|新|狮城|獅城|新加坡|🇸🇬', remark_with, flags=re.I):
        # self.SG_nodes.append(node_str)
        self.SG_remarks.append(remark_with)
      elif re.search(r'KR|韩|韩国|韓國|🇰🇷', remark_with, flags=re.I):
        # self.KR_nodes.append(node_str)
        self.KR_remarks.append(remark_with)
        
    print(f"节点总数: {len(self.remarks)}\t"
          f"HK: {len(self.HK_remarks)}\t"
          f"JP: {len(self.JP_remarks)}\t"
          f"US: {len(self.US_remarks)}\t"
          f"TW: {len(self.TW_remarks)}\t"
          f"SG: {len(self.SG_remarks)}\t"
          f"KR: {len(self.KR_remarks)}")
    return self




