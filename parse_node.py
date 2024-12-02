import base64
import json
import re
import urllib.parse
from typing import Dict, List, Tuple


class ParseNode:

  @staticmethod
  def ss(url: str) -> Tuple[str, dict]:
    ss_link = url[5:]  # 去掉 "ss://"
    # 进行 Base64 解码，添加必要的填充
    base64_str = ss_link.split('@')[0]
    padding = len(base64_str) % 4
    if padding != 0:
      base64_str += '=' * (4 - padding)
    # 进行 Base64 解码
    decoded_bytes = base64.b64decode(base64_str)
    decoded_string = decoded_bytes.decode('utf-8')

    # 提取加密方式和密码
    server, port_with_remark = ss_link.split('@')[1].split(':', 1)
    method, password = decoded_string.split(':')
    port, remark = port_with_remark.split('#')
    remarks = urllib.parse.unquote(remark).strip()

    # 构建 Clash 配置
    clash_node = {
      "name": remarks,
      "server": server.rsplit(":", 1)[0],
      "port": port,
      "type": "ss",
      "cipher": method,
      "password": password
    }

    return ( remarks, clash_node )

  @staticmethod
  def vless(url: str) -> Tuple[str, dict]:
    vless_link = url[8:]  # 去掉 "vless://"
    # 分离 UUID 和其他信息
    uuid_info, rest_remark = vless_link.split('@')
    rest, remarks = rest_remark.split('#')
    uuid = uuid_info
    # 解析主机地址和端口
    server_info, query = rest.split('?')
    server, port = server_info.rsplit(":", 1)
    port = int(port)
    # 解析查询参数
    params = urllib.parse.parse_qs(query)    
    # 获取查询参数（加密方法，安全性，sni 等）
    encryption = params.get('encryption', ['none'])[0]
    security = params.get('security', ['tls'])[0]
    sni = params.get('sni', [''])[0]
    alpn = params.get('alpn', [''])[0]
    fp = params.get('fp', [''])[0]
    host = params.get('host', [''])[0]
    path = urllib.parse.unquote(params.get('path', [''])[0])
    # 提取备注
    remarks = urllib.parse.unquote(remarks).strip()
    # 构建 Clash 配置
    clash_node = {
      "type": "vless",
      "name": remarks,
      "server": server,
      "port": port,
      "uuid": uuid,
      "skip-cert-verify": True,  # 跳过证书验证
      "udp": True,  # 支持 UDP
      "tls": True if security == "tls" else False,  # TLS 安全连接
      "network": "ws",  # WebSocket 协议
      "servername": sni,  # 服务器名称
      "ws-opts": {
        "path": path,  # WebSocket 路径
        "headers": {
          "host": host  # WebSocket 请求头的 host
        }
      }
    }
    return ( remarks, clash_node )

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


class CollectNodes(ParseNode):
  nodes = []  
  HK_nodes = [] # 香港节点
  JP_nodes = [] # 日本节点
  US_nodes = [] # 美国节点
  TW_nodes = [] # 台湾节点 
  SG_nodes = [] # 狮城节点
  KR_nodes = [] # 韩国节点

  remarks = []  
  HK_remarks = [] # 香港节点
  JP_remarks = [] # 日本节点
  US_remarks = [] # 美国节点
  TW_remarks = [] # 台湾节点 
  SG_remarks = [] # 狮城节点
  KR_remarks = [] # 韩国节点

  custom_remarks = {}

  node_list = [ "nodes", "HK_nodes", "JP_nodes", "US_nodes", "TW_nodes", "SG_nodes", "KR_nodes" ]
  remark_list = [ "remarks", "HK_remarks", "JP_remarks", "US_remarks", "TW_remarks", "SG_remarks", "KR_remarks" ]

  keys_map = {}

  parse_node = lambda x: x

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
        
    print(f"节点总数: {len(self.nodes)}\t"
          f"HK: {len(self.HK_nodes)}\t"
          f"JP: {len(self.JP_nodes)}\t"
          f"US: {len(self.US_nodes)}\t"
          f"TW: {len(self.TW_nodes)}\t"
          f"SG: {len(self.SG_nodes)}\t"
          f"KR: {len(self.KR_nodes)}")
    return self




