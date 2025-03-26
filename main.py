import base64
import os
import re
import requests
import yaml
import csv
from typing import Any, Callable, List, Dict, Optional, Union

from parse_node import CollectNodes


headers = {
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
}

class ClashConfig:
  
  @staticmethod
  def read_yaml(file: str) -> Optional[Dict]:
    with open(file, 'r', encoding="utf-8") as f:
      return yaml.safe_load(f)
  
  @staticmethod
  def write_yaml(data: Dict, file: str) -> None:
    with open(file, 'w+', encoding="utf-8") as f:
      yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

  @staticmethod
  def read_local(file: str) -> str:
    with open(file, "r", encoding="utf-8") as f:
      nodes = f.read().strip()
      try:
        d_bytes = base64.b64decode(nodes)
        return d_bytes.decode('utf-8')
      except Exception as e:
        print('local解码错误：', e.args)
        return nodes

  # configs: dict = {}
  # proxy_groups: dict = {}
  urls_pools: list = []
  local_dir = 'local_nodes'
  o_node = CollectNodes()

  @classmethod
  def to_yaml(cls, data: Any, indent: int = 0) -> str:
    """
    递归地将数据转换为 YAML 格式的字符串。
    
    :param data: 数据，可能是字典、列表或其他类型。
    :param indent: 当前的缩进级别，用于格式化输出。
    :return: 生成的 YAML 格式字符串。
    """
    indent_str = ' ' * indent
    if isinstance(data, dict):
      yaml_str = '\n'
      for key, value in data.items():
        yaml_str += f"{indent_str}{key}: {cls.to_yaml(value, indent + 2)}\n"
      return yaml_str
    elif isinstance(data, list):
      yaml_str = '\n'
      for item in data:
        yaml_str += f"{indent_str}- {cls.to_yaml(item, indent + 2)}\n"
      return yaml_str
    elif data is None:
      return "null"
    else:
      return str(data)

  @classmethod
  def get_scribe(cls, url: str) -> str:
    try:
      with requests.get(url, timeout=10, headers=headers) as res:
        if res.status_code < 300:
          print("节点请求成功: ", url)
          nodes = res.text.strip()
          try:
            d_bytes = base64.b64decode(nodes)
            return d_bytes.decode('utf-8')
          except Exception as e:
            print('scribe解码错误：', e.args)
            return nodes
        else:
          print("链接请求错误：", res.status_code, url)
          return None
    except Exception as e:
      print(e.args)
      return cls.get_scribe(url)

  @classmethod
  def get_single_sub(cls, key: str, urls: List[str]) -> None:
    print(f"订阅 {key} 有 {len(urls)} 个节点")
    node_obj = CollectNodes().parse(urls)
    configs = cls.read_yaml('./yaml_files/configs.yaml')
    proxy_groups = cls.read_yaml('./yaml_files/proxy_groups.yaml')["proxy-groups"]
    if node_obj.nodes:
      configs["proxies"] = node_obj.nodes
      proxy_groups[1]["proxies"] = node_obj.remarks
      proxy_groups[2]["proxies"] = node_obj.remarks
      proxy_groups[3]["proxies"] = node_obj.remarks
      proxy_groups[4]["proxies"] = node_obj.remarks
      configs["rules"] = cls.read_yaml('./yaml_files/custom_rules.yaml')["rules"]
    else:
      return
    if node_obj.HK_remarks:
      proxy_groups[26]["proxies"] = node_obj.HK_remarks
    if node_obj.JP_remarks:
      proxy_groups[27]["proxies"] = node_obj.JP_remarks
    if node_obj.US_remarks:
      proxy_groups[28]["proxies"] = node_obj.US_remarks
    if node_obj.TW_remarks:
      proxy_groups[29]["proxies"] = node_obj.TW_remarks
    if node_obj.SG_remarks:
      proxy_groups[30]["proxies"] = node_obj.SG_remarks
    if node_obj.KR_remarks:
      proxy_groups[31]["proxies"] = node_obj.KR_remarks
    configs["proxy-groups"] = proxy_groups

    yaml_str = re.sub(r'[\r\n]+', '\n', cls.to_yaml(configs), flags=re.S) 
    yaml_str = re.sub(r'^(.*?-)[\s\r\n]+', r'\1 ', yaml_str, flags=re.M)
    with open(f"sub/{key}.yaml", "w+", encoding="utf-8") as f:
      f.write(yaml_str)
    os.system(f"tail -n +2 yaml_files/rules.yaml >> sub/{key}.yaml")

  @classmethod
  def run(cls):
    os.makedirs('sub', exist_ok=True)
    with open("urls.csv", "r", encoding="utf-8") as urls_path:
      urls_csv = csv.reader(urls_path)
      for row in urls_csv:
        key, url, valid = row
        if valid != '1':
          continue
        cc = cls.get_scribe(url.strip())
        if cc:
          _urls = cc.split('\n')
          cls.urls_pools += _urls
          cls.get_single_sub(key, _urls)
    
    for file in os.listdir(cls.local_dir):
      key = os.path.splitext(os.path.basename(file))[0]
      cc = cls.read_local(os.path.join(cls.local_dir,  file))
      if cc:
        _urls = cc.split('\n')
        cls.urls_pools += _urls
        cls.get_single_sub(key, _urls)

    cls.get_single_sub("clash", cls.urls_pools)


if __name__ == '__main__':
  # main()
  ClashConfig.run()