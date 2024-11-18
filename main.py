import requests


url = "https://suo.yt/0PKQ4Yf"

headers = {
  "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
}

def main():
  try:
    with requests.get(url, timeout=10, headers=headers) as res:
      if res.status_code < 300:
        with open('clash.yaml', mode="w+", encoding="utf-8") as f:
          f.write(res.text)
          print("节点保存成功")
      else:
        print("链接请求错误：", res.status_code)
  except Exception as e:
    print(e.args)
    main()


if __name__ == '__main__':
  main()