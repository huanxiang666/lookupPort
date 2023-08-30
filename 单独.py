import socket
import dns.resolver
import re


def is_valid_ip(address):  # 判断IP地址
    pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(pattern, address):
        return True
    else:
        return False


def resolve_dns_with_fallback(domain):
    try:
        # 创建 DNS 解析器
        resolver = dns.resolver.Resolver()

        # 尝试解析 A 记录
        try:
            a_records = resolver.resolve(domain, 'A')
            server_address_a = str(a_records[0])
            return server_address_a
        except dns.resolver.NoAnswer:
            pass  # 没有 A 记录，继续尝试解析 CNAME 记录
        except dns.exception.DNSException as e:
            print("Error resolving A record:", e)

        # 尝试解析 CNAME 记录
        try:
            cname_records = resolver.resolve(domain, 'CNAME')
            cname_target = str(cname_records[0].target).rstrip('.')
            # 递归解析 CNAME 记录的目标
            return resolve_dns_with_fallback(cname_target)
        except dns.resolver.NoAnswer:
            pass  # 没有 CNAME 记录，继续尝试解析 AAAA 记录
        except dns.exception.DNSException as e:
            print("Error resolving CNAME record:", e)

        # 尝试解析 AAAA 记录
        try:
            aaaa_records = resolver.resolve(domain, 'AAAA')
            server_address_aaaa = str(aaaa_records[0])
            return server_address_aaaa
        except dns.resolver.NoAnswer:
            pass  # 没有 AAAA 记录，解析失败
        except dns.exception.DNSException as e:
            print("Error resolving AAAA record:", e)

        return None  # 所有尝试都失败，返回 None

    except dns.exception.DNSException as e:
        print("Error:", e)
        return None


def scanner(ip):
    target_ports = [21, 22, 23, 25, 53, 69, 80, 107, 135, 139, 110, 443, 888, 666, 1433, 3306, 3309, 3389, 8080,
                    8888, 19132, 25565]
    for port in target_ports:
        run(ip,port)

def run(ip,port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        print(f"端口 {port} 开放")
        s.close()
    except socket.timeout:
        print(f"端口 {port} X")
    except socket.error as e:
        if e.errno == 10061:  # 端口未开放
            print(f"端口 {port} x")
        else:
            print(f"忽略错误: {e}")


ip = input("请输入ip或者域名\n")
port2 = int(input("请输入端口\n"))
if is_valid_ip(ip):
    print(ip)
else:
    ip = resolve_dns_with_fallback(ip)
    print(ip)
run(ip,port2)
while True:
    user_input = input("请选择一个选项（1扫端口、2扫默认端口、3关闭）：")

    if user_input == "1":
        port2 = int(input("请输入端口\n"))
        run(ip, port2)

    elif user_input == "2":
        print("你选择了选项2")
        scanner(ip)

    elif user_input == "3":
        print("关闭程序")
        # 在这里添加选项3的代码
        break  # 结束循环

    else:
        print("无效的输入，请输入1、2或3")
