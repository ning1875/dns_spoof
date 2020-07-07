#!/usr/bin/python
# coding:utf-8
import dns.resolver
import sys

# 配置想要check的重要常用主域域名
G_TARGET_LIST = [
    'xxxx.xxx.xxx',
]


def query(servers, target_name):
    ans_set = set()
    try:

        my_resolver = dns.resolver.Resolver()
        my_resolver.timeout = 3
        my_resolver.nameservers = servers

        answers = my_resolver.query(target_name, raise_on_no_answer=False, lifetime=3)

        for ipval in answers:
            # print('IP', ipval.to_text())
            ans_set.add(ipval.to_text())
    except Exception as e:
        print(servers, target_name, e)
    finally:
        return ans_set


def run_diff(online_server, test_server):
    all_num = len(G_TARGET_LIST)
    for index, name in enumerate(G_TARGET_LIST):
        print("[{}/{}]正在检查:for name:{}".format(index + 1, all_num, name))
        online_ans_set = query(online_server, name)
        test_ans_set = query(test_server, name)
        if online_ans_set != test_ans_set:
            print("[test_failed:name:{}] detail:online:{} res:{}||| test:{} res:{} ".format(name, online_server,
                                                                                            online_ans_set,
                                                                                            test_server,
                                                                                            test_ans_set, ))
            sys.exit(2)


if __name__ == "__main__":
    import sys

    online_server = ["127.0.0.1"]
    test_server = [sys.argv[1]]
    run_diff(online_server, test_server)
