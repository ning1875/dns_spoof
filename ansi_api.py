from collections import namedtuple

from ansible.parsing.dataloader import DataLoader
from ansible.vars import VariableManager
from ansible.inventory import Inventory
from ansible.utils.vars import load_extra_vars
from ansible.utils.vars import load_options_vars
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.plugins.callback import CallbackBase


class ResultsCollector(CallbackBase):
    def __init__(self, *args, **kwargs):
        super(ResultsCollector, self).__init__(*args, **kwargs)
        self.host_ok = {}
        self.host_unreachable = {}
        self.host_failed = {}

    def v2_runner_on_unreachable(self, result):
        self.host_unreachable[result._host.get_name()] = result

    def v2_runner_on_ok(self, result, *args, **kwargs):
        self.host_ok[result._host.get_name()] = result

    def v2_runner_on_failed(self, result, *args, **kwargs):
        self.host_failed[result._host.get_name()] = result


# class PlaybookApi(PlaybookExecutor):
class PlaybookApi(PlaybookExecutor):
    def __init__(self, host_list, yaml_path, extra_vars):
        self.host_list = host_list
        self.yaml_path = yaml_path
        # self.kcache_path = kcache_path

        self.callback = ResultsCollector()
        self.extra_vars = extra_vars
        self.IpmiPlay()
        super(PlaybookApi, self).__init__(playbooks=[self.yaml_path], inventory=self.inventory,
                                          variable_manager=self.variable_manager,
                                          loader=self.loader, options=self.options, passwords={})
        self._tqm._stdout_callback = self.callback

    def IpmiPlay(self):
        Options = namedtuple('Options',
                             ['listtags', 'listtasks', 'listhosts', 'syntax', 'connection', 'module_path', 'forks',
                              'remote_user', 'private_key_file', 'ssh_common_args', 'ssh_extra_args',
                              'sftp_extra_args', 'scp_extra_args', 'become',
                              'become_method',
                              'become_user',
                              'verbosity', 'check', 'extra_vars'])
        self.options = Options(listtags=False, listtasks=False, listhosts=False, syntax=False, connection='ssh',
                               module_path=None,
                               forks=10, remote_user='',
                               private_key_file=None,
                               ssh_common_args='',
                               ssh_extra_args='',
                               sftp_extra_args='',
                               scp_extra_args='',
                               become=True,
                               become_method='sudo',
                               become_user='root',
                               verbosity=3,
                               check=False,
                               extra_vars={})

        self.loader = DataLoader()

        # create the variable manager, which will be shared throughout
        # the code, ensuring a consistent view of global variables
        variable_manager = VariableManager()
        variable_manager.extra_vars = load_extra_vars(loader=self.loader, options=self.options)
        variable_manager.options_vars = load_options_vars(self.options)
        self.variable_manager = variable_manager
        # create the inventory, and filter it based on the subset specified (if any)
        self.inventory = Inventory(loader=self.loader, variable_manager=self.variable_manager, host_list=self.host_list)
        self.variable_manager.set_inventory(self.inventory)
        self.variable_manager.extra_vars = self.extra_vars

    def get_result(self):
        # print("calling in get_result")
        self.results_raw = {'success': {}, 'failed': {}, "unreachable": {}}
        for host, result in self.callback.host_ok.items():
            self.results_raw['success'][host] = result
        for host, result in self.callback.host_failed.items():
            self.results_raw['failed'][host] = result
        for host, result in self.callback.host_unreachable.items():
            self.results_raw['unreachable'][host] = result._result['msg']
        return self.results_raw


if __name__ == '__main__':
    h = ["127.0.0.1"]
    yaml = "systemd_stop.yaml"

    api = PlaybookApi(h, yaml, {"app": "falcon-judge"})
    api.run()
    res = api.get_result()
    for k, v in res.items():
        for kk, vv in v.items():
            print(kk, vv._result)
