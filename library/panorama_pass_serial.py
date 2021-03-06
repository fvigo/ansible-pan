#!/usr/bin/env python

#  Copyright 2018 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

DOCUMENTATION = '''
---
module: panrama_pass_serial
short_description: change password & serial number of Panorama VM using SSH with SSH key
description:
    - Change the password and serial number of Panorama VM
    - Useful for AWS instances where the first login should be done via SSH.
author: "Luigi Mori (@jtschichold), Ivan Bojer (@ivanbojer), Francesco Vigo (@fvigo)"
version_added: "2.3"
requirements:
    - paramiko
options:
    ip_address:
        description:
            - IP address (or hostname) of PAN-OS device
        required: true
    username:
        description:
            - username for initial authentication
        required: false
        default: "admin"
    key_filename:
        description:
            - filename of the SSH Key to use for authentication
        required: true
    newpassword:
        description:
            - password to configure for admin on the Panorama device
        required: true
    serial:
        description:
            - serial number to add to Panorama VM
        required: true
'''

EXAMPLES = '''
# Tries for 10 times to set the admin password of 192.168.1.1 to "badpassword" and serial to "1234567"
# via SSH, authenticating using key /tmp/ssh.key
- name: set admin password
  panos_admpwd:
    ip_address: "192.168.1.1"
    username: "admin"
    key_filename: "/tmp/ssh.key"
    newpassword: "badpassword"
    serial: 1234567
  register: result
  until: not result|failed
  retries: 10
  delay: 30
'''

RETURN = '''
status:
    description: success status
    returned: success
    type: string
    sample: "Last login: Fri Sep 16 11:09:20 2016 from 10.35.34.56.....Configuration committed successfully"
'''

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


from ansible.module_utils.basic import AnsibleModule
import time
import sys

try:
    import paramiko
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

_PROMPTBUFF = 4096


def wait_with_timeout(module, shell, prompt, timeout=60):
    now = time.time()
    result = b""
    while True:
        if shell.recv_ready():
            result += shell.recv(_PROMPTBUFF)
            resultstr = result.decode("utf-8")
            endresult = resultstr.strip()
            if len(endresult) != 0 and endresult[-1] == prompt:
                break

        if time.time() - now > timeout:
            module.fail_json(msg="Timeout waiting for prompt")

    return resultstr


def set_panwfw_password(module, ip_address, key_filename, newpassword, username, serial):
    stdout = ""

    ssh = paramiko.SSHClient()

    # add policy to accept all host keys, I haven't found
    # a way to retrieve the instance SSH key fingerprint from AWS
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh.connect(ip_address, username=username, key_filename=key_filename)
    shell = ssh.invoke_shell()

    # wait for the shell to start
    buff = wait_with_timeout(module, shell, ">")
    stdout += buff

    # set serial number
    shell.send('set serial-number ' + serial + '\n')
    # wait for the prompt
    buff = wait_with_timeout(module, shell, ">")
    stdout += buff
    if 'cfg.platform.serial' not in buff:
        module.fail_json(msg="Error setting serial number: " + stdout)

    # step into config mode
    shell.send('configure\n')
    # wait for the config prompt
    buff = wait_with_timeout(module, shell, "#")
    stdout += buff

    if module.check_mode:
        # exit and close connection
        shell.send('exit\n')
        ssh.close()
        return False, 'Connection test successful. Password left intact.'

    # set admin password
    shell.send('set mgt-config users ' + username + ' password\n')

    # wait for the password prompt
    buff = wait_with_timeout(module, shell, ":")
    stdout += buff

    # enter password for the first time
    shell.send(newpassword + '\n')

    # wait for the password prompt
    buff = wait_with_timeout(module, shell, ":")
    stdout += buff

    # enter password for the second time
    shell.send(newpassword + '\n')

    # wait for the config mode prompt
    buff = wait_with_timeout(module, shell, "#")
    stdout += buff

    # commit !
    shell.send('commit\n')

    # wait for the prompt
    buff = wait_with_timeout(module, shell, "#", 120)
    stdout += buff

    if 'success' not in buff:
        module.fail_json(msg="Error setting " + username + " password: " + stdout)

    # exit
    shell.send('exit\n')

    ssh.close()

    return True, stdout


def main():
    argument_spec = dict(
        ip_address=dict(required=True),
        username=dict(default='admin'),
        key_filename=dict(required=True),
        newpassword=dict(no_log=True, required=True),
        serial=dict(no_log=True, required=True)
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    if not HAS_LIB:
        module.fail_json(msg='paramiko is required for this module')

    ip_address = module.params["ip_address"]
    if not ip_address:
        module.fail_json(msg="ip_address should be specified")
    key_filename = module.params["key_filename"]
    if not key_filename:
        module.fail_json(msg="key_filename should be specified")
    newpassword = module.params["newpassword"]
    if not newpassword:
        module.fail_json(msg="newpassword is required")
    username = module.params['username']
    serial = module.params["serial"]
    if not serial:
        module.fail_json(msg="serial is required")

    try:
        changed, stdout = set_panwfw_password(module, ip_address, key_filename, newpassword, username, serial)
        module.exit_json(changed=changed, stdout=stdout)
    except Exception:
        x = sys.exc_info()[1]
        module.fail_json(msg=x)


if __name__ == '__main__':
    main()