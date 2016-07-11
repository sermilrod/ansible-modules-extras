#!/usr/bin/python
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: jenkins_job
short_description: Manage jenkins jobs
description:
    - Manage Jenkins jobs by using Jenkins REST API
requirements:
  - "python-jenkins >= 0.4.12"
  - "lxml >= 3.3.3"
version_added: "2.2"
author: "Sergio Millan Rodriguez"
options:
  config_file:
    description:
      - Absolute path to the config.xml for an specific job.
    required: true
  name:
    description:
      - Name of the Jenkins job.
    required: true
  password:
    description:
      - Password to authenticate with the Jenkins server.
    required: false
  state:
    description:
      - Action to take with the Jenkins job.
    required: false
    choices: ['present', 'absent', 'disabled']
    default: present
  token:
    description:
      - API token used to authenticate alternatively to password.
    required: false
  url:
    description:
      - Url where the Jenkins server is accessible.
    required: false
    default: http://localhost:8080
  user:
    description:
       - User to authenticate with the Jenkins server.
    required: false
'''

EXAMPLES = '''
# Create a jenkins job using basic authentication
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    password: admin
    state: present
    url: "http://localhost:8080"
    user: admin

# Create a jenkins job using the token
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    token: asdfasfasfasdfasdfadfasfasdfasdfc
    state: present
    url: "http://localhost:8080"
    user: admin

# Delete a jenkins job using basic authentication
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    password: admin
    state: absent
    url: "http://localhost:8080"
    user: admin

# Delete a jenkins job using the token
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    token: asdfasfasfasdfasdfadfasfasdfasdfc
    state: present
    url: "http://localhost:8080"
    user: admin

# Disable a jenkins job using basic authentication
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    password: admin
    state: disabled
    url: "http://localhost:8080"
    user: admin

# Disable a jenkins job using the token
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    token: asdfasfasfasdfasdfadfasfasdfasdfc
    state: disabled
    url: "http://localhost:8080"
    user: admin

# To re-enable a job just make it be present
- jenkins_job:
    config_file: /path/to/config.xml
    name: test
    password: admin
    state: present
    url: "http://localhost:8080"
    user: admin

# A production ready example
- template:
    src: test-job.xml.j2
    dest: /tmp/test-job-config.xml
    mode: 0644
    owner: jenkins
    group: jenkins

- jenkins_job:
    config_file: /tmp/test-job-config.xml
    name: test-job
    token: abcdefghijklmnopqrstuvwxyz
    state: present
    url: "https://jenkins.mydomain.com"
    user: my_user
'''

RETURN = '''
'''

try:
    import jenkins
    python_jenkins_installed = True
except ImportError:
    python_jenkins_installed = False

try:
    from lxml import etree as ET
    python_lxml_installed = True
except ImportError:
    python_lxml_installed = False

class Jenkins:
    def __init__(self, config_file, name, password, state, token, url, user):
        self.config_file = config_file
        self.name = name
        self.password = password
        self.state = state
        self.token = token
        self.user = user
        self.jenkins_url = url
        self.server = self.get_jenkins_connection()

    def get_jenkins_connection(self):
        try:
            if (self.user and self.password):
                return jenkins.Jenkins(self.jenkins_url, self.user, self.password)
            elif (self.user and self.token):
                return jenkins.Jenkins(self.jenkins_url, self.user, self.token)
            elif (self.user and not (self.password or self.token)):
                return jenkins.Jenkins(self.jenkins_url, self.user)
            else:
                return jenkins.Jenkins(self.jenkins_url)
        except Exception:
            e = get_exception()
            module.fail_json(msg='Unable to connect to Jenkins server, %s' % str(e))

    def get_job_status(self, module):
        try:
            return self.server.get_job_info(self.name)['color'].encode('utf-8')
        except Exception:
            e = get_exception()
            module.fail_json(msg='Unable to fetch job information, %s' % str(e))

    def job_exists(self, module):
        try:
            return bool(self.server.job_exists(self.name))
        except Exception:
            e = get_exception()
            module.fail_json(msg='Unable to validate if job exists, %s for %s' % (str(e), self.jenkins_url))

    def build(self, module):
        if self.state == 'present':
            self.update_job(module)
        elif self.state == 'absent':
            self.delete_job(module)
        else:
            self.disable_job(module)

    def configuration_changed(self):
        changed = False
        config_file = xml_to_string(self.config_file)
        machine_file = job_config_to_string(self.server.get_job_config(self.name).encode('utf-8'))
        if not machine_file == config_file:
            changed = True

        return changed

    def update_job(self, module):
        if not self.job_exists(module):
            self.create_job(module)
        else:
            self.reconfig_job(module)

    def reconfig_job(self, module):
        changed = False
        if self.configuration_changed():
            changed = True
            if not module.check_mode:
                try:
                    self.server.reconfig_job(self.name, xml_to_string(self.config_file))
                except Exception:
                    e = get_exception()
                    module.fail_json(msg='Unable to reconfigure job, %s for %s' % (str(e), self.jenkins_url))

        module.exit_json(changed=changed, name=self.name, state=self.state, url=self.jenkins_url)

    def create_job(self, module):
        changed = False
        try:
            changed = True
            if not module.check_mode:
                self.server.create_job(self.name, xml_to_string(self.config_file))
        except Exception:
            e = get_exception()
            module.fail_json(msg='Unable to create job, %s for %s' % (str(e), self.jenkins_url))

        module.exit_json(changed=changed, name=self.name, state=self.state, url=self.jenkins_url)

    def delete_job(self, module):
        changed = False
        if self.job_exists(module):
            changed = True
            if not module.check_mode:
                try:
                    self.server.delete_job(self.name)
                except Exception:
                    e = get_exception()
                    module.fail_json(msg='Unable to delete job, %s for %s' % (str(e), self.jenkins_url))

        module.exit_json(changed=changed, name=self.name, state=self.state, url=self.jenkins_url)

    def disable_job(self, module):
        changed = False
        if self.job_exists(module):
            status = self.get_job_status(module)
            try:
                if status != "disabled":
                    changed = True
                    if not module.check_mode:
                        self.server.disable_job(self.name)
            except Exception:
                e = get_exception()
                module.fail_json(msg='Unable to disable job, %s for %s' % (str(e), self.jenkins_url))

        module.exit_json(changed=changed, name=self.name, state=self.state, url=self.jenkins_url)

def test_dependencies(module):
    if not python_jenkins_installed:
        module.fail_json(msg="python-jenkins required for this module. "\
              "see http://python-jenkins.readthedocs.io/en/latest/install.html")

    if not python_lxml_installed:
        module.fail_json(msg="lxml required for this module. "\
              "see http://lxml.de/installation.html")

def job_config_to_string(xml_str):
    return ET.tostring(ET.fromstring(xml_str))

def xml_to_string(source):
    return ET.tostring(ET.parse(source).getroot())

def jenkins_builder(module):
    if module.params.get('name') and module.params.get('config_file') and module.params.get('url'):
        return Jenkins(
            module.params.get('config_file'),
            module.params.get('name'),
            module.params.get('password'),
            module.params.get('state'),
            module.params.get('token'),
            module.params.get('url'),
            module.params.get('user')
        )
    else:
        module.fail_json(msg='name, state, url are required: name=%s, config_file=%s, url=%s' % (
                            module.params.get('name'),
                            module.params.get('config_file'),
                            module.params.get('url'),
                            str(e)))

def main():
    module = AnsibleModule(
        argument_spec = dict(
            config_file = dict(required=True, type='path'),
            name        = dict(required=True),
            password    = dict(required=False, no_log=True),
            state       = dict(required=False, default='present', choices=['present', 'absent', 'disabled']),
            token       = dict(required=False, no_log=True),
            url         = dict(required=False, default="http://localhost:8080"),
            user        = dict(required=False)
        ),
        mutually_exclusive = [['password', 'token']],
        supports_check_mode=True,
    )

    test_dependencies(module)
    jenkins = jenkins_builder(module)
    jenkins.build(module)

from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
