# Running the Ansible Playbook to check STIG

```bash
ansible-playbook -i localhost, --check playbook.yml
```

If you want to see the details of the checks (what would be changed) add the `--diff` flag:

```bash
ansible-playbook -i localhost, --check --diff playbook.yml
```
