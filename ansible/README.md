# TOSS 4 STIG Ansible Playbook

## Dependencies

This ansible playbook relies on a few Ansible Galaxy libraries. You can install them with the following commands:

```
ansible-galaxy collection install ansible.posix
ansible-galaxy collection install community.general
```

## Running the Ansible Playbook to check STIG

```bash
ansible-playbook -i localhost, --check playbook.yml
```

If you want to see the details of the checks (what would be changed) add the `--diff` flag:

```bash
ansible-playbook -i localhost, --check --diff playbook.yml
```

## Contributing new controls to the playbook

With the help of our parser code (`$REPO_ROOT/parser`) we've been able to create stubs of all of the controls that need to be implemented with a bunch of boilerplate code/metadata built in (see `$REPO_ROOT/parser/output/TOSS*.yml`).

If you are interested in providing an implementation for a control, fork the repo, choose one of the controls from `parser/output/` and move it in to the ansible role with the following:

```bash
cd $(git rev-parse --show-toplevel)
git mv parser/output/$YOUR_CHOICE ansible/roles/stig/tasks/
```

And then add the missing implementation to that task. Once that implementation is ready, add the control to the list of implemented `controls` listed out in `ansible/roles/stig/defaults/main.yml` (approximately line 3).

Push those changes to a branch, and submit a pull request, and you'll be off and running!

## Notes / Guidance

Some controls can not be checked automatically, and require manually validating. These controls are tagged with the `manual-control` tag, and print a debug message in place of either succeeding or failing.
