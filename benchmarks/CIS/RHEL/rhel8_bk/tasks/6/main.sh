host_file=/home/ansible/rhelHOST
playbook_directory="/home/ansible/playbooks/cis/rhel8_bk/tasks/6"

echo "6 System Maintence"

# 4.1 Configure System Accounting (auditd)
# Pg. 604
echo "6.1 | System File Permissions"
ansible-playbook -i  $host_file $playbook_directory/file_permissions.yml

echo "6.2 | User and group settings"
ansible-playbook -i  $host_file $playbook_directory/user_group_settings.yml

