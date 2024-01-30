host_file=/home/ansible/rhelHOST
playbook_directory="/home/ansible/playbooks/cis/rhel8_bk/tasks/5"

echo "4 Access, Authentication and Authorization"

# 4.1 Configure System Accounting (auditd)
# script runs but ignores the errors with grub2cfg handler
echo "4.1 | 5.1 Configure time-based job schedulers"
ansible-playbook -i  $host_file $playbook_directory/job_schedulers.yml

echo "4.2 | Configure SSH Server"
ansible-playbook -i  $host_file $playbook_directory/ssh.yml

echo "4.3 | Configure Privilege Escalation"
ansible-playbook -i  $host_file $playbook_directory/PE.yml

echo "4.4 | Configure authselect"
ansible-playbook -i  $host_file $playbook_directory/authselect.yml

echo "4.5 | Configure PAM"
ansible-playbook -i  $host_file $playbook_directory/PAM.yml

# Don't need this for test environment but would be useful for enterprise
# echo "5.6 | User Accounts and Environments"
# ansible-playbook -i  $host_file $playbook_directory/users.yml
