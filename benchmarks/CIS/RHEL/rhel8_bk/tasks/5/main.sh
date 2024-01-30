host_file=/home/ansible/rhelHOST
playbook_directory="/home/ansible/playbooks/cis/rhel8_bk/tasks/4"

echo "4 Logging and Auditing"

# 4.1 Configure System Accounting (auditd)
# script runs but ignores the errors with grub2cfg handler
echo "4.1 | Ensure auditing is enabled"
ansible-playbook -i  $host_file $playbook_directory/audit_enabled.yml

echo "4.1.2.x | Configure Data Retention"
ansible-playbook -i  $host_file $playbook_directory/data_retention.yml

echo "4.1.3.x | Configure auditd rules"
ansible-playbook -i  $host_file $playbook_directory/auditd_rules.yml

echo "5.2.4.x | Configure auditd file access"
ansible-playbook -i $host_file $playbook_directory/auditd_fa.yml

# 4.2 Configure Logging
# choose to comment out either rsyslog or journald for which syslog we use.
# when testing I commented out journald and left rsyslog
echo "4.2.1.x | Configure rsyslog"
ansible-playbook -i  $host_file $playbook_directory/rsyslog.yml

# echo "4.2.2 | Configure journald"
# ansible-playbook -i  $host_file $playbook_directory/journald.yml

echo "4.2.3 | Configure logfile perms"
ansible-playbook -i  $host_file $playbook_directory/logfile_perms.yml

echo "4.3 | Configure logrotate"
ansible-playbook -i  $host_file $playbook_directory/logrotate.yml