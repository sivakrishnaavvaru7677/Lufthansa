#!/bin/bash -x
################################################################################
#	Author   _ Siva Krishna Giri Babu Avvaru_ Bikram Behera                                                #
#	Email    _ sivakrishna.avvaru@in.ibm.com_ bikrbehe@in.ibm.com                                          #
#	Reviewed and Modified _ Ashutosh Mishra(ashmishn@in.ibm.com	        #
#	Platform _ Linux (RHEL6 and RHEL7)				        #
#	Script   _ Shell script					                #
#	Title    _ Health check script for Linux                                #	     
################################################################################

rm -rf temp_shadow temp_shadow1 temp1_shadow temp_shadow2 temp-ud psw_temp temp_uid temp_uid1 temp_gid temp_gid1 pasd_temp p5 p4 p3 p2 p1 p6 p12 f1 t1 temp_pam.so file1 log_file1 log_file2 world-writable-test

clear
pause(){
  read -p "Press [Enter] key to continue..." fackEnterKey
}
z=`hostname`
c=`date | awk '{print $1"-"$2"-"$3"-"$6"-"$4}'`
echo "SECTION-HEADING" >>p1
echo "SYSTEM-VALUE/PARAMETER" >>p2
echo "CURRENT-VALUE" >>p3
echo "SECTION-ID" >>p12
echo "HOST-NAME" >>p6
echo "TEST-RESULT" >>p4
echo "SCAN-DATE" >>p5

serv=`which service`

PASS_MAX_DAYS=`cat hc_parameter_infra |grep ^PASS_MAX_DAYS |awk '{print $2}'`
PASS_MIN_DAYS=`cat hc_parameter_infra |grep ^PASS_MIN_DAYS |awk '{print $2}'`
PASS_MIN_LENGTH=`cat hc_parameter_infra |grep ^PASS_MIN_LENGTH |awk '{print $2}'`
SYSLOG_IP=`cat hc_parameter_infra |grep ^SYSLOG_IP |awk '{print $2}'`
SYSLOG_PORT=`cat hc_parameter_infra |grep ^SYSLOG_PORT |awk '{print $2}'`
DIGIT=`cat hc_parameter_infra |grep ^DIGIT |awk '{print $2}'`
UPPER_CASE=`cat hc_parameter_infra |grep ^UPPER_CASE |awk '{print $2}'`
LOWER_CASE=`cat hc_parameter_infra |grep ^LOWER_CASE |awk '{print $2}'`
OTHER_CHAR=`cat hc_parameter_infra |grep ^OTHER_CHAR |awk '{print $2}'`
LOG_ROTATE=`cat hc_parameter_infra |grep ^LOG_ROTATE |awk '{print $2}'`
PAM_REMEMBER=`cat hc_parameter_infra |grep ^PAM_REMEMBER |awk '{print $2}'`
UMASK_VAL=`cat hc_parameter_infra |grep ^UMASK_VAL |awk '{print $2}'`
PERMITROOTLOGIN=`cat hc_parameter_infra |grep ^PERMITROOTLOGIN |awk '{print $2}'`
PERMITEMPTYPASSWORDS=`cat hc_parameter_infra |grep ^PERMITEMPTYPASSWORDS |awk '{print $2}'`
PERMITUSERENVIRONMENT=`cat hc_parameter_infra |grep ^PERMITUSERENVIRONMENT |awk '{print $2}'`
TCPKEEPALIVE=`cat hc_parameter_infra |grep ^TCPKEEPALIVE |awk '{print $2}'`
MAXSTARTUPS=`cat hc_parameter_infra |grep ^MAXSTARTUPS |awk '{print $2}'`
MAXAUTHTRIES=`cat hc_parameter_infra |grep ^MAXAUTHTRIES |awk '{print $2}'`
LOGINGRACETIME=`cat hc_parameter_infra |grep ^LOGINGRACETIME |awk '{print $2}'`
KEYREGENERATIONINTERVAL=`cat hc_parameter_infra |grep ^KEYREGENERATIONINTERVAL |awk '{print $2}'`
LOGLEVEL=`cat hc_parameter_infra |grep ^LOGLEVEL |awk '{print $2}'`
GATEWAYPORTS=`cat hc_parameter_infra |grep ^GATEWAYPORTS |awk '{print $2}'`
STRICTMODES=`cat hc_parameter_infra |grep ^STRICTMODES |awk '{print $2}'`
PRINTMOTD=`cat hc_parameter_infra |grep ^PRINTMOTD |awk '{print $2}'`
LOG_ROTATE_WEEK=`cat hc_parameter_infra |grep ^LOG_ROTATE_WEEK |awk '{print $2}'`
LOG_ROTATE_MONTH=`cat hc_parameter_infra |grep ^LOG_ROTATE_MONTH |awk '{print $2}'`


#AD.1.1.1.1_PASS_MAX_DAYS
sz=`cat /etc/login.defs |grep -v "#"| grep ^PASS_MAX_DAYS | awk '{print $2}' |uniq`
if [ "$sz" != "$PASS_MAX_DAYS" ]
then
	echo "Password Requirementss" >>p1
	echo "PASS_MAX_DAYS value in /etc/login.defs" >>p2
	echo "$sz"  >>p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.1.1.1" >>p12

else
	echo "Password Requirementss" >>p1
	echo "PASS_MAX_DAYS value in /etc/login.defs" >>p2
	echo "$sz" >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.1.1.1" >>p12
	
fi


#AD.1.1.1.2_Fifth field of /etc/shadow
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F"_" '{print $1}' >temp_passwd
for i in `cat temp_passwd`
do
sk=`chage -l $i |grep "^Maximum" |sed -e 's/_//g' |awk '{print $8}'`
        if [ "$sk" != "$PASS_MAX_DAYS" ]
        then
                echo "Password Requirements" >>p1
                echo "PASS_MAX_DAYS" >>p2
		echo "Fifth field of /etc/shadow is not set as "$PASS_MAX_DAYS" for id $i" >>p3
		echo "AD.1.1.1.2" >>p12
		echo "no" >>p4
		echo "$c" >> p5 


#AD.1.1.2.0
len=`cat /etc/login.defs |grep ^PASS_MIN_LEN |awk '{print $2}'`
if [ "$len" == "$PASS_MIN_LENGTH" ]
then
	echo "Password Requirementss" >>p1
        echo "PASS_MIN_LEN, password complexity" >>p2
        echo "pasword-minlen-is-set-as-$len-in-/etc/login.defs" >> p3
        echo "AD.1.1.2.0">>p12
	echo "yes" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
else
	echo "Password Requirementss" >>p1
        echo "PASS_MIN_LEN, password complexity" >>p2
        echo "pasword-minlen-is-set-as-$len-in-/etc/login.defs" >> p3
        echo "AD.1.1.2.0">>p12
	echo "no" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
fi

if [ -f /etc/pam.d/password-auth ]
then
	sk=`cat /etc/pam.d/password-auth |grep ^password |egrep 'requisite|required' |grep pam_cracklib.so |grep "retry=3 minlen=$PASS_MIN_LENGTH dcredit=$DIGIT ucredit=$UPPER_CASE lcredit=$LOWER_CASE ocredit=$OTHER_CHAR" |wc -c`
    	sl=`cat /etc/pam.d/password-auth |grep ^password |egrep 'requisite|required' |grep pam_pwquality.so |grep "minlen=$PASS_MIN_LENGTH dcredit=$DIGIT ucredit=$UPPER_CASE lcredit=$LOWER_CASE ocredit=$OTHER_CHAR" |wc -c`
	sm=`cat /etc/pam.d/password-auth |grep ^password |egrep 'requisite|required' |grep pam_passwdqc.so |grep "min=disabled,$PASS_MIN_LENGTH,$PASS_MIN_LENGTH,$PASS_MIN_LENGTH,$PASS_MIN_LENGTH" |wc -c`

        if [ $sk -gt 0 ] || [ $sl -gt 0 ] || [ $sm -gt 0 ]
        then
                                echo "Password Requirementss" >>p1
                                echo "PASS_MIN_LEN, password complexity" >>p2
                                echo "no-violation-for-Complexity-in-/etc/pam.d/password-auth" >> p3
                       		echo "AD.1.1.2.0">>p12
			        echo "yes" >>p4
                                echo "$c" >> p5
                                echo "$z" >>p6

         else
				echo "AD.1.1.2.0" >>p12
                                echo "Password Requirementss" >>p1
                                echo "PASS_MIN_LEN-password_complexity" >>p2
                                echo "Complexity-violation-in-/etc/pam.d/password-auth" >> p3
                                echo "no" >>p4
                                echo "$c" >> p5
                                echo "$z" >>p6
          fi
                                         
fi

	
if [ -f /etc/pam.d/system-auth ]
then
	sk=`cat /etc/pam.d/system-auth |grep ^password |egrep 'requisite|required' |grep pam_cracklib.so |grep "retry=3 minlen=$PASS_MIN_LENGTH dcredit=$DIGIT ucredit=$UPPER_CASE lcredit=$LOWER_CASE ocredit=$OTHER_CHAR" |wc -c`
    	sl=`cat /etc/pam.d/system-auth |grep ^password |egrep 'requisite|required' |grep pam_pwquality.so |grep "minlen=$PASS_MIN_LENGTH dcredit=$DIGIT ucredit=$UPPER_CASE lcredit=$LOWER_CASE ocredit=$OTHER_CHAR" |wc -c`
	sm=`cat /etc/pam.d/system-auth |grep ^password |egrep 'requisite|required' |grep pam_passwdqc.so |grep "min=disabled,$PASS_MIN_LENGTH,$PASS_MIN_LENGTH,$PASS_MIN_LENGTH,$PASS_MIN_LENGTH" |wc -c`

        if [ $sk -gt 0 ] || [ $sl -gt 0 ] || [ $sm -gt 0 ]
        then
                                echo "Password Requirementss" >>p1
                                echo "PASS_MIN_LEN, password complexity" >>p2
                                echo "no-violation-for-Complexity-in-/etc/pam.d/system-auth" >> p3
                       		echo "AD.1.1.2.0">>p12
			        echo "yes" >>p4
                                echo "$c" >> p5
                                echo "$z" >>p6

         else
				echo "AD.1.1.2.0" >>p12
                                echo "Password Requirementss" >>p1
                                echo "PASS_MIN_LEN-password_complexity" >>p2
                                echo "Password-Complexity-violation-in-/etc/pam.d/system-auth" >> p3
                                echo "no" >>p4
                                echo "$c" >> p5
                                echo "$z" >>p6
          fi
                                         
fi
		echo "$z" >>p6
	else
                echo "Password Requirements" >>p1
                echo "PASS_MAX_DAYS" >>p2
		echo "Fifth field of /etc/shadow is set as "$PASS_MAX_DAYS" for id $i" >>p3
		echo "yes" >>p4
		echo "AD.1.1.1.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done
rm -rf temp_passwd


#AD.1.1.2.1_2nd field of /etc/shadow
cat /etc/shadow | awk -F"_" '{print $1}' >temp_shadow2
for i in `cat temp_shadow2`
do
        sk1=`passwd -S $i |awk '{print $2}'`
        if [ "$sk1" == "NP" ]
        then
		echo "Password Requirements" >>p1
                echo "password specification within /etc/shadow" >>p2
		echo "A null password is assigned for user '$i'" >>p3
		echo "no" >>p4
		echo "AD.1.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
                
	else
		echo "Password Requirements" >>p1
                echo "password specification within /etc/shadow" >>p2
		echo "User '$i' has no null value in second field of /etc/shadow" >>p3
		echo "AD.1.1.2.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
               
        fi
done
rm -rf temp_shadow2

#AD.1.1.2.2_2nd field of /etc/passwd
cat /etc/passwd | awk -F"_" '{print $1}' >temp_passwd
for i in `cat temp_passwd`
do
        sk1=`cat /etc/passwd |grep -w ^$i |awk -F_ '{print $2}'`
        if [ "$sk1" == "" ]
        then
		echo "Password Requirements" >>p1
                echo "second field of /etc/passwd" >>p2
		echo "The second field /etc/passwd is set as null for id $i" >>p3
		echo "no" >>p4
		echo "AD.1.1.2.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
                
	else
		echo "Password_requirement" >>p1
                echo "second field of /etc/passwd" >>p2
		echo "The second field /etc/passwd is not set as null" >>p3
		echo "AD.1.1.2.2" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
               
        fi
done
rm -rf temp_passwd


#AD.1.1.3.1_PASS_MIN_DAYS
sm=`cat /etc/login.defs | grep -v "#"| grep ^PASS_MIN_DAYS  | awk '{print $2}' |uniq`
if [ "$sm" != "$PASS_MIN_DAYS" ]
then
	echo "Password Requirementss" >>p1
	echo "PASS_MIN_DAYS value in /etc/login.defs" >>p2
	echo "$sm" >>p3
	echo "no" >>p4
	echo AD.1.1.3.1 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Password Requirementss" >>p1
	echo "PASS_MIN_DAYS value in /etc/login.defs" >>p2
	echo "$sm" >>p3
	echo "yes" >>p4
	echo AD.1.1.3.1 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi


#AD.1.1.3.2_4th field of /etc/shadow
cat /etc/shadow | awk -F"_" '{print $1}' >temp_passwd
for i in `cat temp_passwd`
do
sk=`chage -l $i |grep "^Minimum" |sed -e 's/_//g' |awk '{print $8}'`
        if [ "$sk" == "$PASS_MIN_DAYS" ]
        then
        echo "Password Requirements" >>p1
        echo "Per-userid_Minimum_Password_Age" >>p2
		echo "Field 4 of /etc/shadow is set as "$PASS_MIN_DAYS" for id $i" >>p3
		echo "AD.1.1.3.2" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
        echo "Password Requirements" >>p1
        echo "Per-userid_Minimum_Password_Age" >>p2
		echo "Field 4 of /etc/shadow is not set as "$PASS_MIN_DAYS" for id $i" >>p3
		echo "No" >>p4
		echo "AD.1.1.3.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done
rm -rf temp_passwd

#AD.1.1.4.1_pam-settings
if [ -f /etc/pam.d/system-auth ]
then
	E=`cat /etc/pam.d/system-auth |grep -v '#' |grep ^password |egrep 'required|sufficient' |grep pam_unix.so |grep remember=$PAM_REMEMBER |egrep 'use_authtok|sha512|md5|shadow'`
	if [ $? -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_set-in-/etc/pam.d/system-auth" >>p3
		echo "yes" >> p4
		echo "AD.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_not_set-in-/etc/pam.d/system-auth" >>p3
		echo "No" >> p4
		echo "AD.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "File-not-found-/etc/pam.d/system-auth. Please check the entry in /etc/pam.d/login, /etc/pam.d/passwd, /etc/pam.d/sshd and /etc/pam.d/su" >>p3
		echo "No" >> p4
		echo "AD.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi

if [ -f /etc/pam.d/password-auth ]
then
	E=`cat /etc/pam.d/password-auth |grep -v '#' |grep ^password |egrep 'required|sufficient' |grep pam_unix.so |grep remember=$PAM_REMEMBER |egrep 'use_authtok|sha512|md5|shadow'`
	if [ $? -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_set-in-/etc/pam.d/password-auth" >>p3
		echo "yes" >> p4
		echo "AD.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "pam_unix.so_remember value_not_set-in-/etc/pam.d/password-auth" >>p3
		echo "no" >> p4
		echo "AD.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "prevent_reuse_of_lat_eight_passwords" >>p2
		echo "File-not-found-/etc/pam.d/password-auth. Please check the entry in /etc/pam.d/login, /etc/pam.d/passwd, /etc/pam.d/sshd and /etc/pam.d/su" >>p3
		echo "no" >> p4
		echo "AD.1.1.4.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi


#AD.1.1.6.0_loginretries value in password-auth and system-auth
if [ -f /etc/pam.d/system-auth ] 
then
sk=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_tally.so deny=5 |pam_tally2.so deny=5" |wc -l`
sl=`cat /etc/pam.d/system-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_tally.so |pam_tally2.so" |wc -l`
	if [ $sk -gt 0 ] && [ $sl -gt 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/system-auth" >>p3
		echo AD.1.1.6.0 >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirementss" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/system-auth" >>p3
		echo AD.1.1.6.0 >>p12
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "loginretries" >>p2
		echo "File not found /etc/pam.d/system-auth" >>p3
		echo AD.1.1.6.0 >>p12
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
if [ -f /etc/pam.d/password-auth ] 
then
sk=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^auth |grep required | egrep -w "pam_tally.so deny=5 |pam_tally2.so deny=5" |wc -l`
sl=`cat /etc/pam.d/password-auth |grep -v '#' | grep ^account |grep required | egrep -w "pam_tally.so |pam_tally2.so" |wc -l`
	if [ $sk -gt 0 ] && [ $sl -gt 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is set in /etc/pam.d/password-auth" >>p3
		echo AD.1.1.6.0 >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirementss" >>p1
		echo "loginretries" >>p2
		echo "Consecutive failed login attempts is not set in /etc/pam.d/password-auth" >>p3
		echo AD.1.1.6.0 >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "loginretries" >>p2
		echo "File not found /etc/pam.d/system-auth" >>p3
		echo AD.1.1.6.0 >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
#AD.1.1.7.1
szkl=`passwd -S root |awk '{print $2}'`
sk=`chage -l root |grep "^Maximum" |sed -e 's/_//g' |awk '{print $8}'`
if [ "$szkl" == "PS" ] && [ "$sk" == "$PASS_MAX_DAYS" ]
then
		echo "AD.1.1.7.1" >>p12
		echo "Password Requirements" >>p1
		echo "Password and expiry settings for ROOT" >>p2
		echo "root_passwd_is_set and expiry period set as $PASS_MAX_DAYS" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
	
		echo "AD.1.1.7.1" >>p12
		echo "Password Requirements" >>p1
		echo "Password and expiry settings for ROOT" >>p2
		echo "root_passwd setting is incorrect. Please check root password expiry and password status" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#AD.1.1.7.2
sz=`cat /etc/ssh/sshd_config | grep -i "^PermitRootLogin" | awk '{print $2}' |uniq`
if [ "$sz" == "$PERMITROOTLOGIN" ]
then
		echo "Password Requirements" >>p1
        	echo "ROOT" >>p2
		echo "Interactive-root-login-is-disabled" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AD.1.1.7.2" >>p12
else
		echo "Password Requirementss" >>p1
        	echo "ROOT" >>p2
		echo "Interactive-root-login-is-enabled" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AD.1.1.7.2" >>p12
fi


#AD.1.1.8.2_UID-validation
cat /etc/passwd | awk -F"_" '{print $3}'| sort  | uniq -cd | awk '{print $2}'> temp_uid
sp=`cat temp_uid | wc -c`
if [ "$sp" == 0 ]
then
		echo "Password Requirementss" >>p1
		echo "UID_validation" >>p2
		echo  "No_duplicate_uid_value_for_users_in_/etc/passwd" >>p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "AD.1.1.8.2" >>p12
		echo "$z" >>p6	
else
		for i in `cat temp_uid`
		do
		echo "Password Requirementss" >>p1
		echo "uid_validation" >>p2
		echo "Duplicate-uid-value-for-UID-$i" >>p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "AD.1.1.8.2" >>p12
		echo "$z" >>p6	
		done
fi


#AD.1.1.9.0_AD.1.1.9.1_non-expiry-passwords
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" |awk -F_ '{print $1}' > sys-user-info
for i in `cat sys-user-info`
do
sk=`passwd -S $i |awk '{print $2}'`
if [ "$sk" == "PS" ] || [ "$sk" == "NP" ]
then
	chage -l $i | grep -w 99999 
	if [ $? -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Expiry_passwd_value_not_exist_for_$i" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.1.9.0_AD.1.1.9.1" >>p12
	else
		echo "Password Requirementss" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Expiry_passwd_value_exist_for_$i" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.1.9.0_AD.1.1.9.1" >>p12
	fi
else
		echo "Password Requirementss" >>p1
		echo "Non-expiring passwords" >>p2
		echo "Not applicable as user ID $i is locked" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.1.9.0_AD.1.1.9.1" >>p12	
fi
done
rm -rf sys-user-info

#AD.1.1.10.1_AD.1.1.11.1_AD.1.1.12.1_Non-expiring ID's
for i in `cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F"_" '{print $1}'`
do
sk=`chage -l $i | grep "Password expires" |sed -e 's/_//' | awk '{ print $3}'`
if [ "$sk" == "never" ]
then
	sk1=`passwd -S $i |awk '{print $2}'`
        if [ "$sk1" == "LK" ]
        then
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has non-expiring password but the account is locked" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.1.10.1_AD.1.1.11.1_AD.1.1.12.1" >>p12
	else
		echo "Password Requirementss" >>p1
		echo "direct_or_remote_login" >>p2
		echo "User $i has non-expiring password but the account is not locked" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.1.10.1_AD.1.1.11.1_AD.1.1.12.1" >>p12
	fi
else
	echo "Password Requirementss" >>p1
	echo "direct_or_remote_login" >>p2
	echo "User $i has expiry password set" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.1.10.1_AD.1.1.11.1_AD.1.1.12.1" >>p12	
fi
done

#AD.1.1.13.3_AD.1.1.10.2_FTP filecheck
ftpRPM=`rpm -q vsftpd`
if [ $? -ne 0 ]
then
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "AD.1.1.13.3_AD.1.1.10.2" >>p12
		echo "Base package vsftpd is not installed" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
if [ -f /etc/ftpusers ] || [ -f /etc/vsftpd.ftpusers ] || [ -f /etc/vsftpd/ftpusers ]
then
	smt=`cat /etc/ftpusers | wc -c`
	smr=`cat /etc/vsftpd.ftpusers | wc -c`
	smt1=`cat /etc/vsftpd/ftpusers | wc -c`
	if [ $smt -eq 0 ] || [ $smr -eq 0 ] || [ $smt1 -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "AD.1.1.13.3_AD.1.1.10.2" >>p12
		echo "ftp_file_exist-but-no-ftp-id" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "ftp_file_exist-with-ftp-id" >> p3
		echo "no" >>p4
		echo "AD.1.1.13.3_AD.1.1.10.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "AD.1.1.13.3_AD.1.1.10.2" >>p12
		echo "ftp_file_doesnt-exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
fi



#AD.1.1.13.2
		echo "Password Requirementss" >>p1
		echo "/etc/security/<FILENAME>" >>p2
		echo "cannot-be-health-checked" >>p3
		echo "Not_Applicable" >> p4
		echo "AD.1.1.13.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	


#AD.1.1.13.3,AD.1.1.10.2_FTP filecheck
ftpRPM=`rpm -q vsftpd`
if [ $? -ne 0 ]
then
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "AD.1.1.13.3,AD.1.1.10.2" >>p12
		echo "Base package vsftpd is not installed" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
if [ -f /etc/ftpusers ] || [ -f /etc/vsftpd.ftpusers ] || [ -f /etc/vsftpd/ftpusers ]
then
	smt=`cat /etc/ftpusers | wc -c`
	smr=`cat /etc/vsftpd.ftpusers | wc -c`
	smt1=`cat /etc/vsftpd/ftpusers | wc -c`
	if [ $smt -eq 0 ] || [ $smr -eq 0 ] || [ $smt1 -eq 0 ]
	then
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "AD.1.1.13.3,AD.1.1.10.2" >>p12
		echo "ftp_file_exist-but-no-ftp-id" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "ftp_file_exist-with-ftp-id" >> p3
		echo "no" >>p4
		echo "AD.1.1.13.3,AD.1.1.10.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirementss" >>p1
		echo "Restrict ftp access" >>p2
		echo "AD.1.1.13.3,AD.1.1.10.2" >>p12
		echo "ftp_file_doesnt-exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
fi


#AD.1.1.13.4_PAM-yes
sk=`cat /etc/ssh/sshd_config |grep -v '#' |grep ^UsePAM |awk '{print $2}'`
if [ "$sk" == "yes" ]
then
	echo "Password Requirementss" >>p1
	echo "/etc/ssh/sshd_config" >>p2
	echo "UsePAM_yes_is_valid" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.1.13.4" >>p12
else
	echo "Password Requirementss" >>p1
	echo "/etc/ssh/sshd_config" >>p2
	echo "AD.1.1.13.4" >>p12
	echo "UsePAM_yes_is_invalid" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#AD.1.2.2_file-check
if [ -f /var/log/wtmp ]
then
	echo "Logging" >>p1
	echo "/var/log/wtmp" >>p2
	echo "/var/log/wtmp_exist" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo AD.1.2.2 >>p12
	echo "$z" >>p6
else
	echo "Logging" >>p1
	echo "/var/log/wtmp" >>p2
	echo "/var/log/wtmp_doesnt_exist" >> p3
	echo "no" >>p4
	echo AD.1.2.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
fi

#AD.1.2.3.1_file-check	
if [ -f /var/log/messages ]
then
	echo "Logging" >>p1
	echo "/var/log/messages" >>p2
	echo "/var/log/messsages_exist" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo AD.1.2.3.1 >>p12
	echo "$z" >>p6
else
	echo "Logging" >>p1
	echo AD.1.2.3.1 >>p12
	echo "/var/log/messages" >>p2
	echo "/var/log/messages_doesnt_exist" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#AD.1.2.4.2

sk=`which pam_tally2` 
if [ $? -eq 0 ]
then
if [ -f /var/log/tallylog ]
then
	echo "Logging" >>p1
	echo "/var/log/tallylog" >>p2
	echo "file-exists-/var/log/tallylog">>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.2.4.2" >>p12
else
	echo "Logging" >>p1
	echo "/var/log/tallylog-permissions" >>p2
	echo "missing-file-/var/log/tallylog">>p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.2.4.2" >>p12
fi
fi

#AD.1.2.5_file-check
szk=`cat /etc/redhat-release | awk '{print $1}'`
if [ "$szk" == "Red" ]
then
	if [ -f /var/log/secure ]
	then
		echo "Logging" >>p1
		echo "/var/log/secure" >>p2
		echo "File /var/log/secure exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.2.5 >>p12
	else
		echo "Logging" >>p1
		echo "/var/log/secure" >>p2
		echo "File /var/log/secure not exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.2.5 >>p12
	fi
else
	if [ -f /var/log/auth.log ]
	then
		echo "Logging" >>p1
		echo "/var/log/auth.log" >>p2
		echo "File /var/log/auth.log exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.2.5 >>p12
	else
		echo "Logging" >>p1
		echo "/var/log/auth.log" >>p2
		echo "File /var/log/auth.log not exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.2.5 >>p12
	fi
fi

#AD.1.2.7.1_Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $A -gt 0 ]
then
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd-is-running" >>p3
		echo "AD.1.2.7.1">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
	if [ $B -gt 0 ]
	then
		echo "Logging" >>p1
               echo "Synchronized system clocks, ensure it is active" >>p2
		echo "chronyd-is-running" >>p3
		echo "AD.1.2.7.1">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
               echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd-chronyd-is-not-running" >>p3
		echo "AD.1.2.7.1">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
fi

#AD.1.2.7.2_Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $B -gt 0 ]
then
	val1=`/usr/bin/chronyc tracking |grep "Leap status" |awk -F_ '{print $2}' |sed -e 's/ //g'`
	if [ "$val1" == "Normal" ]
	then
		echo "Logging" >>p1
       	echo "Synchronized system clocks, chronyd has a server" >>p2
		echo "chronyd-is-active and time-is-synchronised" >>p3
		echo "AD.1.2.7.2">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
        	echo "Synchronized system clocks, chronyd has a server" >>p2
		echo "chronyd-is-active but time-is-not-synchronised" >>p3
		echo "AD.1.2.7.2">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
	val2=`/usr/bin/ntpstat`
	if [ $? -eq 0 ] && [ $A -gt 0 ]
	then
		echo "Logging" >>p1
        	echo "Synchronized system clocks, chronyd has a server" >>p2
		echo "ntpd-is-configured and time-is-synchronised" >>p3
		echo "AD.1.2.7.2">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
       	echo "Synchronized system clocks, chronyd has a server" >>p2
		echo "ntp-is-not-configured" >>p3
		echo "AD.1.2.7.2">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
fi

#AD.1.2.7.3_Logging
ps -ef |grep chronyd |grep -v "grep"
if [ $? -eq 0 ]
then
	sl=`ps -ef |grep chronyd |grep -v "grep" |awk '{print $1}'`
	if [ "$sl" == "chrony" ]
	then
		echo "Logging" >>p1
                echo "Synchronized system clocks, chronyd does not have excess privilege" >>p2
		echo "The task is running as chrony ID" >>p3
		echo "AD.1.2.7.3">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
                echo "Synchronized system clocks, chronyd does not have excess privilege" >>p2
		echo "The task is not running as chrony ID" >>p3
		echo "AD.1.2.7.3">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
                echo "Synchronized system clocks, chronyd does not have excess privilege" >>p2
		echo "Chrony service is not active" >>p3
		echo "AD.1.2.7.3">>p12
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.1.2.7.4,AD.1.2.7.5
str=$(rpm -qa | grep ntp|wc -l)
str1=$(systemctl status ntpd.service|wc -l)
if [ $str == 0 ] || [ $str1 == 0 ]
then
	echo "Logging" >>p1
	echo "NTP Service" >>p2
	echo "NTP Service is Disabled" >>p3
	echo "yes" >>p4
    echo "AD.1.2.7.4_AD.1.2.7.5" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Logging" >>p1
	echo "NTP Service" >>p2
	echo "NTP Service is Enabled" >>p3
	echo "no" >>p4
	echo "AD.1.2.7.4_AD.1.2.7.5" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi




#AD.1.4.1
sk=`cat /etc/pam.d/other |grep ^auth |grep required |grep pam_deny.so |wc -l`
sl=`cat /etc/pam.d/other |grep ^account |grep required |grep pam_deny.so |wc -l`
if [ $sk -gt 0 ] && [ $sl -gt 0 ]
then
	echo "System Settings" >>p1
	echo "/etc/pam.d/other" >>p2
	echo "auth-required-account-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.4.1" >>p12
else
	if [ $sk -eq 0 ] 
	then
		echo "System Settings" >>p1
		echo "/etc/pam.d/other" >>p2
		echo "auth-required-doesnt-have-pam_deny.so in file /etc/pam.d/other" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.1" >>p12
	else
		echo "System Settings" >>p1
		echo "/etc/pam.d/other" >>p2
		echo "auth-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.1" >>p12
	fi

	if [ $sl -eq 0 ]
	then
			echo "System Settings" >>p1
			echo "/etc/pam.d/other" >>p2
			echo "account-required-doesnt-have-pam_deny.so in file /etc/pam.d/other" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.4.1" >>p12
	else
			echo "System Settings" >>p1
			echo "/etc/pam.d/other" >>p2
			echo "account-required-has-pam_deny.so in file /etc/pam.d/other" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.4.1" >>p12
	fi
fi


#AD.1.4.5_AD.1.5.1.1_AD.1.5.1.2_AD.1.5.1.3_AD.1.5.1.4_AD.1.5.1.5_AD.1.5.1.6_AD.1.5.1.7_AD.1.5.1.8
fz1=`service vsftpd status |grep running |wc -c`
fz2=`ls -l /etc/vsftpd/vsftpd.conf |wc -c`
	if [ $fz1 -gt 0 ] || [ $fz2 -gt 0 ]
	then
		sl=`cat /etc/vsftpd/vsftpd.conf |grep ^anonymous_enable |awk -F= '{print $2}'`
		if [ "$sl" == "yes" ]
		then
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "FTP service is running and anonymous FTP is enabled. Please modify the settings as per techspec." >>p3
			echo "AD.1.4.5_AD.1.5.1.1_AD.1.5.1.2_AD.1.5.1.3_AD.1.5.1.4_AD.1.5.1.5_AD.1.5.1.6_AD.1.5.1.7_AD.1.5.1.8">>p12
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
		else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "FTP service is running but anonymous FTP is disabled" >>p3
			echo "AD.1.4.5_AD.1.5.1.1_AD.1.5.1.2_AD.1.5.1.3_AD.1.5.1.4_AD.1.5.1.5_AD.1.5.1.6_AD.1.5.1.7_AD.1.5.1.8">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
		fi
	else
			echo "Network Settingss" >> p1
			echo "Anonymous FTP System Settings" >>p2
			echo "FTP is not configured" >>p3
			echo "AD.1.4.5_AD.1.5.1.1_AD.1.5.1.2_AD.1.5.1.3_AD.1.5.1.4_AD.1.5.1.5_AD.1.5.1.6_AD.1.5.1.7_AD.1.5.1.8">>p12
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
	fi


#AD.1.5.2.1_AD.1.5.2.2_TFTP filecheck
rpm -qa |egrep "tftp-server|tftp"
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "AD.1.5.2.1_AD.1.5.2.2" >>p12
		echo "Base package tftp or tftp-server is not installed" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "AD.1.5.2.1_AD.1.5.2.2" >>p12
		echo "Base package tftp or tftp-server is installed. Please check the Techspec for additional check" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.1.5.3.1
sl=`which service`
sl1=`$sl nfs status`
if [ $? -eq 0 ]
then
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ $? -eq 0 ] && [ "$szm" == "644" ]
	then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is running and file permission is correct" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is running and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "AD.1.5.3.1" >>p12
	fi
else
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ $? -eq 0 ] && [ "$szm" == "644" ]
	then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not running and file permission is correct" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not running and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "AD.1.5.3.1" >>p12
	fi
fi


#AD.1.5.4.1
if [ -f /etc/hosts.equiv ]
then
	echo "Network Settings" >>p1
	echo "/etc/hosts.equiv" >>p2
	echo "/etc/hosts.equiv-file-exist" >> p3
	echo "AD.1.5.4.1" >>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
else
	echo "Network Settings" >>p1
	echo "/etc/hosts.equiv" >>p2
	echo "/etc/hosts.equiv-file-not-exist" >> p3
	echo "AD.1.5.4.1" >>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6

fi

#AD.1.5.4.2
skl=`which arch`
sll=`$skl`
if [ "$sll" == "x86_64" ]
then
  if [ -f /etc/pam.d/rlogin ] || [ -f  /etc/pam.d/rsh ]
  then
	sm=`grep -i "/lib64/security/pam_rhosts_auth.so" /etc/pam.d/rlogin |wc -c`
	sn=`grep -i "/lib64/security/pam_rhosts_auth.so" /etc/pam.d/rsh |wc -c`
	if [ $sm -ne 0 ] || [ $sn -ne 0 ] 
	then
		sa=`grep -i "no_hosts_equiv" /etc/pam.d/rlogin |wc -c`
		sb=`grep -i "no_hosts_equiv" /etc/pam.d/rsh |wc -c`
		if [ $sa -ne 0 ] || [ $sb -ne 0 ]
		then
			echo "Network Settingss" >>p1
			echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
			echo "Required-settings-found-in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
			echo "yes" >>p4
			echo "$c" >> p5
			echo AD.1.5.4.2 >>p12
			echo "$z" >>p6
		else
			echo "Network Settingss" >>p1
			echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
			echo "Required-settings-not-found-in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo AD.1.5.4.2 >>p12
		fi
	else
			echo "Network Settingss" >>p1
			echo "/etc/pam.d-and-etc/pam.d/rlogin" >>p2
			echo "no_hosts_equiv parameter not exist in-file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh" >> p3
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo AD.1.5.4.2 >>p12
	fi
  else
	echo "Network Settingss" >>p1
	echo "/etc/pam.d/rsh-and-/etc/pam.d/rlogin" >>p2
	echo "file-/etc/pam.d/rlogin-and-/etc/pam.d/rsh-not-exists" >> p3
	echo AD.1.5.4.2 >>p12
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
  fi
else
	echo "Network Settingss" >>p1
	echo "/etc/pam.d/rsh-and-/etc/pam.d/rlogin" >>p2
	echo "This is not 64 bit kernel system" >> p3
	echo AD.1.5.4.2 >>p12
	echo "Not_Applicable" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#AD.1.5.5_rexd daemon
if [ -f /etc/inetd.conf ] || [ -f /etc/xinetd.d/xinted.conf ]
then
	sk=`cat /etc/inetd.conf | grep -v "#" | grep -i ^rexd |wc -l`
	sl=`cat /etc/xinetd.d/xinted.conf | grep -v "#" | grep -i ^rexd |wc -l`
	if [ $sk -gt 0 ] || [ $sl -gt 0 ]
	then
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "rexd deamon is runnig" >> p3
		echo "no" >>p4
		echo  "AD.1.5.5">>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "rexd deamon is not runnig" >> p3
		echo "yes" >>p4
		echo  "AD.1.5.5">>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Network Settingss" >>p1
		echo "rexd daemon" >>p2
		echo "File /etc/inetd.conf or /etc/xinetd.d/xinted.conf not exists " >> p3
		echo "yes" >>p4
		echo  "AD.1.5.5">>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi


#AD.1.5.7
if [ $(rpm -qa xorg-x11* | wc -l) -eq 0 ]
then
	echo "Network Settings" >>p1
	echo "X-server access control" >>p2
	echo "X-server packages not installed" >>p3
	echo "Not_Applicable" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.5.7" >>p12
else
sk=`which xhost`
if [ $? -eq 0 ]
then
	$sk
	if [ $? -eq 0 ]
	then
		$sk |grep enabled
		if [ $? -eq 0 ]
		then
			echo "Network Settings" >>p1
			echo "X-server access control" >>p2
			echo "X-server packages installed and Access control is enabled via xhost" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.7" >>p12
		else
			echo "Network Settings" >>p1
			echo "X-server access control" >>p2
			echo "Access control is disabled via xhost. Please check xhost command output and run 'xhost -'" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.7" >>p12
		fi
	else
		echo "Network Settings" >>p1
		echo "X-server access control" >>p2
		echo "X-server packages installed but xhost is not enabled or disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.7" >>p12
	fi	
else
	echo "Network Settings" >>p1
	echo "X-server access control" >>p2
	echo "X-server packages installed but Xhost command not found" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.5.7" >>p12
fi
fi


#AD.1.5.8.1,AD.1.5.8.2,AD.1.5.8.3,AD.1.5.8.4,AD.1.5.8.5,AD.1.5.8.6,AD.1.5.8.7,AD.1.5.8.8,AD.1.5.9.1,AD.1.5.9.2,AD.1.5.9.3,AD.1.5.9.4,AD.1.5.9.5,AD.1.5.9.6,AD.1.5.9.7,AD.1.5.9.8,AD.1.5.9.9,AD.1.5.9.10,AD.1.5.9.11,AD.1.5.9.12,AD.1.5.9.13,AD.1.5.9.14,AD.1.5.9.15,AD.1.5.9.16,AD.1.5.9.17,AD.1.5.9.28
sp=`which service`
sy=`$sp xinetd status`
if [ $? -eq 0 ]
then
	sk=`ls /etc/xinetd.d |wc -l`
	if [ $sk -gt 0 ]
	then
	ls -ltr /etc/xinetd.d/ |grep -v "nrpe" |awk '{print $9}' |grep -v '^$' >xinetd_file
	for i in `cat xinetd_file`
	do
		sj=`cat /etc/xinetd.d/$i |grep -v '#' |grep disable |awk -F= '{print $2}' |sed -e 's/ //g'`
		if [ "$sj" == "yes" ]
		then
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "Service $i is disabled in /etc/xinetd.d" >>p3
			echo "yes" >>p4
			echo "AD.1.5.8.1_AD.1.5.8.2_AD.1.5.8.3_AD.1.5.8.4_AD.1.5.8.5_AD.1.5.8.6_AD.1.5.8.7_AD.1.5.8.8_AD.1.5.9.1_AD.1.5.9.2_AD.1.5.9.3_AD.1.5.9.4_AD.1.5.9.5_AD.1.5.9.6_AD.1.5.9.7_AD.1.5.9.8_AD.1.5.9.9_AD.1.5.9.10_AD.1.5.9.11_AD.1.5.9.12_AD.1.5.9.13_AD.1.5.9.14_AD.1.5.9.15_AD.1.5.9.16_AD.1.5.9.17_AD.1.5.9.28" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
		else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "Service $i is enabled in /etc/xinetd.d" >>p3
			echo "no" >>p4
			echo "AD.1.5.8.1_AD.1.5.8.2_AD.1.5.8.3_AD.1.5.8.4_AD.1.5.8.5_AD.1.5.8.6_AD.1.5.8.7_AD.1.5.8.8_AD.1.5.9.1_AD.1.5.9.2_AD.1.5.9.3_AD.1.5.9.4_AD.1.5.9.5_AD.1.5.9.6_AD.1.5.9.7_AD.1.5.9.8_AD.1.5.9.9_AD.1.5.9.10_AD.1.5.9.11_AD.1.5.9.12_AD.1.5.9.13_AD.1.5.9.14_AD.1.5.9.15_AD.1.5.9.16_AD.1.5.9.17_AD.1.5.9.28" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
		fi
	done
	else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "No service available in /etc/xinetd.d" >>p3
			echo "yes" >>p4
			echo "AD.1.5.8.1_AD.1.5.8.2_AD.1.5.8.3_AD.1.5.8.4_AD.1.5.8.5_AD.1.5.8.6_AD.1.5.8.7_AD.1.5.8.8_AD.1.5.9.1_AD.1.5.9.2_AD.1.5.9.3_AD.1.5.9.4_AD.1.5.9.5_AD.1.5.9.6_AD.1.5.9.7_AD.1.5.9.8_AD.1.5.9.9_AD.1.5.9.10_AD.1.5.9.11_AD.1.5.9.12_AD.1.5.9.13_AD.1.5.9.14_AD.1.5.9.15_AD.1.5.9.16_AD.1.5.9.17_AD.1.5.9.28" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
	fi
else
			echo "Network Settings" >>p1
			echo "Denial of Service through xinetd or inetd" >>p2
			echo "xinetd service is not running" >>p3
			echo "yes" >>p4
			echo "AD.1.5.8.1_AD.1.5.8.2_AD.1.5.8.3_AD.1.5.8.4_AD.1.5.8.5_AD.1.5.8.6_AD.1.5.8.7_AD.1.5.8.8_AD.1.5.9.1_AD.1.5.9.2_AD.1.5.9.3_AD.1.5.9.4_AD.1.5.9.5_AD.1.5.9.6_AD.1.5.9.7_AD.1.5.9.8_AD.1.5.9.9_AD.1.5.9.10_AD.1.5.9.11_AD.1.5.9.12_AD.1.5.9.13_AD.1.5.9.14_AD.1.5.9.15_AD.1.5.9.16_AD.1.5.9.17_AD.1.5.9.28" >>p12
			echo "$c" >>p5
			echo "$z" >>p6
fi
rm -rf xinetd_file

#AD.1.5.9.23
sl=`which service`
sl1=`$sl telnetd status`
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-is-enabled" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.23" >>p12
	else
		echo "Network Settings" >>p1
		echo "telnet-service" >>p2
		echo "telnet-is-disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.23" >>p12
	fi


#AD.1.5.10.1
rpm -q ypserv ypbind portmap yp-tools
if [ $? -eq 0 ]
then
	sl=`which service`
	$sl yppasswdd status
	if [ $? -eq 0 ]
	then
			echo "Network Settings" >>p1
			echo "yppasswdd-daemon" >>p2
			echo "yppasswdd-daemon-is-running" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.10.1" >>p12
	else
			echo "Network Settings" >>p1
			echo "yppasswdd-daemon" >>p2
			echo "yppasswdd-daemon-is-not-running" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.10.1" >>p12
	fi
else
	echo "Network Settings" >>p1
	echo "yppasswdd-daemon" >>p2
	echo "NIS packages not installed." >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.5.10.1" >>p12
fi


#AD.1.5.10.2_AD.1.5.10.3
sz=`rpm -q ypserv ypbind portmap yp-tools`
if [ $? -eq 0 ]
then
	sl=`which service`
	sl1=`$sl ypserv status`
	if [ $? -eq 0 ]
	then
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS-is-disbaled_verify-the-map-files" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.10.2_AD.1.5.10.3" >>p12
	else
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS-is-Enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.10.2_AD.1.5.10.3" >>p12
	fi
else
		echo "Network Settings" >>p1
		echo "NIS and NIS+ maps" >>p2
		echo "NIS packages not installed" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.10.2_AD.1.5.10.3" >>p12
fi


#AD.1.8.1.2
echo "/etc/init.d,/etc/rc.d,/etc/cron.d,/var/spool/cron/tabs/root,/opt,/var,/usr/local,/tmp,/etc,/usr,/,/etc/security/opasswd,/etc/shadow,/etc/passwd,/etc,/var/log,/var/log/faillog,/var/log/tallylog,/var/log/wtmp,/var/log/secure,/var/log/lastlog,/var/log/cron,/var/log/btmp,/var/log/hist,/var/log/sa,/var/log/maillog,/var/log/auth.log,/var/tmp,/var/log/messages,/etc/profile.d/IBMsinit.sh,/etc/profile.d/IBMsinit.csh,/etc/inittab,/var/spool/cron/root,/etc/crontab,/etc/xinetd.conf" > temp

tr "," "\n" < temp > temp1

Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
	for i in `cat temp1`
	do
	if [ -f $i ] || [ -d $i ]
	then
		sj=`ls -ld $i |awk '{print $3}'`
		sk=`ls -ld $i |awk '{print $4}'`
		sl=`id -u $sj`
		sm=`getent group $sk |awk -F_ '{print $3}'`
		if [ $sl -le 999 ]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file $i is owned by $sj - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.8.1.2" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "User Ownership" >>p2
			echo "The file $i is owned by $sj - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.8.1.2" >>p12
		fi
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "User Ownership" >>p2
		echo "The file $i is owned by $sj - File Doesnt Exists" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.1.2" >>p12
	fi
	done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "User Ownership" >>p2
	echo "Its not RHEL" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.8.1.2" >>p12
fi
##########################################################################################################################333333
#AD.1.8.1.3
echo "/etc/init.d,/etc/rc.d,/etc/cron.d,/var/spool/cron/tabs/root,/opt,/var,/usr/local,/tmp,/etc,/usr,/,/etc/security/opasswd,/etc/shadow,/etc/passwd,/etc,/var/log,/var/log/faillog,/var/log/tallylog,/var/log/wtmp,/var/log/secure,/var/log/lastlog,/var/log/cron,/var/log/btmp,/var/log/hist,/var/log/sa,/var/log/maillog,/var/log/auth.log,/var/tmp,/var/log/messages,/etc/profile.d/IBMsinit.sh,/etc/profile.d/IBMsinit.csh,/etc/inittab,/var/spool/cron/root,/etc/crontab,/etc/xinetd.conf" > temp

tr "," "\n" < temp > temp1

Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ $Release == "Red" ]
then
	for i in `cat temp1`
	do
	if [ -f $i ] || [ -d $i ]
	then
		sj=`ls -ld $i |awk '{print $3}'`
		sk=`ls -ld $i |awk '{print $4}'`
		sl=`id -u $sj`
		sm=`getent group $sk |awk -F_ '{print $3}'`
		if [ $sl -le 999 ]
		then
			echo "Protecting Resources - OSRs" >>p1
			echo "Groupids assigned to OSRs" >>p2
			echo "This group $sk is owned by $i - Permission is Valid" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.8.1.3" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
			echo "Groupids assigned to OSRs" >>p2
			echo "This group $sk is not owned by $i - Permission is invalid" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.8.1.3" >>p12
		fi
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "Groupids assigned to OSRs" >>p2
		echo "This group $sk is not owned by $i - File Doesnt Exists" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.1.3" >>p12
	fi
	done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "User Ownership" >>p2
	echo "Its not RHEL" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.8.1.2" >>p12
fi


#AD.1.8.2.1
if [ -f ~root/.rhosts ]
then
	sz=$(stat -c "%a %n" ~root/.rhosts |awk '{print $1}')
	sk=`ls -ld ~root/.rhosts |awk '{print $4}'`
	if [ "$sz" == "600" ] && [ "$sk" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-is-read-write-only-by-root" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.2.1" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-permission-is-set-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.2.1" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.rhosts" >>p2
		echo "The-file-is-not-available" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.2.1" >>p12
fi


#AD.1.8.2.2
if [ -f ~root/.netrc ]
then
	sz=$(stat -c "%a %n" ~root/.netrc |awk '{print $1}')
	sk=`ls -ld ~root/.rhosts |awk '{print $4}'`
	if [ "$sz" == "600" ] && [ "$sk" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-is-read-write-only-by-root" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.2.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-permission-is-set-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.2.2" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "~root/.netrc" >>p2
		echo "The-file-is-not-available" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.2.2" >>p12
fi

#AD.1.8.3.1
str=`ls -ld / |awk '{print $1}' |cut -c9`
str1=`getfacl / |grep other |awk -F"__" '{print $2}' |cut -c 2`
sp=`getfacl / |grep other`
if [ "$str" == "w" ] || [ "$str1" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/-dir-permission" >>p2
		echo "/-dir-is-writtable-by-others and ACL for / is set as '$sp'" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/-dir-permission" >>p2
		echo "/-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.1" >>p12
fi

#AD.1.8.3.3
str=`ls -ld /etc |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc-dir-permission" >>p2
		echo "/etc-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.3" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc-dir-permission" >>p2
		echo "/etc-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.3" >>p12
fi

#AD.1.8.4.1
if [ -f /etc/security/opasswd ]
then
str=$(stat -c "%a %n" /etc/security/opasswd |awk '{print $1}')
if [ "$str" == "600" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.1" >>p12
fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/security/opasswd-permission" >>p2
		echo "/etc/security/opasswd file not exist" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.1" >>p12
fi

#AD.1.8.5.1
str=`ls -ld /var |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-dir-permission" >>p2
		echo "/var-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.5.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-dir-permission" >>p2
		echo "/var-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.5.1" >>p12
fi

#AD.1.8.5.2
find /var/log -type d -perm /o+w \! -perm -1000 >world-writable-test
sk=`cat world-writable-test |wc -l`
if [ $sk -gt 0 ]
then
for i in `cat world-writable-test |grep -v "/bin/slogin"`
do
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log and it's sub-directories permissions" >>p2
	echo "Permission is invalid for $i" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo AD.1.8.5.2 >>p12
done
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log and it's sub-directories permissions" >>p2
	echo "Permission-is-valid for /var/log and it's sub-directories" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo AD.1.8.5.2 >>p12
	echo "$z" >>p6
fi
rm -rf world-writable-test


#AD.1.8.6.1
sk=`which pam_tally2`
if [ $? -ne 0 ]
then
	str6=$(stat -c "%a %n" /var/log/faillog |awk '{print $1}')
	if [ "$str6" == "600" ]
	then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/faillog" >>p2
			echo "/var/log/faillog-Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.8.6.1" >>p12
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/faillog" >>p2
			echo "/var/log/faillog-Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.8.6.1" >>p12
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/faillog" >>p2
			echo "Not applicable as pam_tally2 is in use" >> p3
			echo "Not_Applicable" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.8.6.1" >>p12
fi


#AD.1.8.6.2
sk=`which pam_tally2`
if [ $? -eq 0 ]
then
	str6=$(stat -c "%a %n" /var/log/tallylog |awk '{print $1}')
	if [ "$str6" == "600" ]
	then
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "/var/log/tallylog-Permission-is-valid" >> p3
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.8.6.2" >>p12
	else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "/var/log/tallylog-Permission-is-invalid" >> p3
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.8.6.2" >>p12
	fi
else
			echo "Protecting Resources - OSRs" >>p1
			echo "/var/log/tallylog" >>p2
			echo "Not applicable as pam_tally2 is not in use" >> p3
			echo "Not_Applicable" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.8.6.2" >>p12
fi

#AD.1.8.7.1
str1=`ls -ld /var/log/messages | awk '{print $1}' | cut -c6`
str2=`ls -ld /var/log/messages | awk '{print $1}' | cut -c9`
#str5=$(stat -c "%a %n" /var/log/messages |awk '{print $1}')
#if [ "$str5" == "600" ] || [ "$str5" == "644" ] || [ "$str5" == "755" ]
if [ "$str1" != "w" ] && [ "$str2" != "w" ]
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log/messages-permissions" >>p2
	echo "/var/log/messages-permissions is set correct" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "AD.1.8.7.1" >>p12
	echo "$z" >>p6
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/log/messages-permissions" >>p2
	echo "AD.1.8.7.1" >>p12
	echo "/var/log/messages-permissions is not set correct" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi

#AD.1.8.7.2
str1=`ls -ld /var/log/wtmp | awk '{print $1}' | cut -c9`
if [ "$str1" != "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/wtmp-permission" >>p2
		echo "Permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.7.2" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/wtmp-permission" >>p2
		echo "Permission-is-invalid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.7.2" >>p12
fi

#AD.1.8.12.1.1_AD.1.8.12.1.2_AD.1.8.12.2_AD.1.8.12.3_AD.1.8.12.4_AD.1.8.13.3_AD.1.8.13.4___AD.1.8.17.2_AD.1.8.17.3__AD.1.8.19.2_AD.1.8.19.3___AD.1.9.1.1_AD.1.8.21.2_AD.1.8.21.3___AD.1.8.13.1.2

find /usr/local -type f -perm /o+w \! -perm -1000 >world-writable-test
find /usr/local -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /var -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /var -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /etc -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /etc -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /opt -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /opt -type d -perm /o+w \! -perm -1000 >>world-writable-test
find /tmp -type f -perm /o+w \! -perm -1000 >>world-writable-test
find /tmp -type d -perm /o+w \! -perm -1000 >>world-writable-test
for i in `cat world-writable-test`
do
	echo "Protecting Resources - OSRs" >>p1
	echo "File-Directory-write-permissions-for-others" >>p2
	echo "$i" >> p3
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.8.12.1.1_AD.1.8.12.1.2_AD.1.8.12.2_AD.1.8.12.3_AD.1.8.12.4_AD.1.8.13.3_AD.1.8.13.4___AD.1.8.17.2_AD.1.8.17.3_AD.1.8.19.2_AD.1.8.19.3_AD.1.9.1.1_AD.1.8.21.2_AD.1.8.21.3_AD.1.8.13.1.2">>p12
done

rm -rf world-writable-test

#AD.1.8.10
if [ -f /etc/snmpd.conf ] || [ -f /etc/snmp/snmpd.conf ] || [ -f /etc/snmpd/snmpd.conf ]
then
str1=$(stat -c "%a %n" /etc/snmpd.conf |awk '{print $1}')
str2=$(stat -c "%a %n" /etc/snmp/snmpd.conf |awk '{print $1}')
str3=$(stat -c "%a %n" /etc/snmpd/snmpd.conf |awk '{print $1}')
	if [ "$str1" == "640" ] || [ "$str2" == "640" ] || [ "$str3" == "640" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.10" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-permission-is-invalid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.10" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "snmpd.conf-permission" >>p2
		echo "snmpd.conf-file-not-exist" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.10" >>p12
fi


#AD.1.8.11
str7=$(stat -c "%a %n" /var/tmp |awk '{print $1}')
if [ "$str7" == "1777" ]
then
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/tmp-permission" >>p2
	echo "/var/tmp-permission-is-valid" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo AD.1.8.11 >>p12
else
	echo "Protecting Resources - OSRs" >>p1
	echo "/var/tmp-permission" >>p2
	echo "/var/tmp-permission-is-invalid" >> p3
	echo AD.1.8.11 >>p12
	echo "no" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
fi


#AD.1.8.12.6
if [ -f /etc/profile.d/IBMsinit.sh ]
then
str4=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $1}' | cut -c9`
str5=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $1}' | cut -c6`
str6=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $3}'`
str7=`ls -l /etc/profile.d/IBMsinit.sh | awk '{print $4}'`
	if [ "$str4" != "w" ] && [ "$str5" != "w" ] && [ "$str6" == "root" ] && [ "$str7" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "IBMsinit.sh-permissions" >>p2
		echo "IBMsinit.sh-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.8.12.6 >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "IBMsinit.sh-permissions" >>p2
		echo "IBMsinit.sh-permission-is-not-valid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.8.12.6 >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "IBMsinit.sh-permissions" >>p2
		echo "IBMsinit.sh-file-not-exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.8.12.6 >>p12
fi


#AD.1.8.12.7
if [ -f /etc/profile.d/IBMsinit.csh ]
then
str4=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $1}' | cut -c9`
str5=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $1}' | cut -c6`
str6=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $3}'`
str7=`ls -l /etc/profile.d/IBMsinit.csh | awk '{print $4}'`
	if [ "$str4" != "w" ] && [ "$str5" != "w" ] && [ "$str6" == "root" ] && [ "$str7" == "root" ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "IBMsinit.csh-permissions" >>p2
		echo "IBMsinit.csh-permission-is-valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.8.12.7 >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "IBMsinit.csh-permissions" >>p2
		echo "IBMsinit.csh-permission-is-not-valid" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.8.12.7 >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "IBMsinit.csh-permissions" >>p2
		echo "IBMsinit.csh-file-not-exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.8.12.7 >>p12
fi


#AD.1.8.14.1
sk=`cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' |wc -l`
if [ $sk -gt 0 ]
then
cat /var/spool/cron/root |grep -v '#' |grep -v '^$' |awk '{print $6}' >t1
while IFS= read -r line
do
        sk1=`echo $line |cut -c 1`
        if [ "$sk1" == "/" ]
        then
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Full-path-is-specified-for-command- $line in-/var/spool/cron/root" >>p3
		echo "AD.1.8.14.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/var/spool/cron/root" >>p3
		echo "no" >>p4
		echo "AD.1.8.14.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/var/spool/cron/root" >>p2
		echo "No entry found in-/var/spool/cron/root" >>p3
		echo "AD.1.8.14.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1




#AD.1.8.15.1
cat /etc/crontab |grep -v '#' |egrep -v 'SHELL|PATH|MAILTO|HOME' |grep -v '^$' |awk '{print $6}' >t1
if [ $? -ne 0 ]
then
while IFS= read -r line
do
        sk1=`echo $line |cut -c 1`
        if [ "$sk1" == "/" ]
        then
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Full-path-is-specified-for-command- $line in-/etc/crontab" >>p3
		echo "AD.1.8.15.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/etc/crontab" >>p3
		echo "no" >>p4
		echo "AD.1.8.15.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - OSRs" >>p1
                echo "/etc/crontab" >>p2
		echo "No-cron-entry-found-in-/etc/crontab" >>p3
		echo "yes" >>p4
		echo "AD.1.8.15.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1



#AD.1.8.20.1
ls -l /etc/cron.d |awk '{print $9}' |grep -v '^$' >file1
sk=`cat file1 |wc -l`
if [ $sk -ne 0 ]
then
for i in `cat file1`
do
cat /etc/cron.d/$i |grep -v '#' |grep -v '^$' |egrep -v 'SHELL|PATH|MAILTO|HOME|run-parts' |awk '{print $7}' >t1
while IFS= read -r line
do
	sk1=`echo $line |awk '{print $1}' |cut -c 1`
        if [ "$sk1" == "/" ]
        then
                echo "Protecting Resources - User Resources" >>p1
                echo "/etc/cron.d/-directory-structure" >>p2
		echo "Full-path-is-specified-for-command- $line in-/etc/cron.d/$i" >>p3
		echo "AD.1.8.20.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/cron.d/-directory-structure" >>p2
		echo "Full-path-is-not-specified-for-command- $line in-/etc/cron.d/$i" >>p3
		echo "AD.1.8.20.1" >>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
done <t1
done
else
		echo "Protecting Resources - User Resources" >>p1
                echo "/etc/cron.d/-directory-structure" >>p2
		echo "There-is-no-file-available-in-/etc/cron.d/" >>p3
		echo "AD.1.8.20.1" >>p12
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
rm -rf t1 file1

#AD.1.9.1.2
si=`cat /etc/bashrc |grep -v '#'  |grep ". /etc/profile.d/IBMsinit.sh"| wc -l`
sk=`cat /etc/bashrc |grep -v '#'  |sed -n '/$UID -gt 199/,/fi/p' |head -2 |grep umask |awk '{print $2}'`
su=$(cat /etc/profile.d/IBMsinit.sh  | grep -i "umask" |awk '{print $2}')

if [ -f /etc/bashrc ]
then
	if [ $si -gt 0 ]
	then
		echo "Protecting Resources - User Resources" >>p1
                echo "IBMsinit.sh Status in /etc/bashrc" >>p2
                echo "IBMsinit.sh exists  in /etc/bashrc" >>p3
                echo "Yes" >>p4
                echo "AD.1.9.1.2" >>p12
                echo "$c" >> p5
                echo "$z" >>p6
        else
                echo "Protecting Resources - User Resources" >>p1
                echo "IBMsinit.sh status /etc/bashrc" >>p2
                echo "IBMsinit.sh not exists in /etc/bashrc" >>p3
                echo "Yes" >>p4
                echo "AD.1.9.1.2" >>p12
                echo "$c" >> p5
                echo "$z" >>p6
      fi

			if [ $sk -eq 077 ]
			then 
				echo "Protecting Resources - User Resources" >>p1
			    echo "Umask status /etc/bashrc" >>p2
				echo "Umask set correctly in /etc/bashrc" >>p3
				echo "Yes" >>p4
				echo "AD.1.9.1.2" >>p12
				echo "$c" >> p5
				echo "$z" >>p6
			else
				echo "Protecting Resources - User Resources" >>p1
			    echo "Umask status /etc/bashrc" >>p2
				echo "Umask triggering /etc/profile.d/IBMsinit.sh" >>p3
				echo "Yes" >>p4
				echo "AD.1.9.1.2" >>p12
				echo "$c" >> p5
				echo "$z" >>p6
			fi
	else
		echo "Protecting Resources - User Resources" >>p1
	    echo "/etc/bashrc status" >>p2
		echo "/etc/bashrc file does not exists" >>p3
		echo "No" >>p4
		echo "AD.1.9.1.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
	
	



#AD.1.9.1.2.1
cat /etc/login.defs |grep -v '#' |grep UMASK |uniq
if [ $? -eq 0 ]
then
cat /etc/login.defs |grep -v '#' |grep UMASK >t1
while IFS= read -r line
do
        sk1=`echo $line | awk '{print $2}'`
        if [ "$sk1" == "$UMASK_VAL" ]
        then
                echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/login.defs" >>p2
		echo "umask-value-set-as-$line" >>p3
		echo "AD.1.9.1.2.1" >>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
                echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/login.defs" >>p2
		echo "umask-value-set-as-$line" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
        fi
done <t1
else
		echo "Protecting Resources - User Resources" >>p1
                echo "umask-value-in-/etc/login.defs" >>p2
		echo "umask-value-is-not-set-in-/etc/login.defs" >>p3
		echo "no" >>p4
		echo "AD.1.9.1.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
############################################################################################################
#AD.2.1.1,AD.2.1.2,AV.2.1.1.2,AV.2.1.1.3,AV.2.1.1.4
cc=`cat /etc/ssh/sshd_config | grep ^Ciphers |wc -l`
kk=`cat /etc/ssh/sshd_config | grep ^KexAlgorithms |wc -l`
mm=`cat /etc/ssh/sshd_config | grep ^MACs |wc -l`
if [ $cc -ne 0 ] && [ $kk -ne 0 ] && [ $mm -ne 0 ]
then
	c1=`cat /etc/ssh/sshd_config | grep ^Ciphers | awk  '{print $2}'`
	k1=`cat /etc/ssh/sshd_config|grep ^KexAlgorithms |awk -F"," '{print $1}'|awk '{print $2}'`
	k2=`cat /etc/ssh/sshd_config|grep ^KexAlgorithms |awk -F"," '{print $2}'`
	k3=`cat /etc/ssh/sshd_config|grep ^KexAlgorithms |awk -F"," '{print $3}'`
	k4=`cat /etc/ssh/sshd_config|grep ^KexAlgorithms |awk -F"," '{print $4}'`
	k5=`cat /etc/ssh/sshd_config|grep ^KexAlgorithms |awk -F"," '{print $5}'`
	k6=`cat /etc/ssh/sshd_config|grep ^KexAlgorithms |awk -F"," '{print $6}'`
	m1=`cat /etc/ssh/sshd_config|grep ^MACs |awk '{print $2}'`
	if [ $c1 == "aes256-ctr" ]
	then
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "$c1-algorithm-exist-in-ciphers" >>p3
		echo "Yes" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Encryption" >>p1
		echo "Ciphers-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "$c1-algorithm- does not exist-in-ciphers" >>p3
		echo "no" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
	if [ $k1 == "diffie-hellman-group-exchange-sha256" ] && [ $k2 == "diffie-hellman-group14-sha256" ] && [ $k3 == "diffie-hellman-group16-sha512" ] && [ $k4 == "ecdh-sha2-nistp256" ] && [ $k5 == "ecdh-sha2-nistp384" ] && [ $k6 == "ecdh-sha2-nistp521" ]
	then
		echo "Encryption" >>p1
		echo "KexAlogrithm-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "KexAlogrithm-exist-in-ciphers" >>p3
		echo "Yes" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	 else
		echo "Encryption" >>p1
		echo "KexAlogrithm-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "KexAlogrithm-algorithm-does not exists" >>p3
		echo "No" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6 
	fi
	if [ $m1 == "hmac-sha2-512,hmac-sha2-256" ]
	then
		echo "Encryption" >>p1
		echo "MACs-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "MACs-exist-in-ciphers" >>p3
		echo "Yes" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Encryption" >>p1
		echo "MACs-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "MACs-does not exists" >>p3
		echo "Yes" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6	
	fi	
else
		echo "Encryption" >>p1
		echo "Ciphers-KexAlgorithms-value-in-file-/etc/ssh/sshd_config" >>p2
		echo "Ciphers-KexAlgorithms MACs-entry-doesnot-exist-in-/etc/ssh/sshd_config" >>p3
		echo "no" >> p4
		echo "AD.2.1.1_AD.2.1.2_AV.2.1.1.2_AV.2.1.1.3_AV.2.1.1.4" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi






############################################################################################################
#AV.1.7.2

skk=`cat /etc/ssh/sshd_config |grep "Pubkey"|awk '{print $2}'`


	if [ "$skk" == "yes" ]	
	then
		echo "Identify and Authenticate Users" >>p1
		echo "Public Key Authentication" >>p2
		echo "Public Key Authentication is allowed" >>p3
		echo "yes" >>p4
		echo "AV.1.7.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Identify and Authenticate Users" >>p1
		echo "Public Key Authentication" >>p2
		echo "Public Key Authentication is not allowed" >>p3
		echo "No" >>p4
		echo "AV.1.7.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
#######################################################################################################

#AD.2.1.3.0_AD.2.1.3.1_AD.2.1.3.2
grep ^password /etc/pam.d/* | egrep 'required|sufficient' | grep  pam_unix.so |awk -F_ '{print $1}' > temp_pam.so
for i in `cat temp_pam.so`
do
sk=`cat $i |egrep 'md5|sha512' |grep shadow |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "Encryption" >>p1
		echo "Password-EncryptionRequired" >>p2
		echo "sha512-and-shadow-is-set-in-file-$i" >>p3
		echo "yes" >>p4
		echo "AD.2.1.3.0_AD.2.1.3.1_AD.2.1.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Encryption" >>p1
		echo "Password-EncryptionRequired" >>p2
		echo "sha512-and-shadow-is-not-set-in-file-$i" >>p3
		echo "no" >>p4
		echo "AD.2.1.3.0_AD.2.1.3.1_AD.2.1.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
done
rm -rf temp_pam.so



#AD.1.1.4.6
sk=$(cat /etc/pam.d/system-auth| grep pam_deny.so |wc -l)
sl=$(cat /etc/pam.d/password-auth|grep pam_deny.so | wc -l)

if  [ $sk -gt 0 ]
then
		echo "Password Requirements" >>p1
		echo "pam_deny.so requirement." >>p2
		echo "Pam_deny.so is available in /etc/pam.d/system-auth" >>p3
		echo "yes" >>p4
		echo "AD.1.1.4.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
		echo "pam_deny.so requirement." >>p2
		echo "Pam_deny.so is not available in /etc/pam.d/system-auth" >>p3
		echo "no" >>p4
		echo "AD.1.1.4.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
if [ $sl -gt 0 ]
then
		echo "Password Requirements" >>p1
		echo "pam_deny.so requirement." >>p2
		echo "Pam_deny.so is available in /etc/pam.d/password-auth" >>p3
		echo "yes" >>p4
		echo "AD.1.1.4.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
		echo "pam_deny.so requirement." >>p2
		echo "Pam_deny.so is not available in /etc/pam.d/password-auth" >>p3
		echo "no" >>p4
		echo "AD.1.1.4.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi
#####################################################################################################
#AD.1.1.4.7
sk=$(cat /etc/pam.d/system-auth | grep ^password | egrep -w "pam_cracklib.so|pam_pwquality.so|pam_unix.so|pam_deny.so"|wc -l)
sl=$(cat /etc/pam.d/password-auth | grep ^password | egrep -w "pam_cracklib.so|pam_pwquality.so|pam_unix.so|pam_deny.so"|wc -l)

if  [ $sk -eq 3 ]
then
		echo "Password Requirements" >>p1
		echo "Ensure pam modules are in correct order" >>p2
		echo "All are in correct order /etc/pam.d/system-auth" >>p3
		echo "yes" >>p4
		echo "AD.1.1.4.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
		echo "Ensure pam modules are in correct order" >>p2
		echo "Not in correct order /etc/pam.d/system-auth" >>p3
		echo "no" >>p4
		echo "AD.1.1.4.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
if [ $sl -eq 3 ]
then
		echo "Password Requirements" >>p1
		echo "Ensure pam modules are in correct order" >>p2
		echo "All are in correct order /etc/pam.d/password-auth" >>p3
		echo "yes" >>p4
		echo "AD.1.1.4.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
		echo "Ensure pam modules are in correct order" >>p2
		echo "Not in correct order /etc/pam.d/password-auth" >>p3
		echo "no" >>p4
		echo "AD.1.1.4.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
fi
####################################################################################################




#AD.1.1.7.3
echo "bin,daemon,adm,lp,sync,shutdown,halt,mail,uucp,operator,games,gopher,ftp,nobody,dbus,usbmuxd,rpc,avahi-autoipd,vcsa,rtkit,saslauth,postfix,avahi,ntp,apache,radvd,rpcuser,nfsnobody,qemu,haldaemon,nm-openconnect,pulse,gsanslcd,gdm,sshd,tcpdump" >temp
tr "," "\n" < temp > temp1
             
	for i in `cat temp1`
        do
		#cat /etc/shadow | awk -F"_" '{print $1}' | grep -w ^$i
		getent passwd $i
		if [ $? -eq 0 ]
		then
		sk=`passwd -S $i |awk '{print $2}'`
		if [ "$sk" == "PS" ]
                then
                        echo "AD.1.1.7.3" >>p12
                        echo "Password_requirement" >>p1
                        echo "Password for system ID's" >>p2
                        echo "Password is set for system ID $i" >> p3
                        echo "no" >>p4
                        echo "$c" >> p5
                        echo "$z" >>p6
		else
			echo "AD.1.1.7.3" >>p12
                        echo "Password_requirement" >>p1
                        echo "Password for system ID's" >>p2
                        echo "Password is not set for system ID $i" >> p3
                        echo "yes" >>p4
                        echo "$c" >> p5
                        echo "$z" >>p6
		fi
		fi
        done
rm -rf temp temp1

#AD.1.1.8.3.1_GID-validation
cat /etc/group | awk -F"_" '{print $3}'| sort  | uniq -cd | awk '{print $2}'> temp_gid
sp=`cat temp_gid | wc -c`
if [ "$sp" == 0 ]
then
		echo "Password_requirement" >>p1
		echo "GID_validation" >>p2
		echo "No_duplicate_GID-value_for_users_in_/etc/group" >>p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "AD.1.1.8.3.1" >>p12
		echo "$z" >>p6	
else
		for i in `cat temp_gid`
		do
		echo "Password_requirement" >>p1
		echo "gid_validation" >>p2
		echo "Duplicate-gid-value-for-GID-$i in /etc/group" >>p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "AD.1.1.8.3.1" >>p12
		echo "$z" >>p6	
		done
fi




#AD.1.2.1.4.1
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" != "Red" ]
then
cat /etc/syslog-ng/syslog-ng.conf | grep "authpriv.\*" | grep "/var/log/secure"
	if [ $? -eq 0 ]
	then

				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/syslog-ng/syslog-ng.conf found" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.1" >>p12
			
	else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/syslog-ng/syslog-ng.conf not found" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.1" >>p12
	fi
else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/syslog-ng/syslog-ng.conf-Not_Applicable-for-redhat-linux" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.1" >>p12
		
fi




#AD.1.2.1.4.2
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
sk1=`cat /etc/rsyslog.conf | grep "^authpriv.\*" | grep "/var/log/secure" |wc -c`
sk2=`cat /etc/rsyslog.conf | grep "^*.info_mail.none_authpriv.none_cron.none" |grep /var/log/messages |wc -c`

	if [ "$sk1" -gt "0" ] || [ "$sk2" -gt "0" ]
	then
		skl=`cat /etc/rsyslog.conf | grep "authpriv.\*" | grep "/var/log/secure"`
		if [ $? -eq 0 ]
		then

				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skl'" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.2" >>p12
			
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry missing for '$skl'" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.2" >>p12
		fi
		skz=`cat /etc/rsyslog.conf | grep "*.info_mail.none_authpriv.none_cron.none" |grep /var/log/messages`
		if [ $? -eq 0 ]
		then
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry exist for '$skz'" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.2" >>p12
		else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skz'" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.2" >>p12	
		fi
	else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "/etc/rsyslog.conf entry not exist for '$skl' and '$$kz'" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.2" >>p12		
	fi
else
				echo "Logging" >>p1
				echo "Login success or failure" >>p2
				echo "Not for Redhat Linux" >>p3
				echo "Not_Applicable" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.2.1.4.2" >>p12
		
fi


#AD.1.2.6_logrotate
a=$(cat /etc/logrotate.conf |grep -v '#' |grep ^rotate |uniq  |awk '{print $2}')

if [ $a -eq 13 ]
then
		echo "Logging" >>p1
        echo "RetainLogFiles" >>p2
		echo "logrotate-is-set as correct for '/var/log/' in-/etc/logrotate.conf" >>p3
		echo "AD.1.2.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Logging" >>p1
        echo "RetainLogFiles" >>p2
		echo "logrotate-is-set as incorrect for '/var/log/' in-/etc/logrotate.conf" >>p3
		echo "AD.1.2.6">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi



AD.1.2.7.6_Logging
sl=`whereis service | awk '{print $2}'`
A=`$sl ntpd status |wc -c`
B=`$sl chronyd status |wc -c`
if [ $A -gt 0 ]
then
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd-is-running" >>p3
		echo "AD.1.2.7.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
	if [ $B -gt 0 ]
	then
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "chronyd-is-running" >>p3
		echo "AD.1.2.7.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Logging" >>p1
                echo "Synchronized system clocks, ensure it is active" >>p2
		echo "ntpd-chronyd-is-not-running" >>p3
		echo "AD.1.2.7.6">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
fi

#AD.1.4.3.1.1
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
	st=$(sestatus |head -n 1|awk '{print $3}')
	if [ $? == "disabled"
	then
		echo "System-Settings" >>p1
		echo "Ensure Selinux is not installed" >>p2
		echo "Selinux disabled" >>p3	
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.3.1.1" >>p12
	else
		echo "System-Settings" >>p1
		echo "Ensure Selinux is installed" >>p2
		echo "Selinux enabled" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.3.1.1" >>p12	
	fi
else
	echo "System-Settings" >>p1
	echo "Not a RHEL" >>p2
	echo "Manual check required" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.4.3.1.1" >>p12		
fi




#AD.1.4.3.1.2_AD.1.4.3.1.3
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
	A=`getenforce`
	B=`cat /etc/selinux/config |grep ^SELINUX= |awk -F= '{print $2}'`
	if [ "$A" == "Enforcing" ] || [ "$A" == "Permissive" ] && [ "$B" == "enforcing" ] || [ "$B" == "permissive" ]
	then
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "$B-set-in-file-/etc/selinux/config" >>p3	
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.4.3.1.2_AD.1.4.3.1.3" >>p12
	
	else
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "$B-set-in-file-/etc/selinux/config" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.4.3.1.2_AD.1.4.3.1.3" >>p12	
	fi
else
				echo "System-Settings" >>p1
				echo "Ensure the SELinux state is enforcing or permissive" >>p2
				echo "It is not for Redhat Linux" >>p3
				echo "no" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.4.3.1.2_AD.1.4.3.1.3" >>p12
fi


#AD.1.4.3.1.4
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
	st=$(sestatus |head -n 4|grep ^Loaded|awk '{print $4}')
	if [ $st == "targeted" ]
	then
		echo "System-Settings" >>p1
		echo "SeLinux Loaded policy" >>p2
		echo "Policy is set to Targeted" >>p3	
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.3.1.4" >>p12
	else
		echo "System-Settings" >>p1
		echo "SeLinux Loaded policy" >>p2
		echo "Policy is not set to Targeted" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.3.1.4" >>p12	
	fi
else
	echo "System-Settings" >>p1
	echo "Not a RHEL" >>p2
	echo "Manual check required" >>p3
	echo "No" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.4.3.1.4" >>p12		
fi

#AD.1.5.3.1_AD.1.5.3.3
sl=`which service`
sl1=`$sl nfs status`
if [ $? -eq 0 ]
then
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ $? -eq 0 ] && [ "$szm" == "644" ]
	then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is running and file permission is correct" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.1_AD.1.5.3.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is running and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "AD.1.5.3.1_AD.1.5.3.3" >>p12
	fi
else
	szm=$(stat -c "%a %n" /etc/exports |awk '{print $1}')
	if [ $? -eq 0 ] && [ "$szm" == "644" ]
	then
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not running and file permission is correct" >> p3
		echo "yes" >>p4
		echo "AD.1.5.3.1_AD.1.5.3.3" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Network Settingss" >>p1
		echo "/etc/exports" >>p2
		echo "NFS service is not running and file permission is incorrect" >> p3
		echo "no" >>p4
		echo "$z" >>p6
		echo "$c" >> p5
		echo "AD.1.5.3.1_AD.1.5.3.3" >>p12
	fi
fi



#AD.1.5.9.18.1_AD.1.5.9.18.2_AD.1.5.9.18.3
str=$(rpm -qa | grep snmp*|wc -l)
str1=$(systemctl status snmp.service|wc -l)
if [ $str == 0 ] || [ $str1 == 0 ]
then
	echo "Network Settingss" >>p1
	echo "SNMP Service" >>p2
	echo "SNMP Service is Disabled" >>p3
	echo "yes" >>p4
    echo "AD.1.5.9.18.1_AD.1.5.9.18.2_AD.1.5.9.18.3" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "SNMP Service" >>p2
	echo "SNMP Service is not disabled" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.18.1_AD.1.5.9.18.2_AD.1.5.9.18.3" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

#AD.1.5.9.20.1
stn=`cat /etc/sysctl.conf |grep ^net.ipv4.tcp_syncookies |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ $stn == 1 ]
then
	echo "Network Settingss" >>p1
	echo "TCP/IP stack setting" >>p2
	echo "net.ipv4.tcp_syncookies = $stn-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
    echo "AD.1.5.9.20.1" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "TCP/IP stack setting" >>p2
	echo "net.ipv4.tcp_syncookies = $stn _is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.1" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#AD.1.5.9.20.2
stn=`cat /etc/sysctl.conf |grep ^net.ipv4.icmp_echo_ignore_broadcasts |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ $stn == 1 ]
then
	echo "Network Settingss" >>p1
	echo "TCP/IP stack setting" >>p2
	echo "net.ipv4.icmp_echo_ignore_broadcasts = $stn-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
    echo "AD.1.5.9.20.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "TCP/IP stack setting" >>p2
	echo "net.ipv4.icmp_echo_ignore_broadcasts = $stn _is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.2" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi


#AD.1.5.9.20.3
stn=`cat /etc/sysctl.conf |grep ^net.ipv4.conf.all.accept_redirects |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ $stn == 0 ]
then
	echo "Network Settingss" >>p1
	echo "TCP/IP stack setting" >>p2
	echo "net.ipv4.conf.all.accept_redirects = $stn-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
    echo "AD.1.5.9.20.3" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "TCP/IP stack setting" >>p2
	echo "net.ipv4.conf.all.accept_redirects = $stn _is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.3" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi



#AD.1.5.9.20.5
stn=$(cat /etc/sysctl.conf |grep ^net.ipv4.conf.all.accept_source_route |awk '{print $3}')
stt=$(cat /etc/sysctl.conf |grep ^net.ipv4.conf.default.accept_source_route |awk '{print $3}')
if [ $stn == 0 ] && [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Ensure source routed packets are not accepted " >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.20.5" >>p12
elif [ $stn == 0 ] || [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "One of this not configured net.ipv6.conf.all.accept_ra=$stn net.ipv6.conf.default.accept_ra=$stt" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.5" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Ensure source routed packets are not accepted is not configured" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.5" >>p12
	echo "$c" >> p5
	echo "$z" >>p6		
fi


#AD.1.5.9.20.6
stn=$(cat /etc/sysctl.conf |grep ^net.ipv4.conf.all.secure_redirects |awk '{print $3}')
stt=$(cat /etc/sysctl.conf |grep ^net.ipv4.conf.default.secure_redirects |awk '{print $3}')
if [ $stn == 0 ] && [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Ensure secure ICMP redirects are not accepted " >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.20.6" >>p12
elif [ $stn == 0 ] || [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "One of this not configured net.ipv6.conf.all.accept_ra=$stn net.ipv6.conf.default.accept_ra=$stt" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.6" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Ensure secure ICMP redirects are not accepted is not configured" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.6" >>p12
	echo "$c" >> p5
	echo "$z" >>p6		
fi



#AD.1.5.9.20.7
stn=$(cat /etc/sysctl.conf |grep ^net.ipv4.conf.all.log_martians |awk '{print $3}')
stt=$(cat /etc/sysctl.conf |grep ^net.ipv4.conf.default.log_martians |awk '{print $3}')
if [ $stn == 1 ] && [ $stt == 1 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Ensure suspicious packets are logged " >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.20.7" >>p12
elif [ $stn == 1 ] || [ $stt == 1 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "One of this not configured net.ipv4.conf.all.log_martians=$stn net.ipv4.conf.default.log_martians=$stt" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.7" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Ensure suspicious packets are logged is not configured" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.7" >>p12
	echo "$c" >> p5
	echo "$z" >>p6		
fi

#AD.1.5.9.20.8
stn=`cat /etc/sysctl.conf |grep ^net.ipv4.icmp_ignore_bogus_error_responses |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ $stn == 1 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "Correct-setting-net.ipv4.icmp_ignore_bogus_error_responses = $stn-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
    echo AD.1.5.9.20.8 >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.icmp_ignore_bogus_error_responses = $stn _is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo AD.1.5.9.20.8 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

#AD.1.5.9.21.1
stn=$(cat /etc/sysctl.conf |grep ^net.ipv6.conf.all.accept_ra |awk '{print $3}')
stt=$(cat /etc/sysctl.conf |grep ^net.ipv6.conf.default.accept_ra |awk '{print $3}')
if [ $stn == 0 ] && [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "IPv6 router advertisements are not accepted " >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.21.1" >>p12
elif [ $stn == 0 ] || [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "One of the IPv6 router advertisements is not configured net.ipv6.conf.all.accept_ra=$stn net.ipv6.conf.default.accept_ra=$stt" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.21.1" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "IPv6 router advertisements is not configured" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.21.1" >>p12
	echo "$c" >> p5
	echo "$z" >>p6		
fi
######################################################################################################
#AD.1.5.9.21.2
stn=$(cat /etc/sysctl.conf |grep ^net.ipv6.conf.all.accept_redirect |awk '{print $3}')
stt=$(cat /etc/sysctl.conf |grep ^net.ipv6.conf.default.accept_redirect |awk '{print $3}')
if [ $stn == 0 ] && [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "IPv6 redirect is correctly configured " >>p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo AD.1.5.9.21.2 >>p12
elif [ $stn == 0 ] || [ $stt == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "One of the IPv6 redirect is not configured net.ipv6.conf.all.accept_redirect=$stn net.ipv6.conf.default.accept_redirect=$stt" >>p3
	echo "no" >>p4
	echo AD.1.5.9.21.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "IPv6 redirect is not configured" >>p3
	echo "no" >>p4
	echo AD.1.5.9.21.2 >>p12
	echo "$c" >> p5
	echo "$z" >>p6		
fi
#################################################################################################################333
#AD.1.5.9.24.1.1_Vsftpd service
str=$(rpm -qa vsftpd|wc -l)
str1=$(systemctl status vsftpd | wc -l)
if [ $str -eq 0 ] || [ $str1 -eq 0 ] 
then
	
	echo "System Settings" >>p1
	echo "VSFTPD is Serivce is Disabled" >>p2
	echo "VSFTPD Service is disabled on the server" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.24.1.1" >>p12
else
	echo "System Settings" >>p1
	echo "VSFTPD is service is enabled" >>p2
	echo "VSFTPD Service is enabled on the server" >> p3
	echo "No" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.24.1.1" >>p12
fi
###################################################################################################################
#AD.1.5.9.24.1.2_vsftpd filecheck
str=$(rpm -qa vsftpd|wc -l)
if [ $str -ne 0 ] 
then
	a=$(stat -c "%a %n" /etc/vsftpd/vsftpd.conf |awk '{print $1}')
	bb=$(stat -c "%a %n" /etc/vsftpd/user_list |awk '{print $1}')
	
	if [ $a -eq 600 ] && [ $bb -eq 600 ]
	then
		echo "System Settings" >>p1
		echo "Vsftpd and user_list permission" >>p2
		echo "Vsftpd and user list had permission" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.5.9.24.1.2" >>p12
	else
		echo "System Settings" >>p1
		echo "vsftpd.conf or user_list does not meet permission" >>p2
		echo "root_id_not_exist" >> p3
		echo "no" >>p4
		echo "AD.1.5.9.24.1.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
	echo "System Settings" >>p1
	echo "VSFTPD is not installed" >>p2
	echo "VSFTPD package is not installed on the server" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.24.1.2" >>p12
fi

#AD.1.5.9.24.2_filecheck
str=$(rpm -qa vsftpd|wc -l)
str1=$(rpm -qa ftpd|wc -l)
if [ $str -ne 0 ] || [ $str1 -ne 0 ]
then
	a=$(cat /etc/vsftpd/vsftpd.conf|grep ^anonymous_enable|awk -F"=" '{print $2}')
	
	
	if [ $a == "NO" ]
	then
		echo "System Settings" >>p1
		echo "Disable anonymous ftp if vsftpd is enabled." >>p2
		echo "Disable anonymous ftp if vsftpd is enabled." >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.5.9.24.2" >>p12
	else
		echo "System Settings" >>p1
		echo "Enabled anonymous ftp if vsftpd is enabled." >>p2
		echo "Enabled anonymous ftp if vsftpd is enabled" >> p3
		echo "no" >>p4
		echo "AD.1.5.9.24.2" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
	echo "System Settings" >>p1
	echo "VSFTPD is not installed" >>p2
	echo "VSFTPD package is not installed on the server" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.24.2" >>p12
fi


#AD.1.5.9.25
sl=`which service`
sl1=`$sl nfs status`
if [ $? -eq 0 ] && [ -f /etc/exports ]
then
	pp=`which exportfs`
	sk=`$pp |grep "<world>" |awk '{print $1}' |wc -c`
	if [ $sk -ne 0 ]
	then
	/usr/sbin/exportfs |grep "<world>" |awk '{print $1}' >>ff2
	for i in `cat ff2`
	do
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "NFS is shared to World for FS $i" >> p3
		echo "no" >>p4
		echo "AD.1.5.9.25" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	done
	else
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "No files shared to world in NFS" >> p3
		echo "yes" >>p4
		echo "AD.1.5.9.25" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
		
else
if [ -f /etc/exports ]
then
	pp=`which exportfs`
	sk=`$pp |grep "<world>" |awk '{print $1}' |wc -c`
	if [ $sk -ne 0 ]
	then
	/usr/sbin/exportfs |grep "<world>" |awk '{print $1}' >>ff2
	for i in `cat ff2`
	do
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "NFS is shared to World for FS $i" >> p3
		echo "no" >>p4
		echo "AD.1.5.9.25" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	done
	else
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "No files shared to world in NFS" >> p3
		echo "yes" >>p4
		echo "AD.1.5.9.25" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Network Settingss" >>p1
		echo "Network file system (nfs) settings" >>p2
		echo "NFS is not running and file /etc/exports not exist" >> p3
		echo "yes" >>p4
		echo "AD.1.5.9.25" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
fi
fi


#AD.1.4.2.1_filecheck
if [ "$(rpm -q ftp)" != "package ftp is not installed" ] || [ "$(rpm -q vsftpd)" != "package vsftpd is not installed" ]
then
	aa=`cat /etc/ftpusers | grep -i ^root |wc -c`
	bb=`cat /etc/vsftpd.ftpusers | grep -i ^root |wc -c`
	cc=`cat /etc/vsftpd/ftpusers |grep -i ^root |wc -c`
	if [ $aa -gt 0 ] || [ $bb -gt 0 ] || [ $cc -gt 0 ]
	then
		echo "System Settings" >>p1
		echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
		echo "root_id_exist in /etc/ftpusers-or-/etc/vsftpd.ftpusers" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.4.2.1" >>p12
	else
		echo "System Settings" >>p1
		echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
		echo "root_id_not_exist" >> p3
		echo "no" >>p4
		echo "AD.1.4.2.1" >>p12
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
	echo "System Settings" >>p1
	echo "root-user-in-/etc/ftpusers-or-/etc/vsftpd.ftpusers-or-/etc/vsftp/ftpusers" >>p2
	echo "FTP package is not installed on the server" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.4.2.1" >>p12
fi


#AD.1.5.9.20.4
stn=`cat /etc/sysctl.conf |grep ^net.ipv4.ip_forward |awk -F"=" '{print $2}' |sed -e 's/ //g'`
if [ $stn == 0 ]
then
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.ip_forward = $stn-in-/etc/sysctl.conf" >>p3
	echo "yes" >>p4
    echo "AD.1.5.9.20.4" >>p12
	echo "$c" >> p5
	echo "$z" >>p6
	
else
	echo "Network Settingss" >>p1
	echo "/etc/sysctl.conf" >>p2
	echo "net.ipv4.ip_forward = $stn _is_not_set-in-/etc/sysctl.conf" >>p3
	echo "no" >>p4
	echo "AD.1.5.9.20.4" >>p12
	echo "$c" >> p5
	echo "$z" >>p6	
fi

#AD.1.2.8.1
str=$(systemctl status auditd.service |head -3 | grep active| awk '{print $2}')

if [ $str == "active" ]
then
		echo "Logging" >>p1
		echo "Audit Daemon" >>p2
		echo "AD.1.2.8.1" >>p12
		echo "Audit Daemon is running"  >> p3
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Logging" >>p1
		echo "Audit Daemon" >>p2
		echo "AD.1.2.8.1" >>p12
		echo "Audit Daemon service is not running" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

################################################################################################
#AD.2.0.1.0 
if [ -f /etc/motd ] || [ -f /etc/issue ]
then
	str=`cat /etc/motd |wc -c`
	if [ "$str" -gt "0" ]
	then
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists" >>p2
		echo "Business use notice mentioned in /etc/motd" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.2.0.1.0" >>p12
	else 
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists" >>p2
		echo "Business use notice not mentioned in /etc/motd" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.2.0.1.0" >>p12
	fi
else
		echo "Business Use Notice" >>p1
		echo "Business_use_notice_entry_not_exist_in_file_/etc/motd" >>p2
		echo "/etc/motd_or_/etc/issue_file_not_exist" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.2.0.1.0" >>p12
fi
#####################################################################################################


#AD.1.5.9.24.3_filecheck
str=$(rpm -qa vsftpd|wc -l)
str1=$(rpm -qa ftpd|wc -l)
if [ $str -ne 0 ] || [ $str1 -ne 0 ]
then
	if [ -f /etc/vsftpd/vsftpd.conf ] #&& [ -f /etc/vsftpd/user_list ]
	then
		ck=$(cat /etc/vsftpd/vsftpd.conf|grep ^anonymous_enable|awk -F"=" '{print $2}')		
		if [ $ck == "NO" ]
		then
			echo "System Settings" >>p1
			echo "Configure anonymous_enable settings " >>p2
			echo "Configure anonymous_enable settings $ck" >> p3
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
			echo "AD.1.5.9.24.3" >>p12
		else
			echo "System Settings" >>p1
			echo "anonymous_enable settings " >>p2
			echo "anonymous_enable settings $ck" >> p3
			echo "no" >>p4
			echo "AD.1.5.9.24.3" >>p12
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
		echo "System Settings" >>p1
		echo "vsftpd.conf or user_list file file status" >>p2
		echo "vsftpd.conf or user_list file file not exists" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.5.9.24.3" >>p12
	fi
else
	echo "System Settings" >>p1
	echo "VSFTPD is not installed" >>p2
	echo "VSFTPD package is not installed on the server" >> p3
	echo "yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.5.9.24.3" >>p12
fi



#AD.1.4.2.2_Root
cat /etc/passwd |grep ^root| awk -F"_" '{print $4}'

	if [ $? == 0 ]
	then
		echo "System Settings" >>p1
		echo "Ensure default group for the root account is GID 0" >>p2
		echo "Root GID is set to 0" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo AD.1.4.2.2 >>p12
	else	
		echo "System Settings" >>p1
		echo "Ensure default group for the root account is GID 0" >>p2
		echo "Root GID is not set to 0" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.4.2.2" >>p12
	fi



#######################Siva Updates ##################################################
#AD.1.5.9.26
sl=`which service`
sl1=`$sl nntpd status`
if [ $? -eq 0 ]
then
	sp=`timeout 10s openssl s_client -connect www.google.com_443 2>/dev/null | head -3 |grep CONNECTED |wc -l`
	if [ $sp -gt 0 ]
	then
		echo "Network Settings" >>p1
		echo "NNTP authentication and identification" >>p2
		echo "Internet is enabled and nntpd service is running. Manual intervention required to check newsgroups on the server for NNTP" >>p3
		echo "Manual_Check_Required to see if any New transfer settings on the server" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.26" >>p12
	else
		echo "Network Settings" >>p1
		echo "NNTP authentication and identification" >>p2
		echo "NNTPD service is running, but internet is disasbled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.26" >>p12
	fi
else
	echo "Network Settings" >>p1
	echo "NNTP authentication and identification" >>p2
	echo "NNTPD service is not running on the server" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.5.9.26" >>p12
fi

#AD.1.5.9.27_TFTP filecheck
rpm -qa |egrep "tftp-server|tftp"
if [ $? -ne 0 ]
then
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "AD.1.5.9.27" >>p12
		echo "Base package tftp or tftp-server is not installed" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Network Settings" >>p1
		echo "TFTP System Setting" >>p2
		echo "AD.1.5.9.27" >>p12
		echo "Base package tftp or tftp-server is installed. Please check the Techspec for additional check" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#AD.1.5.9.29_Avahi Daemon
rpm -qa |egrep "tftp-server|tftp"
systemctl status avahi-daemon.service |head -3 | grep active| awk '{print $2}'

if [ $? == "active" ]
then
		echo "Network Settings" >>p1
		echo "Avahi Setting" >>p2
		echo "AD.1.5.9.29" >>p12
		echo "Base package Avahi is installed and service is running"  >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Network Settings" >>p1
		echo "Avahi Setting" >>p2
		echo "AD.1.5.9.29" >>p12
		echo "Avahi Package was not installed and service is not running" >> p3
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.1.5.9.30
sl=$(lsof -i_389| grep LISTEN| wc -l)
sk=$(lsof -i_636| grep LISTEN| wc -l)
if [ $sl -eq 0 ] && [ $sk -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "LDAP" >>p2
		echo "LDAP is not LISTENING" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.30" >>p12
	else
		echo "Network Settings" >>p1AD.1.5.9.30
		echo "LDAP" >>p2
		echo "LDAP service is running" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.30" >>p12
fi
#AD.1.5.9.35
systemctl status cups.service | egrep "active"| awk '{print $2}'
if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "CUPS" >>p2
		echo "CUPS is not running " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.35" >>p12
	else
		echo "Network Settings" >>p1
		echo "CUPS" >>p2
		echo "CUPS service is running, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.35" >>p12
fi

#AD.1.5.11.1_AD.1.5.11.2
sz=$(systemctl status rsh.socket | wc -l)
sa=$(systemctl status rlogin.socket | wc -l)
if [ $sz -eq 0 ] && [ $sa -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "RSH and RLOGIN" >>p2
		echo "RSH and RLOGIN are disabled" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.11.1_AD.1.5.11.2" >>p12
else
		echo "Network Settings" >>p1
		echo "RSH and RLOGIN" >>p2
		echo "One of them or both RSH,RLOGIN are Enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.11.1_AD.1.5.11.2" >>p12
fi
#AD.1.8.3.2.1
str=`ls -ld /usr |awk '{print $1}' |cut -c9`
if [ "$str" == "w" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr-dir-permission" >>p2
		echo "/usr-dir-is-writtable-by-others" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.2.1" >>p12
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr-dir-permission" >>p2
		echo "/usr-dir-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.2.1" >>p12
fi

#AD.1.8.4.2.1_AD.1.8.4.2.3
str=$(stat -c "%a %n" /etc/shadow |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow-permission" >>p2
		echo "/etc/shadow-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.2.1_AD.1.8.4.2.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/shadow-permission" >>p2
		echo "/etc/shadow-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.2.1_AD.1.8.4.2.3" >>p12
fi

#AD.1.8.4.2.2_AD.1.8.4.2.4
str=$(stat -c "%a %n" /etc/gshadow |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/gshadow-permission" >>p2
		echo "/etc/gshadow-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.2.2_AD.1.8.4.2.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/gshadow-permission" >>p2
		echo "/etc/gshadow-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.2.2_AD.1.8.4.2.4" >>p12
fi


#AD.1.8.4.3.1
str=$(stat -c "%a %n" /etc/crontab |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permission" >>p2
		echo "/etc/crontab-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.1" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permission" >>p2
		echo "/etc/crontab-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.1" >>p12
fi

#AD.1.8.4.3.2
str=$(stat -c "%a %n" /etc/cron.hourly |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.hourly-permission" >>p2
		echo "/etc/cron.hourly-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.hourly-permission" >>p2
		echo "/etc/cron.hourly-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.2" >>p12
fi

#AD.1.8.4.3.3
str=$(stat -c "%a %n" /etc/cron.daily |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.daily-permission" >>p2
		echo "/etc/cron.daily-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.daily-permission" >>p2
		echo "/etc/cron.daily-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.3" >>p12
fi


#AD.1.8.4.3.4_Crontab.weekly
str=$(stat -c "%a %n" /etc/cron.weekly |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.weekly-permission" >>p2
		echo "/etc/cron.weekly-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.weekly-permission" >>p2
		echo "/etc/cron.weekly-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.4" >>p12
fi

#AD.1.8.4.3.5_Crontab.monthly
str=$(stat -c "%a %n" /etc/cron.monthly |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.monthly-permission" >>p2
		echo "/etc/cron.monthly-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.5" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.monthly-permission" >>p2
		echo "/etc/cron.monthly-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.5" >>p12
fi
#AD.1.8.4.3.6
str=$(stat -c "%a %n" /etc/cron.d |awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permission" >>p2
		echo "/etc/cron.d-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.6" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permission" >>p2
		echo "/etc/cron.d-permission-is-incorrectly-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.4.3.6" >>p12
fi

#AD.1.8.12.8_gpgcheck
a=$(cat /etc/yum.conf |egrep "gpgcheck"|cut -b 10)
if [ $a -eq 1 ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "Gpgcheck" >>p2
		echo "AD.1.8.12.8" >>p12
		echo "Gpgcheck is set correctly" >> p3
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6	
else
		echo "Protecting Resources - OSRs" >>p1
		echo "Gpgcheck" >>p2
		echo "AD.1.8.12.8" >>p12
		echo "Gpgcheck is not set to one" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#AD.1.8.3.5_Grub2-Permission
str=$(stat -c "%a %n" /boot/grub2 |awk '{print $1}')
if [ "$str" == "700" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot/grub2-permission" >>p2
		echo "/boot/grub2-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.5" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot/grub2-permission" >>p2
		echo "/boot/grub2-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.5" >>p12
fi

#AD.1.8.3.4_boot-permission&owner
str=$(stat -c "%a %n" /boot |awk '{print $1}')
str1=$(ls -ld /boot |awk '{print $3}')
if [ $str == "555" ] && [ $str1 == "root" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot-permission and owner" >>p2
		echo "/boot-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/boot-permission and owner" >>p2
		echo "/boot-permission and owner-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.3.4" >>p12
fi

#AD.1.5.9.34_Rsync Service
str=$(systemctl status rsyncd.service |grep running | wc -l)
if [ $str -gt 0 ]
then
		echo "Network Settings" >>p1
		echo "Rsync" >>p2
		echo "Rsync is Enabled" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.34" >>p12
	else
		echo "Network Settings" >>p1
		echo "Rsync" >>p2
		echo "Rsync-is Disabled" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.34" >>p12
fi

#AD.1.5.9.40_rsh package
str=$(rpm -qa |grep rsh| wc -l)
if [ $str -gt 0 ]
then
		echo "Network Settings" >>p1
		echo "RSH" >>p2
		echo "RSH package is installed" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.40" >>p12
	else
		echo "Network Settings" >>p1
		echo "RSH" >>p2
		echo "RSH package is not installed" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.40" >>p12
fi

#AD.1.5.11.3_rexec Service
str=$(systemctl status rexec|wc -l)
if [ $str -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Rexec" >>p2
		echo "Rexec service is disabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.11.3" >>p12
	else
		echo "Network Settings" >>p1
		echo "Rexec" >>p2
		echo "Rexec service is enabled" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.11.3" >>p12
fi

#AD.1.5.13.1_Ensure core dumps are restricted
str=$(ulimit -c)
str1=$(sysctl fs.suid_dumpable| awk '{print $3}')
if [ $str -eq 0 ] && [ $str1 -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Core dumps and ulimit" >>p2
		echo "Core-dump-ulimit-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.13.1" >>p12
	else
		echo "Network Settings" >>p1
		echo "Core dumps and ulimit" >>p2
		echo "Core-dump-ulimit-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.13.1" >>p12
fi

#AD.1.5.13.2_ASLR
str=$(sysctl -a --pattern "randomize" |awk '{print $3}')
if [ "$str" == "2" ]
then
		echo "Network Settings" >>p1
		echo "ASLR" >>p2
		echo "ASLR-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.13.2" >>p12
	else
		echo "Network Settings" >>p1
		echo "ASLR" >>p2
		echo "ASLR-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.13.2" >>p12
fi

#AD.1.8.3.2.2_/usr

echo "Protecting Resources - OSRs" >>p1
echo "/usr Exceptions to OSR" >>p2
echo "/usr Exceptions to OSR" >>p3
echo "Yes" >>p4
echo "$c" >>p5
echo "$z" >>p6
echo "AD.1.8.3.2.2" >>p12

#AD.1.5.9.39 
rpm -qa | grep -i smb| wc -l
if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Samba" >>p2
		echo "Samba is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.39" >>p12
	else
		echo "Network Settings" >>p1
		echo "Samba" >>p2
		echo "Samba is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.39" >>p12
fi


#AD.1.5.12.4 
str=$(rpm -qa | grep -i postfix| wc -l)
aa=`cat /etc/postfix/main.cf|grep '^myhostname'|awk -F"= " '{print $2}'`
if [ $str -ne 0 ]
then
		if [ -f /etc/postfix/main.cf ]
		then
			aa=`cat /etc/postfix/main.cf|grep '^myhostname'|awk -F"= " '{print $2}'`
			bb=$(cat /etc/postfix/main.cf | grep ^mydomain|awk -F"= " '{print $2}')
			cc=$(cat /etc/postfix/main.cf | grep ^inet_interfaces|awk -F"= " '{print $2}')
			dd=$(cat /etc/postfix/main.cf | grep ^mydestination|awk -F"= " '{print $2}')
			ee=$(cat /etc/postfix/main.cf | grep ^mynetworks_style|awk -F"= "  '{print $2}')
			ff=$(cat /etc/postfix/main.cf | grep ^default_transport|awk -F"= " '{print $2}')	
			 if [ "$aa" == "localhost" ]  && [ "$cc" == "\$myhostname, localhost" ] && [ "$bb" == "localdomain" ] && [ "$dd" == "\$myhostname, localhost.\$mydomain, localhost" ] && [ "$ee" == "host" ] && [ "$ff" == "error:outside mail is not deliverable" ]
			then 
				echo "Network Settings" >>p1
				echo "Postfix " >>p2
				echo "Postfix  is installed, configuration is correctly set" >>p3
				echo "Yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.5.12.4" >>p12
			else
				echo "Network Settings" >>p1
				echo "Postfix " >>p2
				echo "Postfix  is installed, configuration is not correctly set" >>p3
				echo "No" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AD.1.5.12.4" >>p12
			fi
		else
			echo "Network Settings" >>p1
			echo "Postfix " >>p2
			echo "/etc/postfix/main.cf file does not exists" >>p3
			echo "No" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.12.4" >>p12
		fi
else
		echo "Network Settings" >>p1
		echo "Postfix " >>p2
		echo "Postfix  is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.12.4" >>p12
	
fi

#AD.1.5.9.39 
rpm -qa | grep -i smb| wc -l
if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Samba" >>p2
		echo "Samba is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.39" >>p12
	else
		echo "Network Settings" >>p1
		echo "Samba" >>p2
		echo "Samba is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.39" >>p12
fi


#AD.1.5.9.41_AD.1.5.9.33
rpm -qa | grep -i talk| wc -l
if [ $? -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "Talk" >>p2
		echo "Talk Package is not installed " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.41_AD.1.5.9.33" >>p12
	else
		echo "Network Settings" >>p1
		echo "Talk" >>p2
		echo "Talk Package is installed, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.41_AD.1.5.9.33" >>p12
fi


#AD.1.5.9.38
str=$(systemctl status httpd.service |grep running | wc -l)
if [ $str -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "HTTP" >>p2
		echo "HTTP service is not running " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.38" >>p12
	else
		echo "Network Settings" >>p1
		echo "HTTP" >>p2
		echo "HTTP service is running, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.38" >>p12
fi


#AD.1.5.9.32
str=$(rpm -qa | grep -i squid | wc -l)
if [ $str -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "HTTP Proxy" >>p2
		echo "HTTP proxy is Disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.32" >>p12
	else
		echo "Network Settings" >>p1
		echo "HTTP Proxy" >>p2
		echo "HTTP proxy is enable, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.32" >>p12
fi

#AD.1.5.9.36
str=$(systemctl status dhcpd.service | grep -i running | wc -l)
if [ $str -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "DHCP" >>p2
		echo "DHCP Service is Disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.36" >>p12
	else
		echo "Network Settings" >>p1
		echo "DHCP" >>p2
		echo "DHCP Service is enable, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.36" >>p12
fi


#AD.1.5.9.31
str=$(rpm -qa | grep -i dovecot|wc -l)
if [ $str -eq 0 ]
then
		echo "Network Settings" >>p1
		echo "IMAP and POP" >>p2
		echo "IMAP and POP Service is Disabled " >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.31" >>p12
	else
		echo "Network Settings" >>p1
		echo "IMAP and POP" >>p2
		echo "IMAP and POP Service is enable, Manual_Check_Required" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.31" >>p12
fi

#AD.1.8.23.1 
find / -perm -1000 >>world-writable-test

for i in `cat world-writable-test`
do
	echo "Protecting Resources - mixed" >>p1
	echo "Ensure sticky bit is set on all world-writable directories" >>p2
	echo "$i" >> p3
	echo "Yes" >>p4
	echo "$c" >> p5
	echo "$z" >>p6
	echo "AD.1.8.23.1" >>p12
done

rm -rf world-writable-test

#AD.1.5.9.37
str=$(ifconfig | egrep 'ens'|cut -d_ -f1| awk '{print $1}')
ifconfig $str | egrep 'inet'|awk '{print $2}' >>local_temp
cat /etc/resolv.conf | grep 'nameserver' | awk '{print $2}' >> dns_temp
for i in `cat local_temp`
do
	for j in `cat dns_temp`
	do
		if [ $j -eq $i ]
		then
		
			echo "Network Settings" >>p1
			echo "Ensure DNS Server is not enabled" >>p2
			echo "This Server is a DNS server $i" >>p3
			echo "$c" >>p5
			echo "$z" >>p6
			echo "no" >>p4
			echo "AD.1.5.9.37" >>p12
		else
			
			echo "Network Settings" >>p1
			echo "Ensure DNS Server is not enabled" >>p2
			echo "This Server is not a DNS server $i" >>p3
			echo "$c" >>p5
			echo "$z" >>p6
			echo "yes" >>p4
			echo "AD.1.5.9.37" >>p12
		fi
	done
done
rm -rf local_temp dns_temp


#AD.1.3.0_AD.30.1.3.0_AntiVirus
sk=`/opt/ds_agent/dsa_control -r|awk '{print $5}'`
if [ "$sk"  == "OK" ]
then
			echo "AntiVirus" >>p1
			echo "AntiVirus Enabled" >>p2
			echo "AntiVirus is running" >>p3
			echo "Yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.3.0_AD.30.1.3.0" >>p12
else
			echo "AntiVirus" >>p1
			echo "AntiVirus Enabled" >>p2
			echo "AntiVirus is not running" >>p3
			echo "No" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.3.0_AD.30.1.3.0" >>p12
fi


#AD.1.1.8.3.2
cat /etc/passwd |awk -F_ '{print $4}' >> password_temp
cat /etc/group |awk -F_ '{print $3}' >> group_temp

for i in `cat group_temp`
do
	for j in `cat password_temp`
	do
		if [ $j -eq $i ]
		then
		
			echo "Password Requirements" >>p1
			echo "Ensure all groups in /etc/passwd exist in /etc/group" >>p2
			echo "Group exists in both the file /etc/passwd and /etc/group $j" >>p3
			echo "$c" >>p5
			echo "$z" >>p6
			echo "Yes" >>p4
			echo "AD.1.1.8.3.2" >>p12
#		else
			
#			echo "Password Requirements" >>p1
#			echo "Ensure all groups in /etc/passwd exist in /etc/group" >>p2
#			echo "Group doesn't exist in both the file /etc/passwd and /etc/group $j" >>p3
#			echo "$c" >>p5
#			echo "$z" >>p6
#			echo "No" >>p4
#			echo "AD.1.1.8.3.2" >>p12
		fi
	done
done
rm -rf password_temp group_temp


#AD.2.0.1.10 
if [ -f /etc/dconf/profile/gdm ]
then

	str=$(cat /etc/dconf/profile/gdm |grep -i user-db)
	str1=$(cat /etc/dconf/profile/gdm |grep -i system-db)
	str2=$(cat /etc/dconf/profile/gdm |grep -i file-db)
	if [ "$str" == "user-db_user" ] && [ "$str1" == "system-db_gdm" ] && [ "$str" == "file-db_/usr/share/gdm/greeter-dconf-defaults" ]
	then
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists in Gnome." >>p2
		echo "GDM is the GNOME Display Manager properly set" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.2.0.1.10" >>p12
	else 
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists in Gnome." >>p2
		echo "GDM is the GNOME Display Manager is not properly set" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.2.0.1.10" >>p12
	fi
else
		echo "Business Use Notice" >>p1
		echo "Business Use Notice exists in Gnome." >>p2
		echo "GDM is the GNOME Display Manager does not exist" >> p3
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.2.0.1.10" >>p12
fi



#AD.1.4.3.3.1_Audit Daemon
str=$(systemctl status auditd.service |head -3 | grep active| awk '{print $2}')

if [ $str == "active" ]
then
		echo "System Settings" >>p1
		echo "Audit Daemon" >>p2
		echo "AD.1.4.3.3.1" >>p12
		echo "Audit Daemon is running"  >> p3
		echo "Yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "System Settings" >>p1
		echo "Audit Daemon" >>p2
		echo "AD.1.4.3.3.1" >>p12
		echo "Audit Daemon service is not running" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


#AD.1.2.1.4.3
len=$(cat /etc/rsyslog.conf |grep '$FileCreateMode'|awk '{print $2}')
if [ "$len" == 0640 ]
then
	    echo "Logging" >>p1
        echo "Permission for creating file using Rsyslog" >>p2
        echo "Permission is set $len" >> p3
        echo "AD.1.2.1.4.3">>p12
		echo "yes" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
        
else
	    echo "Logging" >>p1
        echo "Permission for creating file using Rsyslog" >>p2
        echo "Permission is not set $len" >> p3        
		echo "AD.1.2.1.4.3">>p12
		echo "no" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
        
fi


#AD.1.1.4.5
len=$(cat /etc/pam.d/system-auth | grep -v '#'|grep ^auth|egrep "required|requisite"|egrep -w 'pam_unix.so'|egrep 'nullok'|wc -l)
if [ "$len" == 0 ]
then
	    echo "Password Requirementss" >>p1
        echo "Do not accept null passwords" >>p2
        echo "Nullok is not allowed" >> p3
        echo "AD.1.1.4.5">>p12
		echo "yes" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
        
else
echo "Password Requirementss" >>p1
        echo "Null Password is allowed" >>p2
        echo "Nullok is allowed need to check manually and fix" >> p3
        echo "AD.1.1.4.5">>p12
	echo "no" >>p4
        echo "$c" >> p5
        echo "$z" >>p6
        
fi




#############################################################################
#### GDPR Settings for Linux #######################

#AD.30.0.1.0_
if [ -f /etc/profile.d/IBMsinit.csh ]
then
sk=`cat /etc/profile.d/IBMsinit.csh | grep "set.*autologout=" |awk -F"=" '{print $2}'`
	if [ $sk -eq 15 ]
	then
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.csh " >>p2
		echo "OS Automatic Logoff is set in /etc/profile.d/IBMsinit.csh" >>p3
		echo "AD.30.0.1.0">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.csh " >>p2
		echo "OS Automatic Logoff is not set correct in /etc/profile.d/IBMsinit.csh" >>p3
		echo "AD.30.0.1.0">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.csh " >>p2
		echo "File /etc/profile.d/IBMsinit.csh_doesnt_exist" >>p3
		echo "AD.30.0.1.0">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
if [ -f /etc/profile.d/IBMsinit.sh ]
then
sk=`cat /etc/profile.d/IBMsinit.sh | grep "TMOUT" |awk -F"=" '{print $2}'`
	if [ $sk -eq 900 ]
	then
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.sh " >>p2
		echo "OS Automatic Logoff is set in /etc/profile.d/IBMsinit.sh" >>p3
		echo "AD.30.0.1.0">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.sh " >>p2
		echo "OS Automatic Logoff is not set correct in /etc/profile.d/IBMsinit.sh" >>p3
		echo "AD.30.0.1.0">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.sh " >>p2
		echo "File /etc/profile.d/IBMsinit.sh_doesnt_exist" >>p3
		echo "AD.30.0.1.0">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.30.0.1.1_IBMsinit.sh
if [ -f /etc/profile.d/IBMsinit.sh ]
then
cat /etc/profile  |grep '.*/etc/profile.d/IBMsinit.sh'
if [ $? -eq 0 ]
then
		echo "Password Requirements" >>p1
        echo "/etc/profile " >>p2
		echo "/etc/profile.d/IBMsinit.sh_is_enabled" >>p3
		echo "AD.30.0.1.1">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Password Requirements" >>p1
        echo "/etc/profile " >>p2
		echo "/etc/profile.d/IBMsinit.sh_is_not_enabled" >>p3
		echo "AD.30.0.1.1">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
else
		echo "Password Requirements" >>p1
        echo "/etc/profile " >>p2
		echo "File /etc/profile.d/IBMsinit.sh not exists" >>p3
		echo "AD.30.0.1.1">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.30.0.1.2_IBMsinit.csh
if [ -f /etc/profile.d/IBMsinit.csh ]
then
cat /etc/csh.login | grep 'source.*/etc/profile.d/IBMsinit.csh'
if [ $? -eq 0 ]
then
		echo "Password Requirements" >>p1
                echo "/etc/csh.login " >>p2
		echo "/etc/profile.d/IBMsinit.csh_is_enabled" >>p3
		echo "AD.30.0.1.2">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
else
		echo "Password Requirements" >>p1
                echo "/etc/csh.login" >>p2
		echo "/etc/profile.d/IBMsinit.csh_is_not_enabled" >>p3
		echo "AD.30.0.1.2">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
else
		echo "Password Requirements" >>p1
                echo "/etc/csh.login" >>p2
		echo "/etc/profile.d/IBMsinit.csh file not exists" >>p3
		echo "AD.30.0.1.2">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.30.0.1.3_Activity Time out
if [ -f /etc/profile.d/IBMsinit.csh ]
then
	sk1=`cat /etc/profile.d/IBMsinit.sh | grep "TMOUT=" |awk -F"=" '{print $2}'`
#	sl=`cat /etc/profile.d/IBMsinit.sh | grep "export.*TMOUT" |wc -l`
	if [ $sk1 -eq 900 ]
	then
			echo "Password Requirements" >>p1
		    echo "/etc/profile.d/IBMsinit.sh" >>p2
			echo "OS Automatic Logoff is set correct in /etc/profile.d/IBMsinit.sh" >>p3
			echo "AD.30.0.1.3">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
	else
			echo "Password Requirements" >>p1
		    echo "/etc/profile.d/IBMsinit.sh" >>p2
			echo "OS Automatic Logoff is not set correct in /etc/profile.d/IBMsinit.sh" >>p3
			echo "AD.30.0.1.3">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
	fi
else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.sh " >>p2
		echo "File /etc/profile.d/IBMsinit.sh_doesnt_exist" >>p3
		echo "AD.30.0.1.3">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi

#AD.30.0.1.4_Screen timeut inactivity
if [ -f /etc/profile.d/IBMsinit.csh ]
then
sk=`cat /etc/profile.d/IBMsinit.csh | grep "set.*autologout=" |awk -F"=" '{print $2}'`
	if [ $sk -eq 15 ]
	then
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.csh " >>p2
		echo "OS Automatic Logoff is set in /etc/profile.d/IBMsinit.csh" >>p3
		echo "AD.30.0.1.4">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.csh " >>p2
		echo "OS Automatic Logoff is not set correct in /etc/profile.d/IBMsinit.csh" >>p3
		echo "AD.30.0.1.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
else
		echo "Password Requirements" >>p1
        echo "/etc/profile.d/IBMsinit.csh " >>p2
		echo "File /etc/profile.d/IBMsinit.csh_doesnt_exist" >>p3
		echo "AD.30.0.1.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi



#AD.30.0.1.6
echo "/bin/csh, /bin/tcsh, /bin/sh, /bin/ksh, /bin/bash,/bin/sh, /bin/false, /sbin/nologin, /usr/bin/sh,/usr/bin/bash,/usr/sbin/nologin, /bin/ksh93, /usr/bin/ksh, /usr/bin/rksh, /usr/bin/ksh93" >shell_file

for i in `cat /etc/passwd |egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F"_" '{print $1}'`
do
sk=`getent passwd $i | awk -F"_" '{print $7}'`
sp=`cat shell_file |grep $sk`
	if [ $? -eq 0 ]
	then
		echo "Password Requirements" >>p1
                echo "OS Automatic Logoff Login shell which supports time out" >>p2
		echo "Valid shell $sk is set for user $i" >>p3
		echo "AD.30.0.1.6">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
                echo "OS Automatic Logoff Login shell which supports time out" >>p2
		echo "Invalid shell $sk is set for user $i" >>p3
		echo "AD.30.0.1.6">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
done
rm -rf shell_file


#AD.30.0.1.7
echo "/bin/sh, /bin/bash, /sbin/nologin, /usr/bin/sh, /usr/bin/bash, /usr/sbin/nologin, /bin/tcsh, /bin/csh, /bin/ksh, /bin/rksh, /bin/false, /bin/ksh93, /usr/bin/ksh, /usr/bin/rksh, /usr/bin/ksh93" >shell_file

for i in `cat /etc/passwd |egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F"_" '{print $1}'`
do
sk=`getent passwd $i | awk -F"_" '{print $7}'`
sp=`cat shell_file |grep $sk`
	if [ $? -eq 0 ]
	then
		echo "Password Requirements" >>p1
        echo "OS Automatic Logoff Login shell which supports time out" >>p2
		echo "Valid shell $sk is set for user $i" >>p3
		echo "AD.30.0.1.7">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	else
		echo "Password Requirements" >>p1
        echo "OS Automatic Logoff Login shell which supports time out" >>p2
		echo "Invalid shell $sk is set for user $i" >>p3
		echo "AD.30.0.1.7">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
done
rm -rf shell_file

#AD.1.4.3.1.1
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
	st=$(sestatus |head -n 1|awk '{print $3}')
	if [ $? == "disabled"
	then
		echo "System-Settings" >>p1
		echo "Ensure Selinux is not installed" >>p2
		echo "Selinux disabled" >>p3	
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.3.1.1" >>p12
	else
		echo "System-Settings" >>p1
		echo "Ensure Selinux is installed" >>p2
		echo "Selinux enabled" >>p3
		echo "Yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.4.3.1.1" >>p12	
	fi
else
	echo "System-Settings" >>p1
	echo "Not a RHEL" >>p2
	echo "Manual check required" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.4.3.1.1" >>p12		
fi


################################################################################################
#AD.30.0.2.1,AD.30.0.2.2,ZY.1.2.2
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" == "Red" ]
then
	if [ -f /etc/rsyslog.conf ]
	then
		sk=`cat /etc/rsyslog.conf |grep -v '^#' | awk '{print $2}' |wc -l`
		
		if [ $sk -gt 0 ]
		then
			echo "Logging" >>p1
		    echo "Logging in external system" >>p2
			echo "/etc/rsyslog.conf is properly set" >>p3
			echo "AD.30.0.2.1_AD.30.0.2.2_ZY.1.2.2">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Logging" >>p1
		    echo "Logging in external system" >>p2
			echo "/etc/rsyslog.conf is not properly set" >>p3
			echo "AD.30.0.2.1_AD.30.0.2.2_ZY.1.2.2">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
			echo "Logging" >>p1
		    echo "Logging in external system" >>p2
			echo "File /etc/rsyslog.conf doesnt_exist" >>p3
			echo "AD.30.0.2.1_AD.30.0.2.2_ZY.1.2.2">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
	fi
else
		echo "Logging" >>p1
        echo "Logging in external system" >>p2
		echo "Not Redhat OS" >>p3
		echo "AD.30.0.2.1_AD.30.0.2.2_ZY.1.2.2">>p12
		echo "Not_Applicable" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi


################################################################################################
#AD.1.5.9.24.4.1_AD.1.5.9.24.4.2
if [ -f /etc/vsftpd/vsftpd.conf ]
then
	str=$(stat -c "%a %n" /etc/vsftpd/vsftpd.conf |awk '{print $1}')
	if [ "$str" == "600" ]
	then
		a=$(cat /etc/vsftpd/vsftpd.conf| grep ^ssl_enable|awk -F"=" '{print $2}')
		b=$(cat /etc/vsftpd/vsftpd.conf| grep ^allow_anon_ssl|awk -F"=" '{print $2}')
		cc=$(cat /etc/vsftpd/vsftpd.conf| grep ^force_local_data_ssl|awk -F"=" '{print $2}')
		d=$(cat /etc/vsftpd/vsftpd.conf| grep ^force_local_logins_ssl|awk -F"=" '{print $2}')
		e=$(cat /etc/vsftpd/vsftpd.conf| grep ^ssl_sslv2|awk -F"=" '{print $2}')
		f=$(cat /etc/vsftpd/vsftpd.conf| grep ^ssl_sslv3|awk -F"=" '{print $2}')
		g=$(cat /etc/vsftpd/vsftpd.conf| grep ^ssl_tlsv1|awk -F"=" '{print $2}')
		h=$(cat /etc/vsftpd/vsftpd.conf| grep ^ssl_tlsv1_1|awk -F"=" '{print $2}')
		i=$(cat /etc/vsftpd/vsftpd.conf| grep ^ssl_tlsv1_2|awk -F"=" '{print $2}')
		j=$(cat /etc/vsftpd/vsftpd.conf| grep ^rsa_cert_file|awk -F"=" '{print $2}')
		k=$(cat /etc/vsftpd/vsftpd.conf| grep ^rsa_private_key_file|awk -F"=" '{print $2}')
		
		if [ $a == "YES" ] || [ $b == "YES" ] || [ $cc == "YES" ] || [ $d == "YES" ] || [ $e == "NO" ] || [ $f == "NO" ] || [ $g == "NO" ] || [ $h == "NO" ] || [ $i == "YES" ] || [ $j == "/etc/pki/tls/certs/$pemFileName" ] || [ $k == "/etc/pki/tls/private/$keyFileName" ]
		then
			echo "Network Settings" >>p1
			echo "vsftpd.conf-permission and SSL check" >>p2
			echo "vsftpd.conf-permission and SSL check is correctly set" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.9.24.4.1_AD.1.5.9.24.4.2" >>p12
		else
			echo "Network Settings" >>p1
			echo "vsftpd.conf-permission and SSL check" >>p2
			echo "/vsftpd.conf-permission and SSL check is incorrect" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AD.1.5.9.24.4.1_AD.1.5.9.24.4.2" >>p12
		fi
	else
		echo "Networking Settings" >>p1
		echo "VSFTP Status" >>p2
		echo "VSFTP is not installed" >>p3
		echo "No" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.5.9.24.4.1_AD.1.5.9.24.4.2" >>p12
	fi
else
	echo "Networking Settings" >>p1
	echo "VSFTP Status" >>p2
	echo "VSFTP is disbaled" >>p3
	echo "No" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "AD.1.5.9.24.4.1_AD.1.5.9.24.4.2" >>p12
fi
#############################################################################################
#AD.1.8.14.2
str=$(find /var/spool/cron/root -type f -perm /o+w \! -perm -1000| wc -l)

if [ -f /var/spool/cron/root ]
then
	if [ $str -eq 0 ] 
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/root-permissions" >>p2
		echo "/var/spool/cron/root-Others permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.14.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/root-permissions" >>p2
		echo "/var/spool/cron/root-Others permission is not valid for $str entries" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.14.2" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/root-permissions" >>p2
		echo "/var/spool/cron/root File-directory does not exists" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.14.2" >>p12
fi

#AD.1.8.14.3
str=$(find /var/spool/cron/root -type f -perm /g+w \! -perm -1000| wc -l)

if [ -f /var/spool/cron/root ]
then
	if [ $str -eq 0 ] 
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/root-permissions" >>p2
		echo "/var/spool/cron/root-Group permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.14.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/root-permissions" >>p2
		echo "/var/spool/cron/root-Group permission is not valid for $str entries" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.14.3" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/spool/cron/root-permissions" >>p2
		echo "/var/spool/cron/root File-directory does not exists" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.14.3" >>p12
fi
#############################################################################################
#AD.1.8.15.2
str=$(find /etc/crontab -type f -perm /o+w \! -perm -1000| wc -l)
str1=$(find /etc/crontab -type d -perm /o+w \! -perm -1000| wc -l)

if [ -f /etc/crontab ]
then
	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permissions" >>p2
		echo "/etc/crontab-Others permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.15.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permissions" >>p2
		echo "/etc/crontab-Others permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.15.2" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permissions" >>p2
		echo "/etc/crontab directory does not exists" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.15.2" >>p12
fi

#AD.1.8.15.3
str=$(find /etc/crontab -type f -perm /g+w \! -perm -1000| wc -l)
str1=$(find /etc/crontab -type d -perm /g+w \! -perm -1000| wc -l)

if [ -f /etc/crontab ]
then
	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permissions" >>p2
		echo "/etc/crontab-Group permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.15.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permissions" >>p2
		echo "/etc/crontab-Group permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.15.3" >>p12
	fi
else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/crontab-permissions" >>p2
		echo "/etc/crontab directory does not exists" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.15.3" >>p12
fi
##############################################################################################
#AD.1.8.20.2
str=$(find /etc/cron.d/ -type f -perm /o+w \! -perm -1000| wc -l)
str1=$(find /etc/cron.d/ -type d -perm /o+w \! -perm -1000| wc -l)


	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permissions" >>p2
		echo "/etc/cron.d-Others permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.20.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permissions" >>p2
		echo "/etc/cron.d-Others permission is not valid for $str entries" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.20.2" >>p12
	fi




#AD.1.8.20.3
str=$(find /etc/cron.d/ -type f -perm /g+w \! -perm -1000| wc -l)
str1=$(find /etc/cron.d/ -type d -perm /g+w \! -perm -1000| wc -l)


	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permissions" >>p2
		echo "/etc/cron.d-Group permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.20.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/etc/cron.d-permissions" >>p2
		echo "/etc/cron.d-Group permission is not valid for $str entries" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.20.3" >>p12
	fi
#############################################################################################
#AD.1.8.22.1
str=$(find /opt -type f -perm /o+w \! -perm -1000| wc -l)
str1=$(find /opt -type f -perm /o+x \! -perm -1000| wc -l)
find /opt -type f -perm /o+w \! -perm -1000 > wother-221
find /opt -type f -perm /o+x \! -perm -1000 > xother-221
for i in `cat wother-221`
do
   ls -l $i >> 221-wother
done
for i in `cat xother-221`
do
   ls -l $i >> 221-xother
done
	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/opt-permissions" >>p2
		echo "/opt-Others permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.1" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/opt-permissions" >>p2
		echo "/opt-Others permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.1" >>p12
		
	fi

rm -rf wother-221 xother-221


#AD.1.8.22.2
str=$(find /var -type f -perm /g+w \! -perm -1000| wc -l)
str1=$(find /var -type f -perm /g+x \! -perm -1000| wc -l)
find /var -type f -perm /g+w \! -perm -1000 > wother-222
find /var -type f -perm /g+x \! -perm -1000 > xother-222
for i in `cat wother-222`
do
   ls -l $i >> 222-wother
done
for i in `cat xother-222`
do
   ls -l $i >> 222-xother
done
	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-permissions" >>p2
		echo "/var-Group permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var-permissions" >>p2
		echo "/var-Group permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.2" >>p12
	fi

rm -rf wother-222 xother-222

#############################################################################################
#AD.1.8.22.3
str=$(find /usr/local  -type f -perm /o+w \! -perm -1000| wc -l)
str1=$(find /usr/local  -type f -perm /o+x \! -perm -1000| wc -l)
find /usr/local -type f -perm /o+w \! -perm -1000 > wother-223
find /usr/local -type f -perm /o+x \! -perm -1000 > xother-223
for i in `cat wother-223`
do
   ls -l $i >> 223-wother
done
for i in `cat xother-223`
do
   ls -l $i >> 223-xother
done

	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr/local-permissions" >>p2
		echo "/usr/local-Others permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/usr/local-permissions" >>p2
		echo "/usr/local-Others permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.3" >>p12
	fi

rm -rf wother-223 xother-223


#AD.1.8.22.4
str=$(find /tmp -type f -perm /g+w \! -perm -1000| wc -l)
str1=$(find /tmp -type f -perm /g+x \! -perm -1000| wc -l)
find /tmp -type f -perm /g+w \! -perm -1000 > wother-224
find /tmp -type f -perm /g+x \! -perm -1000 > xother-224
for i in `cat wother-224`
do
   ls -l $i >> 224-wother
done
for i in `cat xother-224`
do
   ls -l $i >> 224-xother
done 

	if [ $str -eq 0 ] && [ $str1 -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "/tmp-permissions" >>p2
		echo "/tmp-Group permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.4" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/tmp-permissions" >>p2
		echo "/tmp-Group permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.22.4" >>p12
	fi

rm -rf wother-224 xother-224
#############################################################################################
#AD.1.8.18.2
echo "/etc/rc.d/rc0.d,/etc/rc.d/rc1.d,/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d,/etc/rc.d/rc6.d,/etc/rc.d/rcS.d" > temp
tr "," "\n" < temp > temp1

for i in `cat temp1`
do
	str=$(find $i -type d -perm /o+w \! -perm -1000| wc -l)
	if [ $str -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "$i-permissions" >>p2
		echo "$i-Others permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.18.2" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "$i-permissions" >>p2
		echo "$i-Others permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.18.2" >>p12
	fi

done
rm -rf temp temp1



#AD.1.8.18.3
echo "/etc/rc.d/rc0.d,/etc/rc.d/rc1.d,/etc/rc.d/rc2.d,/etc/rc.d/rc3.d,/etc/rc.d/rc4.d,/etc/rc.d/rc5.d,/etc/rc.d/rc6.d,/etc/rc.d/rcS.d" > temp
tr "," "\n" < temp > temp1

for i in `cat temp1`
do

	str=$(find $i -type f -perm /g+w \! -perm -1000| wc -l)
	if [ $str -eq 0 ]
	then
		echo "Protecting Resources - OSRs" >>p1
		echo "$i-permissions" >>p2
		echo "$i-Group permission is valid" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.18.3" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "$i-permissions" >>p2
		echo "$i-Group permission is not valid" >> p3
		echo "No" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AD.1.8.18.3" >>p12
	fi

done
rm -rf temp temp1

#############################################################################################

#AD.1.8.8
str=$(stat -c "%a %n" /var/log/secure|awk '{print $1}')
if [ "$str" == "600" ] || [ "$str" == "0" ] || [ "$str" == "740" ]
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/secure-permission" >>p2
		echo "/var/log/secure-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.8" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/secure-permission" >>p2
		echo "/var/log/secure-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.8" >>p12
fi
###############################################################################################
#AD.1.8.9
str=$(stat -c "%a %n" /tmp|awk '{print $1}')
if [ "$str" == "1777" ] 
then
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/secure-permission" >>p2
		echo "/var/log/secure-permission-is-correctly-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.9" >>p12
	else
		echo "Protecting Resources - OSRs" >>p1
		echo "/var/log/secure-permission" >>p2
		echo "/var/log/secure-permission-is-incorrect" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AD.1.8.9" >>p12
fi

############################################################################################
#AD.1.1.1.3_Thrid field of /etc/shadow
cat /etc/passwd | egrep -v "/sbin/nologin|sync|shutdown|halt|/bin/false" | awk -F"_" '{print $1}' >temp_passwd
dd=$(expr $(date +%s) / 86400)

for i in `cat temp_passwd`
do
	LP=$(grep $i /etc/shadow | awk -F"_" '{print $3}')
				if [ $LP -lt $dd ]
				then
        			echo "Password Requirements" >>p1
        			echo "Last Password Changed" >>p2
					echo "Third field of /etc/shadow is set as past date for id $i" >>p3
					echo "AD.1.1.1.3" >>p12
					echo "Yes" >>p4
					echo "$c" >> p5
					echo "$z" >>p6
				else
        			echo "Password Requirements" >>p1
        			echo "Last Password Change" >>p2
					echo "Third field of /etc/shadow is not valid date for id $i" >>p3
					echo "No" >>p4
					echo "AD.1.1.1.3" >>p12
					echo "$c" >> p5
					echo "$z" >>p6
        		fi
done
rm -rf temp_passwd



#################################################################################################

######### SSH HC Script ####################

#################################################################################################



#AV.1.4.1
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
BC=`which bc`
if (( $($BC <<< "$szk<=3.7") > 0 ))
then
	sk=`cat /etc/ssh/sshd_config | grep -i "^KeepAlive" | awk '{print $2}' |uniq |wc -l`
	if [ $sk -gt 0 ]
	then
	szl=`cat /etc/ssh/sshd_config | grep -i "^KeepAlive" | awk '{print $2}' |uniq`
	if [ "$szl" == "yes" ]
	then
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p3
		echo "KeepAlive_$szl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
	else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "KeepAlive_$szl" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
	fi
	else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "KeepAlive value is set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
	fi
else
		echo "SystemSettings" >>p1
		echo "KeepAlive" >>p2
		echo "Applicable-only-for-openssh-versions-3.7-or-less" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.1" >>p12
fi
#############################################################################################
#AV.1.9.1

  
	szl=`cat /etc/ssh/sshd_config | grep -i "^PermitUserEnvironment" | awk '{print $2}' |uniq`
	if [ $szl == $PERMITUSERENVIRONMENT ]
	then
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "PermitUserEnvironment" >>p2
		echo "PermitUserEnvironment is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.1" >>p12
	fi
#######################################################################################################


#AV.1.9.3
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`
if ( $szk >= "3.9" )
then
	szl=`cat /etc/ssh/sshd_config | grep -i ^AcceptEnv | egrep 'TERM|PATH|HOME| MAIL| SHELL| LOGNAME| USER| USERNAME| _RLD*| DYLD_*| LD_*| LDR_*| LIBPATH| SHLIB_PATH'`
	if [ $? -eq 0 ]
	then
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are not correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.3" >>p12
	else
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.3" >>p12
	fi
else
		echo "Protecting Resources - User Resources" >>p1
		echo "User Environment variables are correctly set" >>p3
		echo "AcceptEnv" >>p2
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.9.3" >>p12
fi
###########################################################################################################
#AV.1.4.2
   sk=`cat /etc/ssh/sshd_config | grep -i "^TCPKeepAlive" |uniq |wc -l`
   if [ $sk -gt 0 ]
   then
		szl=`cat /etc/ssh/sshd_config | grep -i "^TCPKeepAlive" | awk '{print $2}' |uniq`
		if [ "$szl" == "$TCPKEEPALIVE" ]
		then
			echo "System Settings" >>p1
			echo "TCPKeepAlive" >>p2
			echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.4.2" >>p12
		else
			echo "System Settings" >>p1
			echo "TCPKeepAlive" >>p2
			echo "TCPKeepAlive Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.4.2" >>p12
		fi
	else
		echo "System Settings" >>p1
		echo "TCPKeepAlive" >>p2
		echo "TCPKeepAlive Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.2" >>p12
	fi
#################################################################################################
#AV.1.4.4
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" != "openssh" ]
then
	sk=`cat /etc/ssh/sshd_config | grep -i "^MaxConnections" |uniq |wc -l`
	if [ $sk -gt 0 ]
	then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxConnections" | awk '{print $2}' |uniq | awk 'FNR  == 1'`
	if [ "$szl" <= "100" ]
	then
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "$szl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
	fi
	else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Value-is-set" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
	fi
else
		echo "System Settings" >>p1
		echo "MaxConnections" >>p2
		echo "Not Applicable-for-OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.4" >>p12
fi


#AV.1.4.5
sk=`cat /etc/ssh/sshd_config | grep -i "^MaxStartups" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxStartups" | awk '{print $2}' |uniq`
	if [ $szl  -le $MAXSTARTUPS ] || [ "$szl" == "10_30_100" ]
	then
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#MaxStartups" | awk '{print $2}' |uniq`
	if [ $szl  -le $MAXSTARTUPS ] || [ "$szl" == "10_30_100" ]
	then
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxStartups" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.5" >>p12
	fi
fi

#AV.1.4.8_System Settings
sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7,8,9,10,11`
szk=`echo $sz | awk -F"-" '{print $2}'`

if ( $szk >= "3.9" )
then
  sk=`cat /etc/ssh/sshd_config | grep -i "^MaxAuthTries" |uniq |wc -l`
  if [ $sk -gt 0 ]
  then
	szl=`cat /etc/ssh/sshd_config | grep -i "^MaxAuthTries" | awk '{print $2}' |uniq`
	if [ $szl -le $MAXAUTHTRIES ]
	then
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	fi
  else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12
	fi
else
		echo "System Settings" >>p1
		echo "MaxAuthTries" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.8" >>p12


fi
#########################################################################################################
#AV.1.4.14

sz=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] | cut -c1,2,3,4,5,6,7`
if [ "$sz" != "openssh" ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^AuthKbdInt.Retries" | awk '{print $2}' |uniq`
	if [ "$szl" <= "5" ]
	then
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.14" >>p12
	else
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.14" >>p12
	fi
else
		echo "System Settings" >>p1
		echo "AuthKbdInt.Retries" >>p2
		echo "Not Applicable for OpenSSH" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.14" >>p12
fi


#AV.1.4.3
sk=`cat /etc/ssh/sshd_config | grep -i "^LoginGraceTime" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^LoginGraceTime" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$LOGINGRACETIME" ] || [ "$szl" == "2m" ]
	then
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	else
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#LoginGraceTime" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$LOGINGRACETIME" ] || [ "$szl" == "2m" ]
	then
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	else
		echo "System Settings" >>p1
		echo "LoginGraceTime" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.4.3" >>p12
	fi
fi

#AV.1.5.1
sshval=`rpm -qa |grep -i ssh |grep -i openssh-[0-9].[0-9] |cut -c1,2,3,4,5,6,7`
if [ "$sshval" != "openssh" ]
then
sk=`cat /etc/ssh/sshd_config | grep -i "^KeyRegenerationInterval" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szl=`cat /etc/ssh/sshd_config | grep -i "^KeyRegenerationInterval" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$KEYREGENERATIONINTERVAL" ] || [ "$szl" == "1h" ]
	then
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
        echo "$ipAddress" >>en2
        echo "$osName" >>en3
		echo "$timestamp" >>en4
		echo "AV.1.5.1" >>p12
	else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
	    echo "$fqdn" >>en1
        echo "$ipAddress" >>en2
        echo "$osName" >>en3
		echo "$timestamp" >>en4
		echo "AV.1.5.1" >>p12
	fi
else
	szl=`cat /etc/ssh/sshd_config | grep -i "^#KeyRegenerationInterval" | awk '{print $2}' |uniq`
	if [ "$szl" -le "$KEYREGENERATIONINTERVAL" ] || [ "$szl" == "1h" ]
	then
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
		echo "$timestamp" >>en4
	else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
		echo "$timestamp" >>en4
	fi
fi
else
		echo "System Settings" >>p1
		echo "KeyRegenerationInterval" >>p2
		echo "This is not applicable for SSH protocol version 2 for openssh" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.1" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
		echo "$timestamp" >>en4
fi

#AV.1.5.2
sk=`cat /etc/ssh/sshd_config | grep -i "^protocol" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	sz=`grep -i ^protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
	if [ "$sz" == "2" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ] 
	then
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Value is set as $sz in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
		    echo "$timestamp" >>en4			
	else
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "value-should-be-2(or)1,2(or)2,1 in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
			echo "$timestamp" >>en4	
	fi
else
	sz=`grep -i ^#protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
	if [ "$sz" == "2" ] || [ "$sz" == "1,2" ] || [ "$sz" == "2,1" ] 
	then
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Value is set as $sz in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
			echo "$timestamp" >>en4
	else
		echo "Network Settingss" >>p1
		echo "SSH-protocol" >>p2
		echo "Protocol is not set in /etc/ssh/sshd_config" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.5.2" >>p12
    		echo "$fqdn" >>en1
            echo "$ipAddress" >>en2
            echo "$osName" >>en3
		    echo "$timestamp" >>en4
	fi
fi



#AV.2.1.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^Protocol" |uniq |wc -l`
if [ $sk -gt 0 ]
then
  sz=`grep -i ^Protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
  if [ "$sz" == "1" ] || [ "$sz" == "1.2" ] || [ "$sz" == "2.1" ] 
  then
	szl=`cat /etc/ssh/sshd_config | grep -i "^ServerKeyBits" | awk '{print $2}'`
	if [ $szl -ge 1024 ]
	then	
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits-value-is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits value must be greater than or equal to 1024" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	fi
  else

		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "Not applicable as the SSH protocol version 1 is not enabled" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
  fi		
else
  sz=`grep -i ^#protocol /etc/ssh/sshd_config | awk 'FNR == 1 {print $2}'` 
  if [ "$sz" == "1" ] || [ "$sz" == "1.2" ] || [ "$sz" == "2.1" ] 
  then
	szl=`cat /etc/ssh/sshd_config | grep -i "^ServerKeyBits" | awk '{print $2}'`
	if [ $szl -ge 1024 ]
	then	
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits-value-is set as \"$szl\" in /etc/ssh/sshd_config" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	else
		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "ServerKeyBits value must be greater than or equal to 1024" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
	fi
  else

		echo "Encryption" >>p1
		echo "Data Transmission" >>p2
		echo "Not applicable as the SSH protocol version 1 is not enabled" >>p3
		echo "Not_Applicable" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.2.1.1.1" >>p12
  fi		

fi

#AV.1.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PermitEmptyPasswords" |uniq |wc -l`
if [ $sk -gt 0 ]
then
  sz=`cat /etc/ssh/sshd_config | grep -i "^PermitEmptyPasswords" | awk '{print $2}' |uniq`
  if [ "$sz" == "$PERMITEMPTYPASSWORDS" ]
  then
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "PermitEmptyPasswords is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  else
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "Value-is-not-set" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  fi
else
  sz=`cat /etc/ssh/sshd_config | grep -i "^#PermitEmptyPasswords" | awk '{print $2}' |uniq`
  if [ "$sz" == "$PERMITEMPTYPASSWORDS" ]
  then
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "PermitEmptyPasswords is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  else
		echo "Password Requirementss" >>p1
        	echo "PermitEmptyPasswords" >>p2
		echo "Value-is-not-set" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.1.1" >>p12
  fi
fi

#AV.1.7.1.1
sz=`cat /etc/ssh/sshd_config | grep -i "^PermitRootLogin" | awk '{print $2}' |uniq`
if [ "$sz" == "$PERMITROOTLOGIN" ]
then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "PermitRootLogin" >>p2
		echo "PermitRootLogin is set as \"$sz\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.1.1" >>p12
else
		echo "Password Requirementss" >>p1
        	echo "PermitRootLogin" >>p2
		echo "PermitRootLogin is incorrectly set as \"$sz\" in /etc/ssh/sshd_config" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.1.1" >>p12
fi

#AV.1.2.1.2
sk=`cat /etc/ssh/sshd_config | grep -i "^LogLevel" |uniq |wc -l`
if [ $sk -gt 0 ]
then
  sk=`cat /etc/ssh/sshd_config | grep -i "^LogLevel" | awk '{print $2}' |uniq`
  if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ]
  then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2" >>p12
  else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-should-be-set-as-INFO" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2" >>p12
  fi
else
  sk=`cat /etc/ssh/sshd_config | grep -i "^#LogLevel" | awk '{print $2}' |uniq`
  if [ "$sk" == "INFO" ] || [ "$sk" == "DEBUG" ]
  then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-set-as \"$sk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2" >>p12
  else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "LogLevel-should-be-set-as-INFO" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.2" >>p12
  fi
fi
##################################################################################################
#AV.1.2.1.3
sks=`cat /etc/ssh/sshd_config | grep -i "^#LogLevel" |uniq |wc -l`
if [ $sks -gt 0 ]
then
	ssk=$(stat -c "%U %n" /var/log|awk '{print $1}')
	if [ "$ssk" == "root" ]
	then
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "Log files are readable by $ssk " >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.3" >>p12
  	else
		echo "Logging" >>p1
        	echo "LogLevel" >>p2
		echo "Logfiles are readable by $ssk" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.2.1.3" >>p12
	fi
fi

#AV.1.5.5
sk=`cat /etc/ssh/sshd_config | grep -i "^GatewayPorts" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	sz=`cat /etc/ssh/sshd_config | grep -i "^GatewayPorts" | awk '{print $2}' |uniq`
	if [ "$sz" == "$GATEWAYPORTS" ]
	then
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "GatewayPorts is set as \"$sz\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	else
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	fi
else
	sz=`cat /etc/ssh/sshd_config | grep -i "^#GatewayPorts" | awk '{print $2}' |uniq`
	if [ "$sz" == "$GATEWAYPORTS" ]
	then
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "GatewayPorts is set as \"$sz\" in /etc/ssh/sshd_config" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	else
			echo "Network Settingss" >>p1
			echo "GatewayPorts" >>p2
			echo "Value-is-not-set in /etc/ssh/sshd_config" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "AV.1.5.5" >>p12
	fi
fi


#AV.1.7.3.2
if [ -f /etc/hosts.equiv ]
then
	sk=`cat /etc/hosts.equiv |wc -l`
	if [ $sk -gt 0 ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv-exist and entries found. Please check the entry  in file and remediate it as per techspec" >> p3
		echo "no" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.2" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv-exist and but no entry found" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.2" >>p12
	fi
else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/hosts.equiv not exist" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.2" >>p12
fi

#AV.1.7.3.3
if [ -f /etc/hosts.equiv ]
then
	if [ -f /etc/shosts.equiv ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/shosts.equiv-exist" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.3" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "File /etc/shosts.equiv must exist as file /etc/hosts.equiv is in use" >> p3
		echo "no" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.3" >>p12
	fi
else
		echo "IdentifyandAuthenticateUsers" >>p1
        	echo "Host-Based Authentication" >>p2
		echo "Host based authentication is disabled" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "AV.1.7.3.3" >>p12
fi

#AV.1.9.2
sk=`cat /etc/ssh/sshd_config | grep -i "^StrictModes" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szk=`cat /etc/ssh/sshd_config | grep "^StrictModes" | awk '{print $2}' |uniq`
	if [ "$szk" == "$STRICTMODES" ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "StrictModes is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#StrictModes" | awk '{print $2}' |uniq`
	if [ "$szk" == "$STRICTMODES" ]
	then
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "StrictModes is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	else
		echo "IdentifyandAuthenticateUsers" >>p1
		echo "StrictModes" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.1.9.2" >>p12
	fi
fi

#AV.2.0.1.1
sk=`cat /etc/ssh/sshd_config | grep -i "^PrintMotd" |uniq |wc -l`
if [ $sk -gt 0 ]
then
	szk=`cat /etc/ssh/sshd_config | grep "^PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ]
	then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	fi
else
	szk=`cat /etc/ssh/sshd_config | grep "^#PrintMotd" | awk '{print $2}' |uniq`
	if [ "$szk" == "$PRINTMOTD" ]
	then
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "PrintMotd is set as \"$szk\" in /etc/ssh/sshd_config" >> p3
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	else
		echo "Business Use Notice " >>p1
		echo "PrintMotd" >>p2
		echo "Value-is-not-set in /etc/ssh/sshd_config" >> p3
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
		echo "AV.2.0.1.1" >>p12
	fi
fi
#############################################################################################
#AV.1.8.2.1
uu=`ls -ld /bin/openssl |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /usr/bin/openssl |awk '{print $4}'`
ggg=`id -g $gg`

rr=`ls -ld /bin/openssl|cut -c8`
xx=`ls -ld /bin/openssl|cut -c10`


if [ -f /bin/openssl ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "/usr/openssl" >>p2
	echo "/usr/openssl does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.1" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
###########################################################################################
#AV.1.8.2.2
uu=`ls -ld /bin/scp |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/scp |awk '{print $4}'`
ggg=`id -g $gg`

rr=`ls -ld /bin/scp|cut -c8`
xx=`ls -ld /bin/scp|cut -c10`
i=/bin/scp

if [ -f /bin/scp ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.2" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
####################################################################################
#AV.1.8.2.3
uu=`ls -ld /bin/scp2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/scp2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/scp2
rr=`ls -ld /bin/scp2|cut -c8`
xx=`ls -ld /bin/scp2|cut -c10`


if [ -f /bin/scp2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.3" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
###########################################################################################
#AV.1.8.2.4
uu=`ls -ld /bin/sftp |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/sftp |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/sftp
rr=`ls -ld /bin/sftp|cut -c8`
xx=`ls -ld /bin/sftp|cut -c10`


if [ -f /bin/sftp ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.4" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
######################################################################################################
#AV.1.8.2.5
uu=`ls -ld /bin/sftp2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/sftp2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/sftp2
rr=`ls -ld /bin/sftp2|cut -c8`
xx=`ls -ld /bin/sftp2|cut -c10`


if [ -f /bin/sftp2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.5" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#################################################################################################
#AV.1.8.2.6
uu=`ls -ld /bin/sftp-server |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/sftp-server |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/sftp-server
rr=`ls -ld /bin/sftp-server|cut -c8`
xx=`ls -ld /bin/sftp-server|cut -c10`


if [ -f /bin/sftp-server ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.6" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
####################################################################################################
#AV.1.8.2.7
uu=`ls -ld /bin/sftp-server2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/sftp-server2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/sftp-server2
rr=`ls -ld /bin/sftp-server2|cut -c8`
xx=`ls -ld /bin/sftp-server2|cut -c10`


if [ -f /bin/sftp-server2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.7" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################
#AV.1.8.2.8
uu=`ls -ld /bin/slogin |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/slogin |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/slogin
rr=`ls -ld /bin/slogin|cut -c8`
xx=`ls -ld /bin/slogin|cut -c10`


if [ -f /bin/slogin ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.8" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#########################################################################################################
#AV.1.8.2.9
uu=`ls -ld /bin/ssh |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh
rr=`ls -ld /bin/ssh|cut -c8`
xx=`ls -ld /bin/ssh|cut -c10`


if [ -f /bin/ssh ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.9" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
###################################################################################################
#AV.1.8.2.10
uu=`ls -ld /bin/ssh2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh2
rr=`ls -ld /bin/ssh2|cut -c8`
xx=`ls -ld /bin/ssh2|cut -c10`


if [ -f /bin/ssh2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.10" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################
#AV.1.8.2.11
uu=`ls -ld /bin/ssh-add |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-add |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-add
rr=`ls -ld /bin/ssh-add|cut -c8`
xx=`ls -ld /bin/ssh-add|cut -c10`


if [ -f /bin/ssh-add ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.11" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.11" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################
#AV.1.8.2.12
uu=`ls -ld /bin/ssh-add2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-add2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-add2
rr=`ls -ld /bin/ssh-add2|cut -c8`
xx=`ls -ld /bin/ssh-add2|cut -c10`


if [ -f /bin/ssh-add2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.12" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.12" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
######################################################################################################
#AV.1.8.2.13
uu=`ls -ld /bin/ssh-agent |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-agent |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-agent
per=$(stat -c "%a %n" /bin/ssh-agent|awk '{print $1}'|cut -c3)



if [ -f /bin/ssh-agent ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.13" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.13" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.13" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.13" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $per -le 5 ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.13" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.13" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.13" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
######################################################################################################
#AV.1.8.2.14
uu=`ls -ld /bin/ssh-agent2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-agent2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-agent2
rr=`ls -ld /bin/ssh-agent2|cut -c8`
xx=`ls -ld /bin/ssh-agent2|cut -c10`


if [ -f /bin/ssh-agent2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.14" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.14" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
####################################################################################################################
#AV.1.8.2.15
uu=`ls -ld /bin/ssh-askpass |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-askpass |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-askpass
rr=`ls -ld /bin/ssh-askpass|cut -c8`
xx=`ls -ld /bin/ssh-askpass|cut -c10`


if [ -f /bin/ssh-askpass ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.15" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.15" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.15" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.15" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.15" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.15" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.15" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
###########################################################################################################
#AV.1.8.2.16
uu=`ls -ld /bin/ssh-askpass2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-askpass2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-askpass2
rr=`ls -ld /bin/ssh-askpass2|cut -c8`
xx=`ls -ld /bin/ssh-askpass2|cut -c10`


if [ -f /bin/ssh-askpass2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.16" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.16" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.16" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.16" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.16" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.16" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.16" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.17
uu=`ls -ld /bin/ssh-certenroll2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-certenroll2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-certenroll2
rr=`ls -ld /bin/ssh-certenroll2|cut -c8`
xx=`ls -ld /bin/ssh-certenroll2|cut -c10`


if [ -f /bin/ssh-certenroll2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.17" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.17" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.17" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.17" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.17" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.17" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.17" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.18
uu=`ls -ld /bin/ssh-chrootmgr |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-chrootmgr |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-chrootmgr
rr=`ls -ld /bin/ssh-chrootmgr|cut -c8`
xx=`ls -ld /bin/ssh-chrootmgr|cut -c10`


if [ -f /bin/ssh-chrootmgr ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.18" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.18" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.18" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.18" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.18" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.18" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.18" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.19
uu=`ls -ld /bin/ssh-dummy-shell |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-dummy-shell |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-dummy-shell
rr=`ls -ld /bin/ssh-dummy-shell|cut -c8`
xx=`ls -ld /bin/ssh-dummy-shell|cut -c10`


if [ -f /bin/ssh-dummy-shell ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.19" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.19" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.19" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.19" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.19" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.19" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.19" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.20
uu=`ls -ld /bin/ssh-keygen |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-keygen |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-keygen
rr=`ls -ld /bin/ssh-keygen|cut -c8`
xx=`ls -ld /bin/ssh-keygen|cut -c10`


if [ -f /bin/ssh-keygen ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.20" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.20" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.20" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.20" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.20" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.20" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.20" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.21
uu=`ls -ld /bin/ssh-keygen2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-keygen2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-keygen2
rr=`ls -ld /bin/ssh-keygen2|cut -c8`
xx=`ls -ld /bin/ssh-keygen2|cut -c10`


if [ -f /bin/ssh-keygen2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.21" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.21" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.21" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.21" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.21" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.21" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.21" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.22
uu=`ls -ld /bin/ssh-keyscan |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-keyscan |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-keyscan
rr=`ls -ld /bin/ssh-keyscan|cut -c8`
xx=`ls -ld /bin/ssh-keyscan|cut -c10`


if [ -f /bin/ssh-keyscan ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.22" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.22" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.22" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.22" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.22" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.22" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.22" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.23
uu=`ls -ld /bin/ssh-pam-client |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-pam-client |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-pam-client
rr=`ls -ld /bin/ssh-pam-client|cut -c8`
xx=`ls -ld /bin/ssh-pam-client|cut -c10`


if [ -f /bin/ssh-pam-client ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.23" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.23" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.23" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.23" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.23" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.23" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.23" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.24
uu=`ls -ld /bin/ssh-probe |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-probe |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-probe
rr=`ls -ld /bin/ssh-probe|cut -c8`
xx=`ls -ld /bin/ssh-probe|cut -c10`


if [ -f /bin/ssh-probe ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.24" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.24" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.24" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.24" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.24" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.24" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.24" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.25
uu=`ls -ld /bin/ssh-probe2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-probe2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-probe2
rr=`ls -ld /bin/ssh-probe2|cut -c8`
xx=`ls -ld /bin/ssh-probe2|cut -c10`


if [ -f /bin/ssh-probe2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.25" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.25" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.25" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.25" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.25" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.25" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.25" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.26
uu=`ls -ld /bin/ssh-pubkeymgr |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-pubkeymgr |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-pubkeymgr
rr=`ls -ld /bin/ssh-pubkeymgr|cut -c8`
xx=`ls -ld /bin/ssh-pubkeymgr|cut -c10`


if [ -f /bin/ssh-pubkeymgr ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.26" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.26" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.26" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.26" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.26" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.26" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.26" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.27
uu=`ls -ld /bin/ssh-signer |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-signer |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-signer
rr=`ls -ld /bin/ssh-signer|cut -c8`
xx=`ls -ld /bin/ssh-signer|cut -c10`


if [ -f /bin/ssh-signer ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.27" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.27" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.27" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.27" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.27" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.27" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.27" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.28
uu=`ls -ld /bin/ssh-signer2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /bin/ssh-signer2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/bin/ssh-signer2
rr=`ls -ld /bin/ssh-signer2|cut -c8`
xx=`ls -ld /bin/ssh-signer2|cut -c10`


if [ -f /bin/ssh-signer2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.28" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.28" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.29
uu=`ls -ld /lib/libcrypto.a |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib/libcrypto.a |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib/libcrypto.a
rr=`ls -ld /lib/libcrypto.a|cut -c8`
xx=`ls -ld /lib/libcrypto.a|cut -c10`


if [ -f /lib/libcrypto.a ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.29" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.29" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.29" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.29" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.29" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.29" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.29" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.30
uu=`ls -ld /lib/libssh.a |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib/libssh.a |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib/libssh.a
rr=`ls -ld /lib/libssh.a|cut -c8`
xx=`ls -ld /lib/libssh.a|cut -c10`


if [ -f /lib/libssh.a ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.30" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.30" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.30" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.30" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.30" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.30" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.30" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.31
uu=`ls -ld /lib/libssl.a |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib/libssl.a |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib/libssl.a
rr=`ls -ld /lib/libssl.a|cut -c8`
xx=`ls -ld /lib/libssl.a|cut -c10`


if [ -f /lib/libssl.a ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.31" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.31" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.31" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.31" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.31" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.31" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.31" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.32
uu=`ls -ld /lib/libz.a |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib/libz.a |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib/libz.a
rr=`ls -ld /lib/libz.a|cut -c8`
xx=`ls -ld /lib/libz.a|cut -c10`


if [ -f /lib/libz.a ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.32" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.32" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.32" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.32" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.32" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.32" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.32" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.33
uu=`ls -ld /lib-exec/openssh/sftp-server |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib-exec/openssh/sftp-server |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib-exec/openssh/sftp-server
rr=`ls -ld /lib-exec/openssh/sftp-server|cut -c8`
xx=`ls -ld /lib-exec/openssh/sftp-server|cut -c10`


if [ -f /lib-exec/openssh/sftp-server ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.33" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.33" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.33" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.33" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.33" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.33" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.33" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.34
uu=`ls -ld /lib-exec/openssh/ssh-keysign |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib-exec/openssh/ssh-keysign |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib-exec/openssh/ssh-keysign
rr=`ls -ld /lib-exec/openssh/ssh-keysign|cut -c8`
xx=`ls -ld /lib-exec/openssh/ssh-keysign|cut -c10`


if [ -f /lib-exec/openssh/ssh-keysign ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.34" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.34" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.34" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.34" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.34" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.34" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.34" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.35
uu=`ls -ld /lib-exec/openssh/ssh-askpass |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib-exec/openssh/ssh-askpass |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib-exec/openssh/ssh-askpass
rr=`ls -ld /lib-exec/openssh/ssh-askpass|cut -c8`
xx=`ls -ld /lib-exec/openssh/ssh-askpass|cut -c10`


if [ -f /lib-exec/openssh/ssh-askpass ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.35" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.35" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.35" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.35" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.35" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.35" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.35" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.36
uu=`ls -ld /lib-exec/sftp-server |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib-exec/sftp-server |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib-exec/sftp-server
rr=`ls -ld /lib-exec/sftp-server|cut -c8`
xx=`ls -ld /lib-exec/sftp-server|cut -c10`


if [ -f /lib-exec/sftp-server ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.36" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.36" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.36" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.36" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.36" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.36" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.36" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.37
uu=`ls -ld /lib-exec/ssh-keysign |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib-exec/ssh-keysign |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib-exec/ssh-keysign
rr=`ls -ld /lib-exec/ssh-keysign|cut -c8`
xx=`ls -ld /lib-exec/ssh-keysign|cut -c10`


if [ -f /lib-exec/ssh-keysign ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.37" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.37" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.37" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.37" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.37" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.37" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.37" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.38
uu=`ls -ld /lib-exec/ssh-rand-helper |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib-exec/ssh-rand-helper |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib-exec/ssh-rand-helper
rr=`ls -ld /lib-exec/ssh-rand-helper|cut -c8`
xx=`ls -ld /lib-exec/ssh-rand-helper|cut -c10`


if [ -f /lib-exec/ssh-rand-helper ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.38" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.38" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.38" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.38" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.38" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.38" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.38" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.39
uu=`ls -ld /libexec/openssh/sftp-server |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /libexec/openssh/sftp-server |awk '{print $4}'`
ggg=`id -g $gg`

i=/libexec/openssh/sftp-server
rr=`ls -ld /libexec/openssh/sftp-server|cut -c8`
xx=`ls -ld /libexec/openssh/sftp-server|cut -c10`


if [ -f /libexec/openssh/sftp-server ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.39" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.39" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.39" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.39" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.39" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.39" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.39" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.40
uu=`ls -ld /libexec/openssh/ssh-keysign |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /libexec/openssh/ssh-keysign |awk '{print $4}'`
ggg=`id -g $gg`

i=/libexec/openssh/ssh-keysign
rr=`ls -ld /libexec/openssh/ssh-keysign|cut -c8`
xx=`ls -ld /libexec/openssh/ssh-keysign|cut -c10`


if [ -f /libexec/openssh/ssh-keysign ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.40" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.40" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.40" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.40" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.40" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.40" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.40" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.41
uu=`ls -ld /libexec/openssh/ssh-askpass |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /libexec/openssh/ssh-askpass |awk '{print $4}'`
ggg=`id -g $gg`

i=/libexec/openssh/ssh-askpass
rr=`ls -ld /libexec/openssh/ssh-askpass|cut -c8`
xx=`ls -ld /libexec/openssh/ssh-askpass	|cut -c10`


if [ -f /libexec/openssh/ssh-askpass ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.41" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.41" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.41" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.41" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.41" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.41" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.41" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.42
uu=`ls -ld /libexec/sftp-server |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /libexec/sftp-server |awk '{print $4}'`
ggg=`id -g $gg`

i=/libexec/sftp-server
rr=`ls -ld /libexec/sftp-server|cut -c8`
xx=`ls -ld /libexec/sftp-server	|cut -c10`


if [ -f /libexec/sftp-server ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.42" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.42" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.42" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.42" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.42" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.42" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.42" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.43
uu=`ls -ld /libexec/ssh-keysign |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /libexec/ssh-keysign |awk '{print $4}'`
ggg=`id -g $gg`

i=/libexec/ssh-keysign
rr=`ls -ld /libexec/ssh-keysign|cut -c8`
xx=`ls -ld /libexec/ssh-keysign	|cut -c10`


if [ -f /libexec/ssh-keysign ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.43" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.43" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.43" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.43" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.43" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.43" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.43" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.44
uu=`ls -ld /libexec/ssh-rand-helper |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /libexec/ssh-rand-helper |awk '{print $4}'`
ggg=`id -g $gg`

i=/libexec/ssh-rand-helper
rr=`ls -ld /libexec/ssh-rand-helper|cut -c8`
xx=`ls -ld /libexec/ssh-rand-helper	|cut -c10`


if [ -f /libexec/ssh-rand-helper ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.44" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.44" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.44" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.44" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.44" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.44" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.44" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.45
uu=`ls -ld /sbin/sshd |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /sbin/sshd |awk '{print $4}'`
ggg=`id -g $gg`

i=/sbin/sshd
rr=`ls -ld /sbin/sshd|cut -c8`
xx=`ls -ld /sbin/sshd	|cut -c10`


if [ -f /sbin/sshd ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.45" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.45" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.45" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.45" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.45" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.45" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.45" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.46
uu=`ls -ld /sbin/sshd2 |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /sbin/sshd2 |awk '{print $4}'`
ggg=`id -g $gg`

i=/sbin/sshd2
rr=`ls -ld /sbin/sshd2|cut -c8`
xx=`ls -ld /sbin/sshd2	|cut -c10`


if [ -f /sbin/sshd2 ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.46" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.46" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.46" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.46" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.46" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.46" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.46" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.47
uu=`ls -ld /sbin/sshd-check-conf |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /sbin/sshd-check-conf |awk '{print $4}'`
ggg=`id -g $gg`

i=/sbin/sshd-check-conf
rr=`ls -ld /sbin/sshd-check-conf|cut -c8`
xx=`ls -ld /sbin/sshd-check-conf	|cut -c10`


if [ -f /sbin/sshd-check-conf ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.47" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.47" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.47" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.47" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.47" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.47" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.47" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.49
uu=`ls -ld /lib/svc/method/sshd |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /lib/svc/method/sshd |awk '{print $4}'`
ggg=`id -g $gg`

i=/lib/svc/method/sshd
rr=`ls -ld /lib/svc/method/sshd|cut -c8`
xx=`ls -ld /lib/svc/method/sshd	|cut -c10`


if [ -f /lib/svc/method/sshd ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.49" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.49" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.49" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.49" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.49" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.49" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.49" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.2.50
uu=`ls -ld /usr/lib/ssh/sshd |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /usr/lib/ssh/sshd |awk '{print $4}'`
ggg=`id -g $gg`

i=/usr/lib/ssh/sshd
rr=`ls -ld /usr/lib/ssh/sshd|cut -c8`
xx=`ls -ld /usr/lib/ssh/sshd	|cut -c10`


if [ -f /usr/lib/ssh/sshd ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.50" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.50" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.50" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.50" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.2.50" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.2.50" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.2.50" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.1
uu=`ls -ld /etc/openssh/sshd_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/openssh/sshd_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/openssh/sshd_config
rr=`ls -ld /etc/openssh/sshd_config|cut -c8`
xx=`ls -ld /etc/openssh/sshd_config	|cut -c10`


if [ -f /etc/openssh/sshd_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.1" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.1" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.2
uu=`ls -ld /etc/ssh/sshd_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/ssh/sshd_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/ssh/sshd_config
per=$(stat -c "%a %n" /etc/ssh/sshd_config|awk '{print $1}'|cut -c3)



if [ -f /etc/ssh/sshd_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $per -le 5 ]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.2" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.2" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.3
uu=`ls -ld /etc/ssh/sshd2_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/ssh/sshd2_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/ssh/sshd2_config
rr=`ls -ld /etc/ssh/sshd2_config|cut -c8`
xx=`ls -ld /etc/ssh/sshd2_config	|cut -c10`


if [ -f /etc/ssh/sshd2_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.3" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.3" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.4
uu=`ls -ld /etc/ssh2/sshd_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/ssh2/sshd_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/ssh2/sshd_config
rr=`ls -ld /etc/ssh2/sshd_config|cut -c8`
xx=`ls -ld /etc/ssh2/sshd_config	|cut -c10`


if [ -f /etc/ssh2/sshd_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.4" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.4" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.5
uu=`ls -ld /etc/ssh2/sshd2_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/ssh2/sshd2_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/ssh2/sshd2_config
rr=`ls -ld /etc/ssh2/sshd2_config|cut -c8`
xx=`ls -ld /etc/ssh2/sshd2_config	|cut -c10`


if [ -f /etc/ssh2/sshd2_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.5" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.5" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.6
uu=`ls -ld /etc/sshd_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/sshd_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/sshd_config
rr=`ls -ld /etc/sshd_config|cut -c8`
xx=`ls -ld /etc/sshd_config	|cut -c10`


if [ -f /etc/sshd_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.6" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.6" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.7
uu=`ls -ld /etc/sshd2_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /etc/sshd2_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/etc/sshd2_config
rr=`ls -ld /etc/sshd2_config|cut -c8`
xx=`ls -ld /etc/sshd2_config	|cut -c10`


if [ -f /etc/sshd2_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.7" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.7" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.8
uu=`ls -ld /usr/local/etc/sshd_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /usr/local/etc/sshd_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/usr/local/etc/sshd_config
rr=`ls -ld /usr/local/etc/sshd_config|cut -c8`
xx=`ls -ld /usr/local/etc/sshd_config	|cut -c10`


if [ -f /usr/local/etc/sshd_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.8" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.8" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.9
uu=`ls -ld /usr/local/etc/sshd2_config |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /usr/local/etc/sshd2_config |awk '{print $4}'`
ggg=`id -g $gg`

i=/usr/local/etc/sshd2_config
rr=`ls -ld /usr/local/etc/sshd2_config|cut -c8`
xx=`ls -ld /usr/local/etc/sshd2_config	|cut -c10`


if [ -f /usr/local/etc/sshd2_config ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.9" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.9" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
#############################################################################################################################
#AV.1.8.3.10
uu=`ls -ld /usr/lib/ssh/ssh-keysign |awk '{print $3}'`
vv=`id -u $uu`
gg=`ls -ld /usr/lib/ssh/ssh-keysign |awk '{print $4}'`
ggg=`id -g $gg`

i=/usr/lib/ssh/ssh-keysign
rr=`ls -ld /usr/lib/ssh/ssh-keysign|cut -c8`
xx=`ls -ld /usr/lib/ssh/ssh-keysign	|cut -c10`


if [ -f /usr/lib/ssh/ssh-keysign ]
then
	if [ $vv -le 99 ] || [[ $vv -ge 101 && $vv -le 499 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is System user" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "User validation" >>p2
		echo "$i User is not System user" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $ggg -le 99 ] || [[ $ggg -ge 101 && $ggg -le 999 ]]
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is System Group" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Group validation" >>p2
		echo "$i Group is not System Group" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
	if [ $rr == "r" ] && [ $xx == "x" ] 
	then
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is set correctly" >>p3
		echo "yes" >>p4
		echo "AV.1.8.3.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	else
		echo "Protecting Resources – OSRs" >>p1
		echo "Other validation" >>p2
		echo "$i Other's permission is not set correctly" >>p3
		echo "No" >>p4
		echo "AV.1.8.3.10" >>p12
		echo "$c" >>p5
		echo "$z" >>p6
	fi
else
	echo "Protecting Resources – OSRs" >>p1
	echo "$i" >>p2
	echo "$i does not exists" >>p3
	echo "Yes" >>p4
	echo "AV.1.8.3.10" >>p12
	echo "$c" >>p5
	echo "$z" >>p6
fi
##################################################################################################
#AV.1.1.4,#AV.1.1.5
echo "Password Requirements" >>p1
echo "Private Key Passphrases" >>p2
echo "This cann't be health checked" >>p3
echo "Not_Applicable" >>p4
echo "$c" >>p5
echo "$z" >>p6
echo "AV.1.1.4_AV.1.1.5" >>p12

#############################################################################################
#AV.1.7.1.2_Identify and Authenticate Users
yy=$(cat /etc/ssh/sshd_config | egrep ^PermitRootLogin|awk '{print $2}')

        if [ $yy <= "Yes" ] || [ $yy <= "forced-commands" ] ||  [ $yy <="forced-commands" ]
        then
					echo "Identify and Authenticate Users" >>p1
					echo "PermitRootLogin" >>p2
					echo "Root Login is present-$i" >>p3
					echo "AV.1.7.1.2" >>p12
					echo "Yes" >>p4
					echo "$c" >> p5
					echo "$z" >>p6
				else
        			echo "Identify and Authenticate Users" >>p1
					echo "PermitRootLogin" >>p2
					echo "Root Login is not present-$i" >>p3
					echo "No" >>p4
					echo "AV.1.7.1.2" >>p12
					echo "$c" >> p5
					echo "$z" >>p6
        fi
		
#############################################################################################	
#AV.1.2.2
	szl=`cat /etc/ssh/sshd_config | grep -i "^Protocol" | awk  '{print $2}'|cut -c1`
	if [ $szl -eq 2 ]
	then
		echo "Logging" >>p1
		echo "Protocol version $sz1" >>p2
		echo "$szl" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.2.2" >>p12
	else
		echo "Logging" >>p1
		echo "Protocol version QuietMode" >>p2
		echo "Value-is-not-set" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "AV.1.2.2" >>p12
	fi
		


#AV.1.1.6,AV.1.1.7
cat /etc/passwd | awk -F"_" '{print $1}' > temp_id
for i in `cat temp_id`
do
	if [ -f /home/$i/.ssh/authorized_keys ]
	then
		A=`id $i | awk '{print $1}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		B=`id $i | awk '{print $2}' | awk -F"(" '{print $2}' | awk -F")" '{print $1}'`
		sk=`ls -lrt /home/$i/.ssh/id_rsa.pub | awk '{print $3}'`
		sl=`ls -lrt /home/$i/.ssh/id_dsa.pub | awk '{print $4}'`
		if [ "$A" == "$sk" ]
		then
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "Private-key-is-owned-by-correct-group" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.6_AV.1.1.7" >>p12

			
		else
			if [ "$B" == "$sl" ] 
			then
			
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "ownership-for-/home/$i/.ssh/authorized_keys-is-$sk_$sl" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.6_AV.1.1.7" >>p12
			fi
		fi
	else
				echo "Password Requirements" >>p1
				echo "Private Key Passphrases - system-to-system authentication" >>p2
				echo "/home/$i/.ssh/authorized_keys-doesnt-exist" >>p3
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "AV.1.1.6_AV.1.1.7" >>p12
	fi
done
rm -rf 	temp_id	




#################################################################################################

######### SUDO HC Script ####################

#################################################################################################

#ZY.1.2.4_AV.1.2.4
sl=`sed -n '/# rotate.log*/,/#.*keep*/p' /etc/logrotate.conf |grep -v '#' |egrep 'monthly|weekly'`
sn=`cat /etc/logrotate.conf |grep -v '#' |grep ^rotate |uniq  |awk '{print $2}'`

if [[ "$sl" == "weekly" && "$sn" -ge "$LOG_ROTATE_WEEK" ]] || [[ "$sl" == "monthly" && "$sn" -ge "$LOG_ROTATE_MONTH" ]]
then
cat /etc/logrotate.conf |grep "^include.*/etc/logrotate.d"
if [ $? -eq 0 ]
then
  sp=`cat /etc/logrotate.d/syslog |grep '^/var/log/secure' |wc -l`
  if [ $sp -gt 0 ]
  then
	sed -n '/\/var\/log\/secure.*{/,/}/p' /etc/logrotate.d/syslog |grep -v '#' > log_file1
	sk=`cat log_file1 |wc -l`
	if [ $sk -gt 0 ]
	then
		sj1=`cat log_file1 |grep rotate |awk '{print $2}'`
		sj2=`cat log_file1 |grep weekly |wc -c`
		sj3=`cat log_file1 |grep monthly |wc -c`
		if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]]
		then
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as correct for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4_AV.1.2.4">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as incorrect for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4_AV.1.2.4">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is-set-as correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4_AV.1.2.4">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
  else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is not set correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4_AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
  fi
else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "'include /etc/logrotate.d' entry not found in /etc/logrotate.conf. Please check logrotate policy manually" >>p3
		echo "ZY.1.2.4_AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
else
cat /etc/logrotate.conf |grep "^include.*/etc/logrotate.d"
if [ $? -eq 0 ]
then
  sp=`cat /etc/logrotate.d/syslog |grep '^/var/log/secure' |wc -l`
  if [ $sp -gt 0 ]
  then
	sed -n '/\/var\/log\/secure.*{/,/}/p' /etc/logrotate.d/syslog |grep -v '#' > log_file1
	sk=`cat log_file1 |wc -l`
	if [ $sk -gt 0 ]
	then
		sj1=`cat log_file1 |grep rotate |awk '{print $2}'`
		sj2=`cat log_file1 |grep weekly |wc -c`
		sj3=`cat log_file1 |grep monthly |wc -c`
		if [[ $sj1 -ge $LOG_ROTATE_WEEK  &&  $sj2 -gt 1 ]] || [[ $sj1 -ge $LOG_ROTATE_MONTH  &&  $sj3 -gt 1 ]]
		then
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as correct for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4_AV.1.2.4">>p12
			echo "yes" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		else
			echo "Logging" >>p1
		        echo "Retain Log Files" >>p2
			echo "Logrotate-is-set-as incorrect for /var/log/secure in-/etc/logrotate.d/syslog" >>p3
			echo "ZY.1.2.4_AV.1.2.4">>p12
			echo "no" >>p4
			echo "$c" >> p5
			echo "$z" >>p6
		fi
	else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is-set-as correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4_AV.1.2.4">>p12
		echo "yes" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
	fi
  else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "Logrotate for /var/log/secure is not set correct in /etc/logrotate.d/syslog" >>p3
		echo "ZY.1.2.4_AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
  fi
else
		echo "Logging" >>p1
                echo "Retain Log Files" >>p2
		echo "'include /etc/logrotate.d' entry not found in /etc/logrotate.conf. Please check logrotate policy manually" >>p3
		echo "ZY.1.2.4_AV.1.2.4">>p12
		echo "no" >>p4
		echo "$c" >> p5
		echo "$z" >>p6
fi
fi
rm -rf log_file1


#ZY.1.4.2.0_#ZY.1.4.2.1
cat /etc/sudoers |grep SHELLESCAPE
if [ $? -eq 0 ]
then
cat /etc/sudoers | grep -i "noexec"
if [ $? -eq 0 ]
then
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "noexec is enabled" >>p3
		echo "yes" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.4.2.0_ZY.1.4.2.1" >>p12
else
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "noexec-is-not-enabled" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.4.2.0_ZY.1.4.2.1" >>p12
fi
else
		echo "System Settings" >>p1
		echo "Commands which allow shell escape" >>p2
		echo "shell escape-is-not-enabled" >>p3
		echo "no" >>p4
		echo "$c" >>p5
		echo "$z" >>p6
		echo "ZY.1.4.2.0_ZY.1.4.2.1" >>p12
fi

#ZY.1.4.2.3
Release=`cat /etc/redhat-release |awk '{print $1}'`
if [ "$Release" != "Red" ]
then
cat /etc/sudoers | grep "Defaults env_file=/etc/sudo.env"
	if [ $? -eq 0 ]
	then
		if [ -f /etc/sudo.env ]
		then
			cat /etc/sudo.env | egrep "^SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n"
			if [ $? -eq 0 ]
			then
				echo "System Settings" >>p1
				echo "Commands which allow shell escape" >>p2
				echo "SMIT-values-found" >>p3
				echo "missing-values-SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n" >>p2
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "ZY.1.4.2.3" >>p12
			
			else
				echo "missing-values-SMIT_SHELL=n|^SMIT_SEMI_COLON=n|^SMIT_QUOTE=n" >>p3
				echo "System Settings" >>p1
				echo "Commands which allow shell escape" >>p2
				echo "yes" >>p4
				echo "$c" >>p5
				echo "$z" >>p6
				echo "ZY.1.4.2.3" >>p12
			fi
		else
			echo "System Settings" >>p1
			echo "Commands which allow shell escape" >>p2
			echo "/etc/sudo.env-file-not-found" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.4.2.3" >>p12
		fi
	fi
else
			echo "System Settings" >>p1
			echo "Commands which allow shell escape" >>p2
			echo "This-is-not-for-Linux" >>p3
			echo "Not_Applicable" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.4.2.3" >>p12

fi

#ZY.1.4.3.3
#sl=`cat /etc/sudoers.d/* |grep "Cmnd_Alias.*SUDOSUDO.*=.*/usr/local/bin/sudo,.*/usr/bin/sudo,.*/bin/sudo"`
#sp=`cat /etc/sudoers |grep "Cmnd_Alias.*SUDOSUDO" |grep "=.*/usr/local/bin/sudo,.*/usr/bin/sudo,.*/bin/sudo"`
sk=`cat /etc/sudoers |grep -v '#' |grep -v '^$' |tail -1`
#cat /etc/sudoers | grep "^ALL ALL=\!SUDOSUDO"
#if [ "$sk" == "ALL ALL=!SUDOSUDO" ]
if [[ "$sk" == *"ALL ALL=!SUDOSUDO"* ]]
then
			
			echo "System Settings" >>p1
			echo "Preventing Nested Sudo invocation" >>p2
			echo "ALL-ALL=!SUDOSUDO-found" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.4.3.3" >>p12
else
			
			echo "System Settings" >>p1
			echo "Preventing Nested Sudo invocation" >>p2
			echo "ALL-ALL=!SUDOSUDO-not-found" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.4.3.3" >>p12
fi



#ZY.1.2.3,ZY.1.4.4
sl=`ls -l /var/log/hist/root/ |wc -c`
if [ "$sl" -gt "0" ] && [ -f /etc/profile.d/secondary_logging_IBM.sh ]
then
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is in place" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.3_ZY.1.4.4" >>p12
else
	sl1=`ls -ltr /root/.history-sudo-* |wc -l`
	if [ $sl1 -gt 0 ]
	then
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is in place" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.3_ZY.1.4.4" >>p12
	else		
			echo "Logging" >>p1
			echo "Secondary logging" >>p2
			echo "Secondary login is not in place" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.3_ZY.1.4.4" >>p12
	fi
fi



#ZY.1.2.1
sk=`cat /etc/sudoers.d/* |grep "\!logfile" |wc -l`
sl=`cat /etc/sudoers |grep "\!logfile" |wc -l`
if [ $sk -gt 0 ] || [ $sl -gt 0 ]
then
			echo "Logging" >>p1
			echo "Sudo Logging must not be disabled" >>p2
			echo "Sudo logging is disabled" >>p3
			echo "no" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.1" >>p12
else
			echo "Logging" >>p1
			echo "Sudo Logging must not be disabled" >>p2
			echo "Sudo logging is not disabled" >>p3
			echo "yes" >>p4
			echo "$c" >>p5
			echo "$z" >>p6
			echo "ZY.1.2.1" >>p12
fi




#ZY.1.4.3.1,ZY.1.8.2.1,ZY.1.8.2.2,ZY.1.8.1.2,ZY.1.8.1.4
cat /etc/sudoers |egrep "^#include|^#includedir" |awk '{print $2}' >temp1
cat /etc/sudoers.d/* |egrep "^#include|^#includedir" |awk '{print $2}' >>temp1
for i in `cat temp1`
do
sk=`echo $i |cut -c1`
if [ "$sk" == "/" ]
then
	echo "System Settings" >>p1
	echo "Specific commands/programs executed via sudo_" >>p2
	echo "Full path specified for command \"$i\" in sudoers config file having include or includedir statements" >>p3
	echo "yes" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "ZY.1.4.3.1_ZY.1.8.2.1_ZY.1.8.2.2_ZY.1.8.1.2_ZY.1.8.1.4" >>p12
else
	echo "System Settings" >>p1
	echo "Specific commands/programs executed via sudo_" >>p2
	echo "Full path not specified for command \"$i\" in sudoers config file having include or includedir statements" >>p3
	echo "no" >>p4
	echo "$c" >>p5
	echo "$z" >>p6
	echo "ZY.1.4.3.1_ZY.1.8.2.1_ZY.1.8.2.2_ZY.1.8.1.2_ZY.1.8.1.4" >>p12
fi
done
rm -rf temp1

#ZY.1.8.1.0
ls -l /etc/sudoers
if [ $? -eq 0 ]
then
	sz=`ls -lrt /etc/sudoers | awk '{print $1}' | cut -c9`
	sz1=`ls -lrt /etc/sudoers | awk '{print $3}'`
	if [ "$sz1" == "root" ] && [ "$sz" != "w" ]
	then
				echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
				echo "Permission of /etc/sudoers is valid" >>p3
                echo "yes" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.0" >>p12
	else
				echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
				echo "Permission of /etc/sudoers is invalid" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.0" >>p12
	fi
else
				echo "Protecting Resources - OSRs" >>p1
                echo "/etc/sudoers permission" >>p2
				echo "File /etc/sudoers not exist" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.0" >>p12
fi

#ZY.1.4.5
echo "System Settings" >>p1
echo "Editors used with sudo privileges" >>p2
echo "This cann't be health checked" >>p3
echo "Not_Applicable" >>p4
echo "$c" >>p5
echo "$z" >>p6
echo "ZY.1.4.5" >>p12
		 

#ZY.1.8.1.1,ZY.1.8.1.3,ZY.1.8.1.5,ZY.1.8.1.6,ZY.1.8.2.3
sl=`ls -ltr /etc/sudoers.d |wc -l`
file1=`ls -ld /etc/sudoers.d |wc -l`
if [ $file1 -gt 0 ] && [ $sl -gt 1 ]
then
cat /etc/sudoers |egrep "^#include|^#includedir" |awk '{print $2}' >temp1
cat /etc/sudoers.d/* |egrep "^#include|^#includedir" |awk '{print $2}' >>temp1
	sn=`cat temp1 |wc -l`
	if [ $sn -gt 0 ]
	then
	for i in `cat temp1`
	do
		sz=`ls -ld $i | awk '{print $1}' | cut -c9`
		sk=`ls -ld $i | awk '{print $3}'`
		sp=`ls -ld $i | awk '{print $4}'`
		if [ "$sk" == "root" ] && [ "$sz" != "w" ] && [ "$sp" == "root" ]
		then
			echo "Protecting Resources - OSRs" >>p1
		        echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
			echo "File permission is valid for $i" >>p3
		        echo "yes" >>p4
		        echo "$c" >>p5
		        echo "$z" >>p6
		        echo "ZY.1.8.1.1_ZY.1.8.1.3_ZY.1.8.1.5_ZY.1.8.1.6_ZY.1.8.2.3" >>p12
		else
			echo "Protecting Resources - OSRs" >>p1
		        echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
			echo "File permission is invalid for $i" >>p3
		        echo "no" >>p4
		        echo "$c" >>p5
		        echo "$z" >>p6
		        echo "ZY.1.8.1.1_ZY.1.8.1.3_ZY.1.8.1.5_ZY.1.8.1.6_ZY.1.8.2.3" >>p12
		fi
	done
	else
		echo "Protecting Resources - OSRs" >>p1
                echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
		echo "SUDO template not implemented" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.1_ZY.1.8.1.3_ZY.1.8.1.5_ZY.1.8.1.6_ZY.1.8.2.3" >>p12
	fi

else
		echo "Protecting Resources - OSRs" >>p1
                echo "File permission in /etc/sudoers.d and /etc/sudoers" >>p2
		echo "SUDO template not implemented" >>p3
                echo "no" >>p4
                echo "$c" >>p5
                echo "$z" >>p6
                echo "ZY.1.8.1.1_ZY.1.8.1.3_ZY.1.8.1.5_ZY.1.8.1.6_ZY.1.8.2.3" >>p12
fi
rm -rf temp1
##########################################################################################
#ZY.30.0.2
ss=`grep ^auth /etc/rsyslog.conf |awk -F"." '{print $1}'`
echo $ss
if [ $ss == "authpriv" ]|| [ $ss == "auth" ]
then
  		echo "Logging" >>p1
        	echo "Sudo Logging in external system" >>p2
		echo "Sudo Logging is using $ss" >> p3
		echo "yes" >>p4
         	echo "$c" >> p5
                echo "$z" >>p6
		echo "ZY.30.0.2" >>p12
  else
		echo "Logging" >>p1
        	echo "Sudo Logging in external system" >>p2
		echo "Sudo Logging is not using $ss" >> p3
                echo "no" >>p4
                echo "$c" >> p5
                echo "$z" >>p6
		echo "ZY.30.0.2" >>p12
  fi


paste -d ";" p6 p12 p1 p2 p3 p4 p5 > `hostname`_Linux_SSH_SUDO-Lufthansa$c_mhc.csv
chmod 644 `hostname`_Linux_SSH_SUDO-Lufthansa$c_mhc.csv
rm -rf temp_shadow temp_shadow1 temp1_shadow temp_shadow2 temp_shadow3 temp-ud psw_temp temp_uid temp_uid1 temp_gid temp_gid1 pasd_temp  f1 t1 temp_pam.so world-writable-test log_file1
