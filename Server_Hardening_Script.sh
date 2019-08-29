#!/bin/sh
####################################################################################################
#
#       FILE: Server_Hardening_Script.sh
#
#       Usage: $(basename $0)
#
#
# 		DESCRIPTION:Script to check server hardening parameters.
#		Release:2
#       AUTHOR:Sarath KV
#		Platforms:RHEL [  5, 6,7 ] , HP-UX [ 11.a ] & SOlaris [  10 & 11 ]
#      	VERSION:2.2
#      	CREATED:30/June/2014
##################################################################################################
#
#
#  Setup Initial Global Parameters
#
#
##################################################################################################
#set -vx

##################################################################################################
# Define Global Variables
##################################################################################################
OS=`uname`                                                                      ; export OS
HOSTNAME=`uname -n`                                                             ; export HOSTNAME
DATE=`date +%d-%B-%Y`                                                           ; export DATE
#SCRIPT_LOCATION="`pwd`"                                                	   ; export SCRIPT_LOCATION
SCRIPT_LOCATION="/script"                                           	       	; export SCRIPT_LOCATION
#SCRIPT_LOCATION=`dirname "$0"`                                                  ; export SCRIPT_LOCATION
BASEDIR="/var/tmp/server_hardening"                                             ; export BASEDIR
TMP_DIR="/tmp"                                                                  ; export TMP_DIR
PATH=${PATH}:${SCRIPT_LOCATION}                                                 ; export PATH
#DEBUG_MODE="0"                                                                  ; export DEBUG_MODE
FAILED_NUM_CHK=""                                                               ; export FAILED_NUM_CHK
SUCCESS_NUM_CHK=""                                                              ; export SUCCESS_NUM_CHK
NA_NUM_CHK=""                                                                   ; export NA_NUM_CHK

#Script is supported for Linux, Solaris and HP-UX
if [ "${OS}" = "HP-UX" ] ||  [ "${OS}" = "SunOS" ] || [ "${OS}" = "Linux" ] ; then 
	echo "Script is supported for Linux/HP-UX/Solaris " >/dev/null 2>&1
else 
	echo "Script is not supported for ${OS}"
fi

##################################################################################################
# Edit these three variables based on the flavours supported and the account
##################################################################################################
ACCOUNT_NAME="Account_Name"                                                                    ; export ACCOUNT_NAME
SCRIPT_OBJECTIVE="server_hardening"                                                   ; export SCRIPT_OBJECTIVE

##################################################################################################
# Based on the account name and the script type, determine script's pre-name
##################################################################################################
SCRIPT_PREFIX=""                                                                ; export SCRIPT_PREFIX
if [ -n "${ACCOUNT_NAME}" ] ; then SCRIPT_PREFIX="${ACCOUNT_NAME}_"; fi
if [ -n "${SCRIPT_OBJECTIVE}" ] ; then SCRIPT_PREFIX="${SCRIPT_PREFIX}${SCRIPT_OBJECTIVE}_"; fi
export SCRIPT_PREFIX

##################################################################################################
# Initialize the scripts files needed for the script execution
##################################################################################################
FUNCTIONS_FILE="${SCRIPT_LOCATION}/${SCRIPT_PREFIX}function_definitions"	; export FUNCTIONS_FILE
CONSTANTS_FILE="${SCRIPT_LOCATION}/script_constants"            ; export CONSTANTS_FILE
EXCEPTIONS_FILE="${SCRIPT_LOCATION}/exception_file"			; export exception_file

##################################################################################################
# Ensure script is initialized by root user
##################################################################################################
if [ ${LOGNAME} != "root" ] && [ `whoami` != "root" ] ;then
	echo "$0: ERROR - Script must be run by root user."
	exit 1
fi

##################################################################################################
# Ensure all the script files needed for execution exists.
##################################################################################################
for FILE in ${CONSTANTS_FILE} ${FUNCTIONS_FILE}
do
	if [ ! -f ${FILE} ] ; then
		${ECHO_CMD} "ERROR: ${FILE} file does not exist. Please copy the file and rerun the script."
		exit 1
	fi
done

##############################################################################
# Initialise and source the variables & Functions used in the script in current shell and export them
##############################################################################
. ${CONSTANTS_FILE} >/dev/null 2>&1
. ${FUNCTIONS_FILE} >/dev/null 2>&1

##################################################################################################
# SCRIPT USAGE
##################################################################################################
if [ "$#" -ne 1 ]  ; then
	Usage_fn
	exit 1
elif  [ "$@" = "verify" ] || [ "$@" = "repair" ] ;then
	echo "arg is :$@. Executing the respective case statement" >/dev/null 2>&1
else
	Usage_fn
	exit 1
fi
##############################################################################
# Define and create the data and log directories
##############################################################################
BASEDIR="${BASEDIR}/${HOSTNAME}_${DATE}"                          ; export BASEDIR
LOGDIR="${BASEDIR}/logs"                            			  ; export LOGDIR

if [ ! -d ${BASEDIR} ]; then mkdir -p ${BASEDIR}; fi
if [ ! -d ${LOGDIR} ]; then mkdir -p ${LOGDIR}; fi

##############################################################################
# Define custom files
##############################################################################

##############################################################################
# Define and Initialize data and log files
##############################################################################
DATA_FILE="${BASEDIR}/${HOSTNAME}_captured_outputs.txt.`date +%F`"                  ; export DATA_FILE
#LOG_FILE="${LOGDIR}/logs_`date +%F`"                                               ; export LOG_FILE
TEMP_FILE="${BASEDIR}/${HOSTNAME}_captured_outputs.txt.`date +%F`"                  ; export DATA_FILE
cp /dev/null ${DATA_FILE}
#cp /dev/null ${LOG_FILE}

##################################################################################################
# Clean up the temporary files on exit, abort, failed etc
##################################################################################################
trap 'Clean_fn' 0
trap 'Clean_fn; exit' 1 2 3 15

##################################################################################################
#function to display the basic server parameters like server name and OS name
##################################################################################################
${ECHO_CMD} "" | tee -a ${DATA_FILE}
${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
Basic_server_info_fn
${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}

##################################################################################################
# If the i/p parameter is "verification", then call functions related to each section of the check-list
##################################################################################################
case "${1}" in
verify)
	#Write functions for each task in the check-list to verify the functionality. Print section/task no also
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 1. PATCHES AND ADDITIONAL SOFTWARE " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 1.1 Use the Latest Packages and Updates " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	kernel_version_fn "1.1"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2. FILES/DIRECTORY PERMISSIONS " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2.1 Verify file permissions of passwd, shadow and cron files " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	fileperm_verify_fn "-rw-r--r--" "root" "root" "${USER_FILE}" "644" "2.1"
	fileperm_verify_fn "-rw-r--r--" "root" "root" "${GROUP_FILE}" "644" "2.1"
	fileperm_verify_fn "-r--------" "root" "root" "${SHADOW_FILE}" "400" "2.1"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2.2 Restrict at / cron to Authorized Users " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} "Check for at.allow,cron.allow,at.deny & cron.deny files: " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	fileperm_verify_fn "-r--------" "root" "root" "${AT_ALLOW}" "400" "2.2"
	fileperm_verify_fn "-r--------" "root" "root" "${CRON_ALLOW}" "400" "2.2"
	file_remove_fn "$AT_DENY" "2.2"
	file_remove_fn "$CRON_DENY" "2.2"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2.3 Check no NFS shares exported with root access and are authorized to specific hosts " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"  | tee -a ${DATA_FILE}
	nfs_share_verfy_access_fn "2.3"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"  | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3. Warning Banners "  | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.1 Create Warnings for Standard Login Services "  | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	banner_std_login_verify_fn "3.1"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.2 Enable a Warning Banner for the SSH Service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	banner_ssh_ftp_verify_fn "banner" "${SSH_CONFIG}" "Property of Account_Name" " " "3.2"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.3 Enable a Warning Banner for the GNOME Service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	banner_GNOME_verify_fn "3.3"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.4 Enable a Warning Banner for the FTP service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	ps -eaf | grep -w ftp | grep -v grep >/dev/null
	if [ $? -eq 0 ] ; then
		banner_ssh_ftp_verify_fn "banner" "${FTP_BANNER}" "Property of Account_Name" " " "3.4"
	else
		${ECHO_CMD} "\nCOMMAND: ps -eaf | grep -w ftp | grep -v grep\n" | tee -a ${DATA_FILE}
		${ECHO_CMD} "${NORM}CURRENT VALUE: AS PER EXPECTED VALUE, ftp is not running. No need to set banner msg${NORM}" | tee -a ${DATA_FILE}
		${ECHO_CMD} "${NORM}EXPECTED VALUE: No need to set banner msg if ftp is not running${NORM}" | tee -a ${DATA_FILE}
		${ECHO_CMD} "\nOUTPUT: `ps -eaf | grep -w ftp | grep -v grep`" | tee -a ${DATA_FILE}
		SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:3.4"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.5 Check that the Banner Setting for telnet is Null " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	banner_TELNET_verify_fn "3.5"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4 User Accounts and Environment " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.1 Verify that there are no accounts with empty password fields"  | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	user_empty_password_verify_fn "4.1"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.2 Set Strong Password Creation Policies " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	if [ "${OS}" = "Linux" ] ; then
		set_strong_passwd_Linux_verify_fn "4.2"
	elif [ "${OS}" = "HP-UX" ] ; then	
		string_verify_fn "MIN_PASSWORD_LENGTH" "${PASSWORD_POLICY}" "8" "=" "4.2"
		string_verify_fn "PASSWORD_MIN_LOWER_CASE_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
		string_verify_fn "PASSWORD_MIN_SPECIAL_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
		string_verify_fn "PASSWORD_MIN_DIGIT_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
		string_verify_fn "PASSWORD_MAXDAYS" "${PASSWORD_POLICY}" "175" "=" "4.2"
		string_verify_fn "PASSWORD_HISTORY_DEPTH" "${PASSWORD_POLICY}" "6" "=" "4.2"
		string_verify_fn "PASSWORD_WARNDAYS" "${PASSWORD_POLICY}" "30" "=" "4.2"	 
	elif [ "${OS}" = "SunOS" ] ; then	
		string_verify_fn "PASSLENGTH" "${PASSWORD_POLICY}" "8" "=" "4.2"
		string_verify_fn "MINALPHA" "${PASSWORD_POLICY}" "1" "=" "4.2"
		string_verify_fn "MINSPECIAL" "${PASSWORD_POLICY}" "1" "=" "4.2"
		string_verify_fn "MINDIGIT" "${PASSWORD_POLICY}" "1" "=" "4.2"
		string_verify_fn "MAXWEEKS" "${PASSWORD_POLICY}" "25" "=" "4.2"
		string_verify_fn "HISTORY" "${PASSWORD_POLICY}" "6" "=" "4.2"
		string_verify_fn "WARNWEEKS" "${PASSWORD_POLICY}" "4" "=" "4.2"
		string_verify_fn "WARNWEEKS" "${PASSWORD_POLICY}" "4" "=" "4.2"
		string_verify_fn "NAMECHECK" "${PASSWORD_POLICY}" "YES" "=" "4.2"
		string_verify_fn "WHITESPACE" "${PASSWORD_POLICY}" "YES" "=" "4.2"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.3 Verify no UID 0 accounts exist other than the root. Root only should have UID value 0. " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	duplicate_uid_verify_fn "4.3"
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.4 Restrict root Login to System Console " | tee -a ${DATA_FILE}
	${ECHO_CMD} "--------------------------------------------------------------" | tee -a ${DATA_FILE}
	restrict_root_login_verify_fn "4.4"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.5 Remove user .netrc, .rhosts and .shosts files " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	rhosts_netrc_shosts_verify_fn "4.5"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.6 Set Default Umask for users set to 077 " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	string_verify_fn "umask" "${ETC_PROFILE}" "077" " " "4.6"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.7 Check That Users Are Assigned Home Directories " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	home_dir_verify_fn "4.7"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.8  Check for Duplicate UIDs " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	DID_verify_fn "UID" "4.8"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.9 Check for Duplicate GIDs " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	DID_verify_fn "GID" "4.9"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"
	${ECHO_CMD} " ## 4.10 Check all SA accounts { Reserved UIDs & GIDs  } are aligned to Group ID of sysadmin, which is 14"  | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	Check_reserved_ids_verify_fn "4.10"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.11 Check for Duplicate User Names " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	DID_verify_fn "USERNAME" "4.11"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.12 Check for Duplicate Group Names " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	DID_verify_fn "GROUPNAME" "4.12"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.13 Enable Session Timeout settings for user Logins - Check for Clientalive interval " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	string_verify_fn "ClientAliveInterval" "${SSH_CONFIG}" "600" " " "4.13"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.14  Disable root login for SSH " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	string_verify_fn "PermitRootLogin" "${SSH_CONFIG}" "no" " " "4.14"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.15  Set Retry Limit for Account Lockout  "  | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	if [ "${OS}" = "Linux" ] ; then
		string_verify_fn "password.*pam_cracklib.so.*retry=5" "${PAM_FILE}" "4.15"
	elif [ "${OS}" = "HP-UX" ] ; then
		string_verify_fn "AUTH_MAXTRIES" "${PASSWORD_POLICY}" "5" "=" "4.15" 
	elif [ "${OS}" = "SunOS" ] ; then	
		string_verify_fn "RETRIES" "${ETC_SECURETTY}" "5" "=" "4.15"
		string_verify_fn "LOCK_AFTER_RETRIES" "${SECURITY_POLICY}" "YES" "=" "4.15"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.16  Block known system users " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	lock_systemusers_verify_fn "www sys smbnull iwww owww sshd hpsmh uucp nuucp adm daemon bin lp hpdb nobody sfmdb tftp cimsrvr hpirs" "4.16"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5  Security Configuration Hardening   -  Disable Unnecessary Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.1 Disable NIS Server Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_NIS_server_verify_fn "5.1"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.2  Disable NIS Client Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_NIS_client_verify_fn "5.2"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.3  Disable Local-only send mail Service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_sendmail_verify_fn "5.3"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.4  Disable remote user commands (rlogin, rsh, rcp, rexec) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_remote_commands_verify_fn "5.4"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.5  Disable Rwall ,finger ,UUCP, TFTP, Telnet, FTP services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_unwanted_svcs_verify_fn "5.5"
	${ECHO_CMD} ""	 | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.6  Disable services  chargen-dgram, chargen-stream (LINUX)" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_chargen_verify_fn "5.6"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.7  Disable daytime-dgram , daytime-stream (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_daytime_verify_fn "5.7"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.8 Disable echo-dgram & echo-stream (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_echo_verify_fn "5.8"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.9 Disable tcpmux-server (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_tcpmux_verify_fn "5.9"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.10 Disable Login on Serial Ports (HP-UNIX)" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_login_on_serial_ports_verify_fn "5.10"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.11 Enable stack protection " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	enable_stack_protection_verify_fn "5.11"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.12 Disable the CDE GUI Login " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"	 | tee -a ${DATA_FILE}
	disable_CDE_GUI_verify_fn "5.12"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.13 Disable SNMP and OpenView Agents" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"
	disable_snmp_verify_fn "5.13"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.14 Enable Strong  random TCP sequence numbers " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	enable_random_strong_tcp_seq_verify_fn "5.14"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.15 Check for User FTP restrictions and no FTP access enabled for ROOT account " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	ps -eaf | grep -w ftp | grep -v grep >/dev/null
	if [ $? -eq 0 ] ; then
		restrict_ftp_user_verify_fn "5.15"
	else
		${ECHO_CMD} "\nCOMMAND: ps -eaf | grep -w ftp | grep -v grep\n" | tee -a ${DATA_FILE}
		${ECHO_CMD} "${NORM}CURRENT VALUE: AS PER EXPECTED VALUE, ftp is not running. No need to restrict users to ftp access${NORM}" | tee -a ${DATA_FILE}
		${ECHO_CMD} "${NORM}EXPECTED VALUE: No need to restrict users to ftp access if ftp is not running${NORM}" | tee -a ${DATA_FILE}
		${ECHO_CMD} "\nOUTPUT: `ps -eaf | grep -w ftp | grep -v grep`" | tee -a ${DATA_FILE}
		SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:5.15"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.16 Prevent Syslog from accepting messages from Network " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	prevent_syslog_verify_fn "5.16"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.17 Configure screen lock to lock after 600 seconds of inactivity " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	configure_screen_lock_verify_fn "5.17"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.19 Disable Avahi Server (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_avahi_verify_fn "5.19"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.20 Disable response to broadcast ping request " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	disable_broadcast_ping_response_verify_fn "5.20"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"	 | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.21 Configure the NTP service to act as a client only" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"	 | tee -a ${DATA_FILE}
	ntp_client_verify_fn "5.21"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6  Auditing and Logging  " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.1 Configure Sys log Auditing - Arch sight  " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	syslog_auth_verify_fn "6.1"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.2 Log all failed login attempts  " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"
	log_failed_login_attempts_verify_fn
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.3 Log all Switch User Logs " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	log_all_switch_user_verify_fn "6.3"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.4 Turn on the auditd daemon to record system events like user failed logins " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	enable_auditd_verify_fn	"6.4"
;;
repair)

	#call functions to verify all tasks in check-list . Display task no also
	#Write functions to implement each task in check-list except if any exceptions specified in the file. 	
	#read the exceptions file and don't run implementation section for the sections mentioned in that file

	# Create a exception file if it is not present
	if [ ! -f "${EXCEPTIONS_FILE}" ] ; then
		touch ${EXCEPTIONS_FILE}
	fi

	# Write functions for each task in the check-list to verify the functionality. Print section/task no also
	# Script shouldn't run the task if the task no is present in ${EXCEPTIONS_FILE}"
	#[ "${exception_no}" = "2.1" ] && { call verify fns ; } || {	call set fns ;}			
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 1. PATCHES AND ADDITIONAL SOFTWARE " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 1.1 Use the Latest Packages and Updates " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^1.10$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		kernel_version_fn "1.10"
	else
		kernel_version_fn "1.10"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2. FILES/DIRECTORY PERMISSIONS " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2.1 Verify file permissions of passwd, shadow and cron files " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^2.1$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		fileperm_verify_fn "-rw-r--r--" "root" "root" "${USER_FILE}" "644" "2.1"
		fileperm_verify_fn "-rw-r--r--" "root" "root" "${GROUP_FILE}" "644" "2.1"
		fileperm_verify_fn "-r--------" "root" "root" "${SHADOW_FILE}" "400" "2.1"
	else
		fileperm_set_fn "-rw-r--r--" "root" "root" "${USER_FILE}" "644" "2.1"
		fileperm_set_fn "-rw-r--r--" "root" "root" "${GROUP_FILE}" "644" "2.1"
		fileperm_set_fn "-r--------" "root" "root" "${SHADOW_FILE}" "400" "2.1"
	fi			
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2.2 Restrict at / cron to Authorized Users " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} "Check for at.allow,cron.allow,at.deny & cron.deny files: " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^2.2$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		fileperm_verify_fn "-r--------" "root" "root" "${AT_ALLOW}" "400" "2.2"
		fileperm_verify_fn "-r--------" "root" "root" "${CRON_ALLOW}" "400" "2.2"
		file_remove_fn "$AT_DENY" "2.2"
		file_remove_fn "$CRON_DENY" "2.2"
	else
		fileperm_set_fn "-r--------" "root" "root" "${AT_ALLOW}" "400" "2.2"
		fileperm_set_fn "-r--------" "root" "root" "${CRON_ALLOW}" "400" "2.2"
		file_remove_fn "${AT_DENY}" "2.2"
		file_remove_fn "${CRON_DENY}" "2.2"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 2.3 Check no NFS shares exported with root access and are authorized to specific hosts " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^2.3$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		nfs_share_verfy_access_fn "2.3"
	else
		nfs_share_set_access_fn "2.3"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3. Warning Banners " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.1 Create Warnings for Standard Login Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^3.1$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		banner_std_login_verify_fn "3.1"
	else
		banner_std_login_set_fn "3.1"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.2 Enable a Warning Banner for the SSH Service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^3.2$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		banner_ssh_ftp_verify_fn "banner" "${SSH_CONFIG}" "Property of Account_Name" " " "3.2"
	else
		banner_ssh_ftp_set_fn "banner" "${SSH_CONFIG}" "Property of Account_Name" " " "3.2"
	fi	
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.3 Enable a Warning Banner for the GNOME Service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^3.3$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		banner_GNOME_verify_fn "3.3"  
	else
		banner_GNOME_verify_fn "3.3"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.4 Enable a Warning Banner for the FTP service  " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^3.4$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		ps -eaf | grep -w ftp | grep -v grep >/dev/null
		if [ $? -eq 0 ] ; then
			banner_ssh_ftp_verify_fn "banner" "${FTP_BANNER}" "Property of Account_Name" " " "3.4"
		else
			${ECHO_CMD} "${NORM}CURRENT VALUE: AS PER EXPECTED VALUE, ftp is not running. No need to set banner msg${NORM}" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}EXPECTED VALUE: No need to set banner msg if ftp is not running${NORM}" | tee -a ${DATA_FILE}
			SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:3.4"
		fi
	else
		ps -eaf | grep -w ftp | grep -v grep >/dev/null
		if [ $? -eq 0 ] ; then
			banner_ssh_ftp_set_fn "banner" "${FTP_BANNER}" "Property of Account_Name" " " "3.4"
		else
			${ECHO_CMD} "\nCOMMAND: ps -eaf | grep -w ftp | grep -v grep\n" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}CURRENT VALUE: AS PER EXPECTED VALUE, ftp is not running. No need to set banner msg${NORM}" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}EXPECTED VALUE: No need to set banner msg if ftp is not running${NORM}" | tee -a ${DATA_FILE}
			${ECHO_CMD} "\nOUTPUT: `ps -eaf | grep -w ftp | grep -v grep`" | tee -a ${DATA_FILE}
			SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:3.4"
		fi	
	fi
	${ECHO_CMD} ""
	${ECHO_CMD} "----------------------------------------------------------------"  | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 3.5 Check that the Banner Setting for telnet is Null "
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^3.5$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		banner_TELNET_verify_fn "3.5"  
	else
		banner_TELNET_verify_fn "3.5"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4 User Accounts and Environment  " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.1 Verify that there are no accounts with empty password fields." | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"
	grep "^4.1$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		user_empty_password_verify_fn "4.1"
	else
		user_empty_password_set_fn "4.1"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.2 Set Strong Password Creation Policies " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.2$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		if [ ${OS} = "Linux" ] ; then
			set_strong_passwd_Linux_verify_fn "4.2"
		elif [ "${OS}" = "HP-UX" ] ; then	
			string_verify_fn "MIN_PASSWORD_LENGTH" "${PASSWORD_POLICY}" "8" "=" "4.2"
			string_verify_fn "PASSWORD_MIN_LOWER_CASE_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_verify_fn "PASSWORD_MIN_SPECIAL_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_verify_fn "PASSWORD_MIN_DIGIT_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_verify_fn "PASSWORD_MAXDAYS" "${PASSWORD_POLICY}" "175" "=" "4.2"
			string_verify_fn "PASSWORD_HISTORY_DEPTH" "${PASSWORD_POLICY}" "6" "=" "4.2"
			string_verify_fn "PASSWORD_WARNDAYS" "${PASSWORD_POLICY}" "30" "=" "4.2"
		elif [ "${OS}" = "SunOS" ] ; then	
			string_verify_fn "PASSLENGTH" "${PASSWORD_POLICY}" "8" "=" "4.2"
			string_verify_fn "MINALPHA" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_verify_fn "MINSPECIAL" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_verify_fn "MINDIGIT" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_verify_fn "MAXWEEKS" "${PASSWORD_POLICY}" "25" "=" "4.2"
			string_verify_fn "HISTORY" "${PASSWORD_POLICY}" "6" "=" "4.2"
			string_verify_fn "WARNWEEKS" "${PASSWORD_POLICY}" "4" "=" "4.2"
			string_verify_fn "WARNWEEKS" "${PASSWORD_POLICY}" "4" "=" "4.2"
			string_verify_fn "NAMECHECK" "${PASSWORD_POLICY}" "YES" "=" "4.2"
			string_verify_fn "WHITESPACE" "${PASSWORD_POLICY}" "YES" "=" "4.2"
		fi
	else
		if [ ${OS} = "Linux" ] ; then
			set_strong_passwd_Linux_set_fn "4.2"
		elif [ "${OS}" = "HP-UX" ] ; then	
			string_set_fn "MIN_PASSWORD_LENGTH" "${PASSWORD_POLICY}" "8" "=" "4.2"
			string_set_fn "PASSWORD_MIN_LOWER_CASE_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_set_fn "PASSWORD_MIN_SPECIAL_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_set_fn "PASSWORD_MIN_DIGIT_CHARS" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_set_fn "PASSWORD_MAXDAYS" "${PASSWORD_POLICY}" "175" "=" "4.2"
			string_set_fn "PASSWORD_HISTORY_DEPTH" "${PASSWORD_POLICY}" "6" "=" "4.2"
			string_set_fn "PASSWORD_WARNDAYS" "${PASSWORD_POLICY}" "30" "=" "4.2"
		elif [ "${OS}" = "SunOS" ] ; then	
			string_set_fn "PASSLENGTH" "${PASSWORD_POLICY}" "8" "=" "4.2"
			string_set_fn "MINALPHA" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_set_fn "MINSPECIAL" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_set_fn "MINDIGIT" "${PASSWORD_POLICY}" "1" "=" "4.2"
			string_set_fn "MAXWEEKS" "${PASSWORD_POLICY}" "25" "=" "4.2"
			string_set_fn "HISTORY" "${PASSWORD_POLICY}" "6" "=" "4.2"
			string_set_fn "WARNWEEKS" "${PASSWORD_POLICY}" "4" "=" "4.2"
			string_set_fn "WARNWEEKS" "${PASSWORD_POLICY}" "4" "=" "4.2"
			string_set_fn "NAMECHECK" "${PASSWORD_POLICY}" "YES" "=" "4.2"
			string_set_fn "WHITESPACE" "${PASSWORD_POLICY}" "YES" "=" "4.2"
		fi	
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "--------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.3 Verify no UID 0 accounts exist other than root " | tee -a ${DATA_FILE}
	${ECHO_CMD} "--------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.3$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		duplicate_uid_verify_fn "4.3"
	else
		duplicate_uid_set_fn "4.3"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "--------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.4 Restrict root Login to System Console " | tee -a ${DATA_FILE}
	${ECHO_CMD} "--------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.4$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		restrict_root_login_verify_fn "4.4"
	else
		restrict_root_login_set_fn "4.4"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.5 Remove user .netrc, .rhosts and .shosts files " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.5$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		rhosts_netrc_shosts_verify_fn "4.5"
	else
		rhosts_netrc_shosts_set_fn "4.5"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.6 Set Default Umask for users set to 077   " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.6$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		string_verify_fn "umask" "${ETC_PROFILE}" "077" " " "4.6"
	else
		string_set_fn "umask" "${ETC_PROFILE}" "077" " " "4.6"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.7 Check That Users Are Assigned Home Directories " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.7$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		home_dir_verify_fn "4.7"
	else
		home_dir_set_fn "4.7"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.8  Check for Duplicate UIDs " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"	 | tee -a ${DATA_FILE}	
	DID_verify_fn "UID" "4.8"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.9 Check for Duplicate GIDs " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	DID_verify_fn "GID" "4.9"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.10 Check all SA accounts { Reserved UIDs & GIDs  } are aligned to Group ID of sysadmin, which is 14"  | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"  | tee -a ${DATA_FILE}
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	grep "^4.10$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		Check_reserved_ids_verify_fn "4.10"
	else
		Check_reserved_ids_set_fn "4.10"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.11 Check for Duplicate User Names " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	DID_verify_fn "USERNAME" "4.11"	
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 4.12 Check for Duplicate Group Names " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} "Check for Duplicate Group Name" | tee -a ${DATA_FILE}
	DID_verify_fn "GROUPNAME" "4.12"
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.13 Enable Session Timeout settings for user Logins - Check for Clientalive interval " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.13$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		string_verify_fn "ClientAliveInterval" "${SSH_CONFIG}" "600" " " "4.13"
	else
		string_set_fn "ClientAliveInterval" "${SSH_CONFIG}" "600" " " "4.13"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.14  Disable root login for SSH " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.14$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		string_verify_fn "PermitRootLogin" "${SSH_CONFIG}" "no" " " "4.14"
	else
		string_set_fn "PermitRootLogin" "${SSH_CONFIG}" "no" " " "4.14"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.15  Set Retry Limit for Account Lockout " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.15$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		if [ "${OS}" = "Linux" ] ; then
			string_verify_fn "password.*pam_cracklib.so.*retry=5" "${PAM_FILE}" "4.15"
		elif [ "${OS}" = "HP-UX" ] ; then				
			string_verify_fn "AUTH_MAXTRIES" "${PASSWORD_POLICY}" "5" "=" "4.15"
		elif [ "${OS}" = "SunOS" ] ; then	
			string_verify_fn "RETRIES" "${ETC_SECURETTY}" "5" "=" "4.15"
			string_verify_fn "LOCK_AFTER_RETRIES" "${SECURITY_POLICY}" "YES" "=" "4.15"
		fi
	else
		if [ "${OS}" = "Linux" ] ; then
			egrep -q "^password.*pam_cracklib.so.*retry=5" "${PAM_FILE}" 
			if [ $? -eq 0 ] ; then
				${ECHO_CMD} "${NORM}CURRENT VALUE: retry limit is set as expected${NORM}" | tee -a ${DATA_FILE}
				${ECHO_CMD} "${NORM}EXPECTED VALUE: retry limit should be set as expected${NORM}" | tee -a ${DATA_FILE}
				SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:4.15"
			else
				string_set_fn "password    requisite     pam_cracklib.so try_first_pass retry=5 minlen=8,dcredit=-1,ucredit=-1,ocredit=-1 lcredit=-1 reject_username gecoscheck" "${PAM_FILE}" "4.15"
			fi
		elif [ "${OS}" = "HP-UX" ] ; then	 
			string_set_fn "AUTH_MAXTRIES" "${PASSWORD_POLICY}" "5" "=" "4.15"
		elif [ "${OS}" = "SunOS" ] ; then	
			string_set_fn "RETRIES" "${ETC_SECURETTY}" "5" "=" "4.15"
			string_set_fn "LOCK_AFTER_RETRIES" "${SECURITY_POLICY}" "YES" "=" "4.15" 
		fi
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ##4.16  Block known system users " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^4.16$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		lock_systemusers_verify_fn "www sys smbnull iwww owww sshd hpsmh uucp nuucp adm daemon bin lp hpdb nobody sfmdb tftp cimsrvr hpirs" "4.16"
	else
		lock_systemusers_set_fn "www sys smbnull iwww owww sshd hpsmh uucp nuucp adm daemon bin lp hpdb nobody sfmdb tftp cimsrvr hpirs" "4.16"		
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5  Security Configuration Hardening   -  Disable Unnecessary Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.1 Disable NIS Server Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.1$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_NIS_server_verify_fn "5.1"
	else
		disable_NIS_server_set_fn "5.1"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.2  Disable NIS Client Services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.2$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_NIS_client_verify_fn "5.2"
	else
		disable_NIS_client_set_fn "5.2"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.3  Disable Local-only send mail Service " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.3$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_sendmail_verify_fn "5.3"
	else
		disable_sendmail_set_fn "5.3"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.4  Disable remote user commands (rlogin, rsh, rcp, rexec) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.4$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_remote_commands_verify_fn "5.4"
	else
		disable_remote_commands_set_fn "5.4"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.5 Disable Rwall ,finger ,UUCP, TFTP, Telnet, FTP services " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.5$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_unwanted_svcs_verify_fn "5.5"
	else
		disable_unwanted_svcs_set_fn "5.5"
	fi
	${ECHO_CMD} ""	 | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.6 Disable services  chargen-dgram, chargen-stream (LINUX)" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.6$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_chargen_verify_fn "5.6"
	else
		disable_chargen_set_fn "5.6"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.7 Disable daytime-dgram , daytime-stream (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.7$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_daytime_verify_fn "5.7"
	else
		disable_daytime_set_fn "5.7"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.8  Disable echo-dgram & echo-stream (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.8$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_echo_verify_fn "5.8"
	else
		disable_echo_set_fn "5.8"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.9  Disable tcpmux-server (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.9$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_tcpmux_verify_fn "5.9"
	else
		disable_tcpmux_set_fn "5.9"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.10  Disable Login on Serial Ports (HP-UNIX)" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.10$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_login_on_serial_ports_verify_fn "5.10"
	else
		disable_login_on_serial_ports_set_fn "5.10"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.11  Enable stack protection " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.11$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		enable_stack_protection_verify_fn "5.11"
	else
		enable_stack_protection_set_fn "5.11"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.12  Disable the CDE GUI Login " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.12$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_CDE_GUI_verify_fn "5.12"
	else
		disable_CDE_GUI_set_fn "5.12"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.13  Disable SNMP and OpenView Agents" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.13$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_snmp_verify_fn "5.13"
	else
		disable_snmp_set_fn "5.13"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.14  Enable Strong  random TCP sequence numbers " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.14$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		enable_random_strong_tcp_seq_verify_fn "5.14"
	else
		enable_random_strong_tcp_seq_set_fn "5.14"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.15  Check for User FTP restrictions and no FTP access enabled for ROOT account " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.15$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		ps -eaf | grep -w ftp | grep -v grep >/dev/null
		if [ $? -eq 0 ] ; then
			restrict_ftp_user_verify_fn "5.15"
		else
			${ECHO_CMD} "\nCOMMAND: ps -eaf | grep -w ftp | grep -v grep\n" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}CURRENT VALUE: AS PER EXPECTED VALUE, ftp is not running. No need to restrict users to ftp access${NORM}" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}EXPECTED VALUE: No need to restrict users to ftp access if ftp is not running${NORM}" | tee -a ${DATA_FILE}
			SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:5.15"
			${ECHO_CMD} "\nOUTPUT: `ps -eaf | grep -w ftp | grep -v grep`" | tee -a ${DATA_FILE}
		fi
	else
		ps -eaf | grep -w ftp | grep -v grep >/dev/null
		if [ $? -eq 0 ] ; then
			restrict_ftp_user_set_fn "5.15"
		else
			${ECHO_CMD} "\nCOMMAND: ps -eaf | grep -w ftp | grep -v grep\n" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}CURRENT VALUE: AS PER EXPECTED VALUE, ftp is not running. No need to restrict users to ftp access${NORM}" | tee -a ${DATA_FILE}
			${ECHO_CMD} "${NORM}EXPECTED VALUE: No need to restrict users to ftp access if ftp is not running${NORM}" | tee -a ${DATA_FILE}
			SUCCESS_NUM_CHK="${SUCCESS_NUM_CHK}:5.15"
			${ECHO_CMD} "\nOUTPUT: `ps -eaf | grep -w ftp | grep -v grep`" | tee -a ${DATA_FILE}
		fi
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.16  Prevent Syslog from accepting messages from Network " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.16$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		prevent_syslog_verify_fn "5.16"
	else
		prevent_syslog_set_fn "5.16"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.17  Configure screen lock to lock after 600 seconds of inactivity " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.17$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		configure_screen_lock_verify_fn "5.17"
	else
		configure_screen_lock_set_fn "5.17"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.19  Disable Avahi Server (LINUX) " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.19$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_avahi_verify_fn "5.19"
	else
		disable_avahi_set_fn "5.19"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.20  Disable response to broadcast ping request " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^5.20$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		disable_broadcast_ping_response_verify_fn "5.20"
	else
		disable_broadcast_ping_response_set_fn "5.20"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"	 | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 5.21  Configure the NTP service to act as a client only" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------"	 | tee -a ${DATA_FILE}
	grep "^5.21$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		ntp_client_verify_fn "5.21"
	else
		ntp_client_set_fn "5.21"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6   Auditing and Logging " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.1  Configure Sys log Auditing . Arch sight  " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^6.1$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		syslog_auth_verify_fn "6.1"
	else
		syslog_auth_set_fn "6.1"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.2  Log all failed login attempts  " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^6.2$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		log_failed_login_attempts_verify_fn
	else
		log_failed_login_attempts_set_fn
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.3  Log all Switch User Logs " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^6.3$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		log_all_switch_user_verify_fn "6.3"
	else
		log_all_switch_user_set_fn "6.3"
	fi
	${ECHO_CMD} "" | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	${ECHO_CMD} " ## 6.4 Turn on the auditd daemon to record system events like user failed logins " | tee -a ${DATA_FILE}
	${ECHO_CMD} "----------------------------------------------------------------" | tee -a ${DATA_FILE}
	grep "^6.4$" ${EXCEPTIONS_FILE} >/dev/null 2>&1
	if [ $? -eq 0 ] ; then
		enable_auditd_verify_fn "6.4"
	else
		enable_auditd_set_fn "6.4"
	fi
;; 
esac
${ECHO_CMD} "" | tee -a ${DATA_FILE}
#########################################################################
# Call end message function.
#########################################################################
end_msg_fn