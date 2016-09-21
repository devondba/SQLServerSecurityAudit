/* Check SQL Logins for basic security measures */

--ensure we're clear
	IF OBJECT_ID('tempdb..#AuditResults') IS NOT NULL
	BEGIN
		DROP TABLE #AuditResults
	END

--Create results table
CREATE TABLE #AuditResults
							(	
									ServerName sysname
								,	InstanceName sysname
								,	LoginName sysname
								,	Issue varchar(200)
								,	Importance int
							);


--sql_logins check https://msdn.microsoft.com/en-us/library/ms174355.aspx
--sys.server_principals https://msdn.microsoft.com/en-us/library/ms188786.aspx

WITH SQLLoginChecks 
AS
(

	SELECT	CAST(SERVERPROPERTY('machinename')as sysname) AS 'ServerName'
		,	CAST(ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename'))as sysname) AS 'InstanceName'
		,	name AS LoginName
		,	PWDCOMPARE(name, password_hash) AS PasswordEqualsName
		,	is_policy_checked
		,	is_expiration_checked 
	FROM	master.sys.sql_logins
	WHERE	PWDCOMPARE(name, password_hash) = 1
			OR
			is_policy_checked = 0
			OR
			is_expiration_checked = 0
)

	INSERT INTO #AuditResults
	SELECT  CAST(ServerName as sysname) AS ServerName
		,	CAST(InstanceName as sysname) AS InstanceName
		,	LoginName
		,	CASE
				WHEN PasswordEqualsName = 1 AND is_policy_checked = 0 AND is_expiration_checked = 0 
					THEN 'Login with PASSWORD EQUAL to login name, without CHECK_POLICY enabled and without CHECK_EXPIRATION enabled.'
				WHEN PasswordEqualsName = 1 AND is_policy_checked = 0 
					THEN 'Login with PASSWORD EQUAL to login name and without CHECK_POLICY enabled.'
				WHEN PasswordEqualsName = 1 AND is_expiration_checked = 0
					THEN 'Login with PASSWORD EQUAL to login name and without CHECK_EXPIRATION enabled.'
				WHEN PasswordEqualsName = 1 
					THEN 'Login with PASSWORD EQUAL to login name.'
				WHEN is_policy_checked = 0 AND is_expiration_checked = 0
					THEN 'Login without CHECK_POLICY enabled and without CHECK_EXPIRATION enabled.'
				WHEN is_policy_checked = 0
					THEN 'Login without CHECK_POLICY enabled.'
				WHEN is_expiration_checked = 0
					THEN 'Login without CHECK_EXPIRATION enabled.'
			END As Issue
		,	CASE
				WHEN PasswordEqualsName = 1 AND is_policy_checked = 0 AND is_expiration_checked = 0 THEN 5000
				WHEN PasswordEqualsName = 1 AND is_policy_checked = 0 THEN 3000
				WHEN PasswordEqualsName = 1 AND is_expiration_checked = 0 THEN 2500
				WHEN PasswordEqualsName = 1 THEN 2000
				WHEN is_policy_checked = 0 AND is_expiration_checked = 0 THEN 1500
				WHEN is_policy_checked = 0 THEN 1000
				WHEN is_expiration_checked = 0 THEN 500
			END As Importance
				
		--,	PasswordEqualsName
		--,	is_policy_checked
		--,	is_expiration_checked
	FROM #SQLLoginChecks
	ORDER BY Importance DESC;

	/*
	SELECT *
	FROM #AuditResults
	*/

/*
--check for sysadmins
https://msdn.microsoft.com/en-us/library/ms188772.aspx
*/
	IF OBJECT_ID('tempdb..#SysAdmins') IS NOT NULL
	BEGIN
		DROP TABLE #SysAdmins
	END

	CREATE TABLE #SysAdmins (
									ServerRole SYSNAME
								,	MemberName SYSNAME
								,	MemberSID VARBINARY(85)
							)

	INSERT INTO #SysAdmins
	EXEC sp_helpsrvrolemember 'sysadmin'

	INSERT INTO #AuditResults
	SELECT		CAST(SERVERPROPERTY('machinename')as sysname) AS 'ServerName'
			,	CAST(ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename'))as sysname) AS 'InstanceName'
			,	MemberName AS	LoginName 
			,	'The user is a member of the sysadmins role, this user can do anything.' AS	Issue 
			,	400 AS	Importance 
	FROM #SysAdmins
	ORDER BY Importance DESC;


	SELECT *
	FROM #AuditResults
	ORDER BY Importance DESC;


/*
Check for default service accont
*/

	SELECT	servicename
		,	startup_type_desc
		,	service_account
	FROM	sys.dm_server_services
	WHERE	
			(
				servicename = 'SQL Server (MSSQLSERVER)'
				AND
				service_account = 'NT Service\MSSQLSERVER'
			)
			OR
			(
				servicename = 'SQL Server Agent (MSSQLSERVER)'
				AND
				service_account = 'NT Service\SQLSERVERAGENT'
			)
