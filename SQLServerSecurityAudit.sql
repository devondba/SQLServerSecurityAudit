
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
				
	FROM SQLLoginChecks
	ORDER BY Importance DESC;


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

/*
Check for default service account
*/

	INSERT INTO #AuditResults
	SELECT		CAST(SERVERPROPERTY('machinename')as sysname) AS 'ServerName'
			,	CAST(ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename'))as sysname) AS 'InstanceName'
			,	service_account AS	LoginName 
			,	'Default service account in use.' AS	Issue 
			,	300 AS	Importance 
	FROM	sys.dm_server_services
	WHERE	service_account Like 'NT Service%' --'NT Service\MSSQLSERVER' etc for any service

/*
	Check login mode
*/
	IF OBJECT_ID('tempdb..#LoginConfig') IS NOT NULL
	BEGIN
		DROP TABLE #LoginConfig
	END

	CREATE TABLE #LoginConfig (
									name char(10)
								,	config_value char(25)
							)

	INSERT INTO #LoginConfig
	EXEC master.sys.xp_loginconfig 'login mode'

	--select * from #LoginConfig
	INSERT INTO #AuditResults
	SELECT		CAST(SERVERPROPERTY('machinename')as sysname) AS 'ServerName'
			,	CAST(ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename'))as sysname) AS 'InstanceName'
			,	'' AS	LoginName 
			,	config_value + ' Is in use.' + 
						CASE WHEN config_value = 'Windows NT Authentication' 
							THEN ' This is a best practice.'
							ELSE ' This is not a best practice.'
							END AS	Issue 
			,	CASE WHEN config_value = 'Windows NT Authentication' THEN 10 ELSE 350 END AS Importance
	FROM #LoginConfig


/*
	check config
	https://docs.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-configurations-transact-sql?view=sql-server-2017
*/

	IF OBJECT_ID('tempdb..#ConfigValues') IS NOT NULL
	BEGIN
		DROP TABLE #ConfigValues
	END
	IF OBJECT_ID('tempdb..#PreferedConfig') IS NOT NULL
	BEGIN
		DROP TABLE #PreferedConfig
	END


	Create TABLE #PreferedConfig (Name nvarchar(35),
									Prefered bit,
									Priority int
								)
	INSERT INTO #PreferedConfig
	VALUES	(N'cross db ownership chaining', 0, 200)
		,	(N'remote access', 0, 200)
		,	(N'show advanced options', 0, 200)	
		,	(N'remote proc trans', 0, 200)
		,	(N'remote admin connections', 1, 200)	
		,	(N'common criteria compliance enabled', 1, 200)	
		,	(N'filestream access level', 0, 200)	
		,	(N'Agent XPs', 0, 200)	
		,	(N'Database Mail XPs', 0, 200)	
		,	(N'SMO and DMO XPs', 0, 200)	
		,	(N'xp_cmdshell', 0, 200)	
		,	(N'default trace enabled', 1, 200)	
		,	(N'contained database authentication', 1, 200)	


	Create Table #ConfigValues (
								name nvarchar(35), 
								value_in_use sql_variant,
								Prefered bit,
								Priority int
								)
	
	INSERT INTO #AuditResults
	SELECT		CAST(SERVERPROPERTY('machinename')as sysname) AS 'ServerName'
			,	CAST(ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename'))as sysname) AS 'InstanceName'
			,	'    -----    ' AS	LoginName 
			,	'''' + sc.name + '''' + N' has a value of ' + cast(sc.value_in_use as nvarchar(30)) + N', the preference is ' + cast(pc.prefered as nchar(1)) + N'. This is informational only'
			,	CASE WHEN sc.value_in_use = pc.prefered THEN pc.priority ELSE pc.priority + 50 END AS Importance
	--SELECT sc.name, sc.value_in_use, pc.prefered, pc.priority
	FROM [sys].configurations sc
		INNER JOIN #PreferedConfig pc
		ON sc.name = pc.name

	--SELECT *
	--FROM #ConfigValues

	/*

		Logging Level Auditing
	*/

	IF OBJECT_ID('tempdb..#LogingLevelAudit') IS NOT NULL
	BEGIN
		DROP TABLE #LogingLevelAudit
	END

	CREATE TABLE #LogingLevelAudit (
									value char(10)
								,	audit tinyint
							)

	INSERT INTO #LogingLevelAudit
	EXEC xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel'

	--SELECT * FROM #LogingLevelAudit
	INSERT INTO #AuditResults
	SELECT		CAST(SERVERPROPERTY('machinename')as sysname) AS 'ServerName'
			,	CAST(ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename'))as sysname) AS 'InstanceName'
			,	'' AS	LoginName 
			,	'Login auditing is set to: ' + 
						CASE WHEN audit in (1,3)
							THEN 'None, this is not a best practice!'
							WHEN audit = 2
							THEN 'Failed logins only, this is the defult'
							WHEN audit = 3
							THEN 'Successful logins only'
							WHEN audit = 4
							THEN 'Both failed and successful logins'
							END AS	Issue 
			,	CASE WHEN audit in (1,3)
							THEN 500
							WHEN audit = 2
							THEN 10
							WHEN audit = 3
							THEN 400
							WHEN audit = 4
							THEN 10
							END AS Importance
	FROM #LogingLevelAudit

--Return the results

	SELECT *
	FROM #AuditResults
	ORDER BY Importance DESC;




/*

--Elevated Permissions on a Database

	--need to execute against each database
	SELECT DISTINCT
			DB_NAME()
		,	'Elevated Permissions'
		,	'In ' + DB_NAME() + ', user ' + u.NAME + '  has the role ' + g.NAME
		,	'This user has more rights than just data access.'
		,'db_owner'
		,'db_accessAdmin'
		,'db_securityadmin'
		,'db_ddladmin'
	FROM	dbo.sysmembers m
			INNER JOIN dbo.sysusers u
			ON m.memberuid = u.uid
			INNER JOIN sysusers g
			ON m.groupuid = g.uid
	WHERE	u.NAME <> 'dbo'
			AND g.NAME IN (
							'db_owner'
							,'db_accessAdmin'
							,'db_securityadmin'
							,'db_ddladmin'
							);

*/
