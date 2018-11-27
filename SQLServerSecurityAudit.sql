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














--Elevated Permissions on a Database

	--need to execute against each database
	SELECT DISTINCT
		,	DB_NAME()
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

--Backing Up to Same Drive Where Databases Reside - need to check permissions on drive, only sql should write/delete, others can read

SELECT
										93 AS CheckID ,
										1 AS Priority ,
										'Backup' AS FindingsGroup ,
										'Backing Up to Same Drive Where Databases Reside' AS Finding ,
										'http://BrentOzar.com/go/backup' AS URL ,
										CAST(COUNT(1) AS VARCHAR(50)) + ' backups done on drive '
										+ UPPER(LEFT(bmf.physical_device_name, 3))
										+ ' in the last two weeks, where database files also live. This represents a serious risk if that array fails.' Details
								FROM    msdb.dbo.backupmediafamily AS bmf
										INNER JOIN msdb.dbo.backupset AS bs ON bmf.media_set_id = bs.media_set_id
																  AND bs.backup_start_date >= ( DATEADD(dd,
																  -14, GETDATE()) )
								WHERE   UPPER(LEFT(bmf.physical_device_name COLLATE SQL_Latin1_General_CP1_CI_AS, 3)) IN (
										SELECT DISTINCT
												UPPER(LEFT(mf.physical_name COLLATE SQL_Latin1_General_CP1_CI_AS, 3))
										FROM    sys.master_files AS mf )
								GROUP BY UPPER(LEFT(bmf.physical_device_name, 3))

Agent XPs
/*
				Believe it or not, SQL Server doesn't track the default values
				for sp_configure options! We'll make our own list here.
				*/
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'access check cache bucket count', 0, 1001 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'access check cache quota', 0, 1002 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'Ad Hoc Distributed Queries', 0, 1003 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'affinity I/O mask', 0, 1004 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'affinity mask', 0, 1005 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'affinity64 mask', 0, 1066 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'affinity64 I/O mask', 0, 1067 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'Agent XPs', 0, 1071 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'allow updates', 0, 1007 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'awe enabled', 0, 1008 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'backup checksum default', 0, 1070 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'backup compression default', 0, 1073 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'blocked process threshold', 0, 1009 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'blocked process threshold (s)', 0, 1009 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'c2 audit mode', 0, 1010 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'clr enabled', 0, 1011 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'common criteria compliance enabled', 0, 1074 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'contained database authentication', 0, 1068 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'cost threshold for parallelism', 5, 1012 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'cross db ownership chaining', 0, 1013 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'cursor threshold', -1, 1014 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'Database Mail XPs', 0, 1072 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'default full-text language', 1033, 1016 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'default language', 0, 1017 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'default trace enabled', 1, 1018 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'disallow results from triggers', 0, 1019 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'EKM provider enabled', 0, 1075 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'filestream access level', 0, 1076 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'fill factor (%)', 0, 1020 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'ft crawl bandwidth (max)', 100, 1021 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'ft crawl bandwidth (min)', 0, 1022 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'ft notify bandwidth (max)', 100, 1023 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'ft notify bandwidth (min)', 0, 1024 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'index create memory (KB)', 0, 1025 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'in-doubt xact resolution', 0, 1026 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'lightweight pooling', 0, 1027 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'locks', 0, 1028 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'max degree of parallelism', 0, 1029 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'max full-text crawl range', 4, 1030 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'max server memory (MB)', 2147483647, 1031 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'max text repl size (B)', 65536, 1032 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'max worker threads', 0, 1033 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'media retention', 0, 1034 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'min memory per query (KB)', 1024, 1035 );
				/* Accepting both 0 and 16 below because both have been seen in the wild as defaults. */
				IF EXISTS ( SELECT  *
							FROM    sys.configurations
							WHERE   name = 'min server memory (MB)'
									AND value_in_use IN ( 0, 16 ) )
					INSERT  INTO #ConfigurationDefaults
							SELECT  'min server memory (MB)' ,
									CAST(value_in_use AS BIGINT), 1036
							FROM    sys.configurations
							WHERE   name = 'min server memory (MB)'
				ELSE
					INSERT  INTO #ConfigurationDefaults
					VALUES  ( 'min server memory (MB)', 0, 1036 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'nested triggers', 1, 1037 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'network packet size (B)', 4096, 1038 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'Ole Automation Procedures', 0, 1039 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'open objects', 0, 1040 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'optimize for ad hoc workloads', 0, 1041 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'PH timeout (s)', 60, 1042 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'precompute rank', 0, 1043 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'priority boost', 0, 1044 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'query governor cost limit', 0, 1045 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'query wait (s)', -1, 1046 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'recovery interval (min)', 0, 1047 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'remote access', 1, 1048 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'remote admin connections', 0, 1049 );
				/* SQL Server 2012 changes a configuration default */
				IF @@VERSION LIKE '%Microsoft SQL Server 2005%'
					OR @@VERSION LIKE '%Microsoft SQL Server 2008%'
					BEGIN
						INSERT  INTO #ConfigurationDefaults
						VALUES  ( 'remote login timeout (s)', 20, 1069 );
					END
				ELSE
					BEGIN
						INSERT  INTO #ConfigurationDefaults
						VALUES  ( 'remote login timeout (s)', 10, 1069 );
					END
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'remote proc trans', 0, 1050 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'remote query timeout (s)', 600, 1051 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'Replication XPs', 0, 1052 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'RPC parameter data validation', 0, 1053 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'scan for startup procs', 0, 1054 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'server trigger recursion', 1, 1055 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'set working set size', 0, 1056 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'show advanced options', 0, 1057 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'SMO and DMO XPs', 1, 1058 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'SQL Mail XPs', 0, 1059 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'transform noise words', 0, 1060 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'two digit year cutoff', 2049, 1061 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'user connections', 0, 1062 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'user options', 0, 1063 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'Web Assistant Procedures', 0, 1064 );
				INSERT  INTO #ConfigurationDefaults
				VALUES  ( 'xp_cmdshell', 0, 1065 );


--sp_configure options changed
SELECT  cd.CheckID ,
										200 AS Priority ,
										'Non-Default Server Config' AS FindingsGroup ,
										cr.name AS Finding ,
										'http://BrentOzar.com/go/conf' AS URL ,
										( 'This sp_configure option has been changed.  Its default value is '
										  + COALESCE(CAST(cd.[DefaultValue] AS VARCHAR(100)),
													 '(unknown)')
										  + ' and it has been set to '
										  + CAST(cr.value_in_use AS VARCHAR(100))
										  + '.' ) AS Details
								FROM    sys.configurations cr
										INNER JOIN #ConfigurationDefaults cd ON cd.name = cr.name
										LEFT OUTER JOIN #ConfigurationDefaults cdUsed ON cdUsed.name = cr.name
																  AND cdUsed.DefaultValue = cr.value_in_use
								WHERE   cdUsed.name IS NULL;






/* check location of backup files is different to sql files*/

SELECT          physical_device_name,
                backup_start_date,
                backup_finish_date,
                backup_size/1024.0 AS BackupSizeKB
				,*
FROM	master.sys.databases d
		LEFT OUTER JOIN msdb.dbo.backupset b 
			ON d.NAME COLLATE SQL_Latin1_General_CP1_CI_AS = b.database_name COLLATE SQL_Latin1_General_CP1_CI_AS
			AND b.type = 'D'
			AND b.server_name = SERVERPROPERTY('ServerName') /*Backupset ran on current server */
		INNER JOIN msdb.dbo.backupmediafamily m ON b.media_set_id = m.media_set_id /*for locations of files */
WHERE	d.database_id <> 2 /* Bonus points if you know what that means */
		AND d.STATE NOT IN (
								1
							,	6
							,	10
							) /* Not currently offline or restoring, like log shipping databases */
		AND d.is_in_standby = 0 /* Not a log shipping target database */
		AND d.source_database_id IS NULL /* Excludes database snapshots */




