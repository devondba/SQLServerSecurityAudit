/* Check SQL Logins for basic security measures */


WITH SQLLoginChecks
AS
(
	SELECT	SERVERPROPERTY('machinename') AS 'ServerName'
		,	ISNULL(SERVERPROPERTY('instancename'), SERVERPROPERTY('machinename')) AS 'InstanceName'
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

	SELECT  ServerName
		,	InstanceName
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
	FROM SQLLoginChecks
	ORDER BY Importance DESC;


