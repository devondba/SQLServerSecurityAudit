# SQLServerSecurityAudit
A script built for the SQL Server Community to allow simple security auditing of your SQL Servers.

2016-09-20
The script uses sys.sql_logins to check SQL Server logins with PASSWORD EQUAL to the login name, logins without CHECK_POLICY enabled and logins without CHECK_EXPIRATION enabled.

