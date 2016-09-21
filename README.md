# SQLServerSecurityAudit
A script built for the SQL Server Community to allow simple security auditing of your SQL Servers.

So Far:

2016-09-20
The script uses sys.sql_logins to check SQL Server logins with PASSWORD EQUAL to the login name, logins without CHECK_POLICY enabled and logins without CHECK_EXPIRATION enabled.

Reference:
https://msdn.microsoft.com/en-us/library/bb283235.aspx (Securing SQL Server)

Brain dump ... Road Map:
Use T-SQL Scripts to audit the security of:

SQL Server Logins

SQL Users

SQL Databases

SQL Jobs

Bring scripts together to provide a uniform output with appropriate links for additional information.
Build SSRS report over the top to allow scheduled reporting and auiditing.
Wrap in PowerShell for simplistic multiple servers/instance audits.
Query active directory policies against MS best practices to see if the accounts used for SQL Server are appropriatly configured.
Check folder locations used by SQL server for permissions and potential risks.
