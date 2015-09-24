USE master;
GO

BEGIN TRY DROP PROCEDURE STIG_Audits END TRY BEGIN CATCH END CATCH;
GO

CREATE PROCEDURE STIG_Audits AS
-- Create a Queue
DECLARE @rc INT;
DECLARE @TraceID INT;
DECLARE @options INT = 6;             -- 6 specifies TRACE_FILE_ROLLOVER (2) and SHUTDOWN_ON_ERROR (4)
DECLARE @tracefile NVARCHAR(128) = $(traceFile);  
                                      -- Trace file location and beginning of file name (SQL Server adds a suffix)
DECLARE @maxfilesize BIGINT = $(maxFileSize);    -- Trace file size limit in megabytes
DECLARE @stoptime datetime = null;    -- do not stop
DECLARE @filecount INT = $(fileCount);          -- Number of trace files in the rollover set
EXEC @rc = SP_TRACE_CREATE 
	@TraceID output,
	@options,
	@tracefile,
	@maxfilesize,
	@stoptime,
	@filecount
;
IF (@rc != 0) GOTO Error;

-- Set the events:
DECLARE @on BIT = 1;

-- Logins are audited based on SQL Server instance
-- setting Audit Level stored in registry
-- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL.[#]\MSSQLServer\AuditLevel
-- Audit Login
-- Occurs when a user successfully logs in to SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 14, 1, @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 14, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 14, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 14, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 14, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 14, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 14, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 14, 64, @on; -- SessionLoginName
-- Audit Logout
-- Occurs when a user logs out of SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 15, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 15, 13, @on; -- Duration
EXEC SP_TRACE_SETEVENT @TraceID, 15, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 15, 15, @on; -- EndTime
EXEC SP_TRACE_SETEVENT @TraceID, 15, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 15, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 15, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 15, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 15, 64, @on; -- SessionLoginName
-- Audit Server Starts and Stops
-- Occurs when the SQL Server service state is modified.
EXEC SP_TRACE_SETEVENT @TraceID, 18, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 18, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 18, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 18, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 18, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 18, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 18, 64, @on; -- SessionLoginName
-- Audit Login Failed
-- Indicates that a login attempt to SQL Server from a client failed.
EXEC SP_TRACE_SETEVENT @TraceID, 20, 1, @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 20, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 20, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 20, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 20, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 31, @on; -- Error
EXEC SP_TRACE_SETEVENT @TraceID, 20, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 20, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 20, 64, @on; -- SessionLoginName
-- Audit Statement GDR Event
-- Occurs every time a GRANT, DENY, REVOKE for a statement
-- permission is issued by any user in SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 102, 1, @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 102, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 102, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 102, 19, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 102, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 102, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 102, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 102, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 102, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 102, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 102, 64, @on; -- SessionLoginName
-- Audit Object GDR Event
-- Occurs every time a GRANT, DENY, REVOKE for an object
-- permission is issued by any user in SQL Server.
EXEC SP_TRACE_SETEVENT @TraceID, 103, 1, @on; -- TextData
EXEC SP_TRACE_SETEVENT @TraceID, 103, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 103, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 103, 19, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 103, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 103, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 28, @on; -- ObjectType
EXEC SP_TRACE_SETEVENT @TraceID, 103, 34, @on; -- ObjectName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 37, @on; -- OwnerName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 39, @on; -- TargetUserName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 40, @on; -- DBUserName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 103, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 103, 44, @on; -- ColumnPermissions
EXEC SP_TRACE_SETEVENT @TraceID, 103, 59, @on; -- ParentName
EXEC SP_TRACE_SETEVENT @TraceID, 103, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 103, 64, @on; -- SessionLoginName
-- Audit AddLogin Event
-- Occurs when a SQL Server login is added or removed;
-- for sp_addlogin and sp_droplogin.
EXEC SP_TRACE_SETEVENT @TraceID, 104, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 104, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 104, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 104, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 104, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 104, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 104, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 104, 64, @on; -- SessionLoginName
-- Audit Login GDR Event
-- Occurs when a Windows login right is added or removed;
-- for sp_grantlogin, sp_revokelogin, and sp_denylogin.
EXEC SP_TRACE_SETEVENT @TraceID, 105, 6, @on; -- NTUserName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 7, @on; -- NTDomainName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 8, @on; -- HostName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 10, @on; -- ApplicationName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 11, @on; -- LoginName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 12, @on; -- SPID
EXEC SP_TRACE_SETEVENT @TraceID, 105, 14, @on; -- StartTime
EXEC SP_TRACE_SETEVENT @TraceID, 105, 23, @on; -- Success
EXEC SP_TRACE_SETEVENT @TraceID, 105, 26, @on; -- ServerName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 35, @on; -- DatabaseName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 41, @on; -- LoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 105, 42, @on; -- TargetLoginName
EXEC SP_TRACE_SETEVENT @TraceID, 105, 43, @on; -- TargetLoginSid
EXEC SP_TRACE_SETEVENT @TraceID, 105, 60, @on; -- IsSystem
EXEC SP_TRACE_SETEVENT @TraceID, 105, 64, @on; -- SessionLoginName
-- Audit Login Change Property Event
-- Occurs when a property of a login, except passwords,
-- is modified; for sp_defaultdb and sp_defaultlanguage.
EXEC SP_TRACE_SETEVENT @TraceID, 106, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 106, 64, @on;
-- Audit Login Change Password Event
-- Occurs when a SQL Server login password is changed.
-- Passwords are not recorded.
EXEC SP_TRACE_SETEVENT @TraceID, 107, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 107, 64, @on;
-- Audit Add Login to Server Role Event
-- Occurs when a login is added or removed from a fixed server role;
-- for sp_addsrvrolemember, and sp_dropsrvrolemember.
EXEC SP_TRACE_SETEVENT @TraceID, 108, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 38, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 108, 64, @on;
-- Audit Add DB User Event
-- Occurs when a login is added or removed as a database user
-- (Windows or SQL Server) to a database; for sp_grantdbaccess,
-- sp_revokedbaccess, sp_adduser, and sp_dropuser.
EXEC SP_TRACE_SETEVENT @TraceID, 109, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 21, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 38, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 44, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 51, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 109, 64, @on;
-- Audit Add Member to DB Role Event
-- Occurs when a login is added or removed as a database user
-- (fixed or user-defined) to a database; for sp_addrolemember,
-- sp_droprolemember, and sp_changegroup.
EXEC SP_TRACE_SETEVENT @TraceID, 110, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 38, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 110, 64, @on;
-- Audit Add Role Event
-- Occurs when a login is added or removed as a database user to a
-- database; for sp_addrole and sp_droprole.
EXEC SP_TRACE_SETEVENT @TraceID, 111, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 38, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 111, 64, @on;
-- Audit App Role Change Password Event
-- Occurs when a password of an application role is changed.
EXEC SP_TRACE_SETEVENT @TraceID, 112, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 38, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 112, 64, @on;
-- Audit Statement Permission Event
-- Occurs when a statement permission (such as CREATE TABLE) is used.
EXEC SP_TRACE_SETEVENT @TraceID, 113, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 19, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 113, 64, @on;
-- Audit Backup/Restore Event
-- Occurs when a BACKUP or RESTORE command is issued.
EXEC SP_TRACE_SETEVENT @TraceID, 115, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 115, 64, @on;
-- Audit DBCC Event
-- Occurs when DBCC commands are issued.
EXEC SP_TRACE_SETEVENT @TraceID, 116, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 44, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 116, 64, @on;
-- Audit Change Audit Event
-- Occurs when audit trace modifications are made.
EXEC SP_TRACE_SETEVENT @TraceID, 117, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 44, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 117, 64, @on;
-- Audit Object Derived Permission Event
-- Occurs when a CREATE, ALTER, and DROP object commands are issued.
EXEC SP_TRACE_SETEVENT @TraceID, 118, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 118, 64, @on;
-- Audit Database Management Event
-- Occurs when a CREATE, ALTER, or DROP statement executes on
-- database objects, such as schemas.
EXEC SP_TRACE_SETEVENT @TraceID, 128, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 128, 64, @on;
-- Audit Database Object Management Event
-- Occurs when a CREATE, ALTER, or DROP statement executes on
-- database objects, such as schemas.
EXEC SP_TRACE_SETEVENT @TraceID, 129, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 129, 64, @on;
-- Audit Database Principal Management Event
-- Occurs when principals, such as users, are created, altered, or
-- dropped from a database.
EXEC SP_TRACE_SETEVENT @TraceID, 130, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 130, 64, @on;
-- Audit Schema Object Management Event
-- Occurs when server objects are created, altered, or dropped.
EXEC SP_TRACE_SETEVENT @TraceID, 131, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 59, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 131, 64, @on;
-- Audit Server Principal Impersonation Event
-- Occurs when there is an impersonation within server scope, such
-- as EXECUTE AS LOGIN.
EXEC SP_TRACE_SETEVENT @TraceID, 132, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 132, 64, @on;
-- Audit Database Principal Impersonation Event
-- Occurs when an impersonation occurs within the database scope,
-- such as EXECUTE AS USER or SETUSER.
EXEC SP_TRACE_SETEVENT @TraceID, 133, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 38, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 133, 64, @on;
-- Audit Server Object Take Ownership Event
-- Occurs when the owner is changed for objects in server scope.
EXEC SP_TRACE_SETEVENT @TraceID, 134, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 134, 64, @on;
-- Audit Database Object Take Ownership Event
-- Occurs when a change of owner for objects within database scope
-- occurs.
EXEC SP_TRACE_SETEVENT @TraceID, 135, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 135, 64, @on;
-- Audit Change Database Owner
-- Occurs when ALTER AUTHORIZATION is used to change the owner of a
-- database and permissions are checked to do that.
EXEC SP_TRACE_SETEVENT @TraceID, 152, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 152, 64, @on;
-- Audit Schema Object Take Ownership Event
-- Occurs when ALTER AUTHORIZATION is used to assign an owner to an
-- object and permissions are checked to do that.
EXEC SP_TRACE_SETEVENT @TraceID, 153, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 59, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 153, 64, @on;
-- Audit Server Scope GDR Event
-- Indicates that a grant, deny, or revoke event for permissions in
-- server scope occurred, such as creating a login.
EXEC SP_TRACE_SETEVENT @TraceID, 170, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 19, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 170, 64, @on;
-- Audit Server Object GDR Event
-- Indicates that a grant, deny, or revoke event for a schema object,
-- such as a table or function, occurred.
EXEC SP_TRACE_SETEVENT @TraceID, 171, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 19, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 171, 64, @on;
-- Audit Database Object GDR Event
-- Indicates that a grant, deny, or revoke event for database
-- objects, such as assemblies and schemas, occurred.
EXEC SP_TRACE_SETEVENT @TraceID, 172, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 19, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 172, 64, @on;
-- Audit Server Operation Event
-- Occurs when Security Audit operations such as altering settings,
-- resources, external access, or authorization are used.
EXEC SP_TRACE_SETEVENT @TraceID, 173, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 173, 64, @on;
-- Audit Server Alter Trace Event
-- Occurs when a statement checks for the ALTER TRACE permission.
EXEC SP_TRACE_SETEVENT @TraceID, 175, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 175, 64, @on;
-- Audit Server Object Management Event
-- Occurs when server objects are created, altered, or dropped.
EXEC SP_TRACE_SETEVENT @TraceID, 176, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 45, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 46, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 176, 64, @on;
-- Audit Server Principal Management Event
-- Occurs when server principals are created, altered, or dropped.
EXEC SP_TRACE_SETEVENT @TraceID, 177, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 39, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 42, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 43, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 45, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 177, 64, @on;
-- Audit Database Operation Event
-- Occurs when database operations occur, such as checkpoint or
-- subscribe query notification.
EXEC SP_TRACE_SETEVENT @TraceID, 178, 1, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 6, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 7, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 8, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 10, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 11, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 12, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 14, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 23, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 26, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 28, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 34, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 35, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 37, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 40, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 41, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 60, @on;
EXEC SP_TRACE_SETEVENT @TraceID, 178, 64, @on;

-- Set the trace status to start.
EXEC SP_TRACE_SETSTATUS @TraceID, 1;

-- Display trace ID for future reference.
SELECT @TraceID AS TraceID;

GOTO Finish;
Error:
SELECT @rc AS ErrorCode;
Finish:
GO

EXEC SP_PROCOPTION 'STIG_Audits', 'startup', 'true';
GO