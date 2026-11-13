SELECT event_time, event_code, failure_code, src_host, src_ip, dc_host, logon_type
FROM   {view_failed_logins}
WHERE  account = :account
  AND  event_time >= :start AND event_time < :end
ORDER  BY event_time
LIMIT  5000
