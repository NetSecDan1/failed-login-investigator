SELECT event_time, event_code, account, src_host, src_ip, failure_code, logon_type, dc_host
FROM   <catalog>.<schema>.v_auth_failures
WHERE  account = :account
  AND  event_time >= :start AND event_time < :end
ORDER  BY event_time
LIMIT  5000
