SELECT event_time, event_code, caller_host, actor
FROM   {view_account_events}
WHERE  account = :account
  AND  event_time >= :start AND event_time < :end
ORDER  BY event_time
LIMIT  1000
