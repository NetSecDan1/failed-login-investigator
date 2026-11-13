SELECT event_time, error_code, client_app, app, src_ip
FROM   {view_entra_failures}
WHERE  account = :account
  AND  event_time >= :start AND event_time < :end
ORDER  BY event_time
LIMIT  5000
