SELECT count(*) AS events, count(DISTINCT dc_host) AS reporting_hosts, max(event_time) AS newest
FROM   {view_failed_logins}
WHERE  event_time >= :start AND event_time < :end
