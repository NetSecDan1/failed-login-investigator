SELECT count(*) AS events, max(event_time) AS newest
FROM   {view_entra_failures}
WHERE  event_time >= :start AND event_time < :end
