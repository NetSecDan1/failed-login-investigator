SELECT count(*) AS events
FROM   {view_entra_failures}
WHERE  event_time >= :start AND event_time < :end
