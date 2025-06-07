WITH FailedWrongNetwork AS (
  SELECT DISTINCT
    a.DeviceName,
    a.MACAddress
  FROM AuthEvents a
  JOIN AuthorizedDevices d ON a.DeviceName = d.DeviceName
  WHERE 
    a.AuthResult = 'Failure'
    AND a.NetworkName != d.AuthorizedNetwork
),

CorrectSuccess AS (
  SELECT 
    a.DeviceName,
    a.MACAddress,
    a.Timestamp AS SuccessTime,
    a.NetworkName
  FROM AuthEvents a
  JOIN AuthorizedDevices d ON a.DeviceName = d.DeviceName
  WHERE 
    a.AuthResult = 'Success'
    AND a.NetworkName = d.AuthorizedNetwork
)

SELECT 
  s.DeviceName,
  s.MACAddress,
  s.SuccessTime,
  s.NetworkName AS AuthorizedNetwork
FROM CorrectSuccess s
JOIN FailedWrongNetwork f ON s.DeviceName = f.DeviceName AND s.MACAddress = f.MACAddress;
