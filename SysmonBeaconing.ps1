# Sysmon Beaconing Script
# Goes through all Event ID 3 and 22 events in the last day to look for beaconing.

$date = (get-date).adddays(-1)
$sysmonlogs = get-winevent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; starttime=$date; id=3,22}
$networkconnections = $sysmonlogs | Where-Object ID -eq 3
$dnsqueries = $sysmonlogs | Where-Object ID -eq 22

# Pulls out the Destination IP, Image, User, and Time from each ID 3 event.
$conarray = foreach ($con in $networkconnections) {
    $con = [xml]$con.ToXML()
    [PSCustomObject]@{
        DestinationIP = $con.Event.EventData.Data[14].'#text'
	    Image = $con.Event.EventData.Data[4].'#text'
	    User = $con.Event.EventData.Data[5].'#text'
	    Time = $con.Event.EventData.Data[1].'#text'
    }
}

# Pulls out the Parent Domain, Query, Image, and Time from each ID 22 event.
$dnsarray = foreach ($dns in $dnsqueries) {
    $dns = [xml]$dns.ToXML()
    $query = $dns.Event.EventData.Data[4].'#text'.split('.')
    [PSCustomObject]@{
        ParentDomain = $query[-2] + '.' + $query[-1]
	    Query = $dns.Event.EventData.Data[4].'#text'
	    Image = $dns.Event.EventData.Data[7].'#text'
	    Time = $con.Event.EventData.Data[1].'#text'
    }
}

# Groups and Sorts each array.  Users can figure out how they want to report and display from here.
$conarray | Group-Object destinationip,image | select count, name | sort count -Descending
$dnsarray | select parentdomain,query,image -Unique | Group-Object parentdomain,image | select count,name |sort count -Descending
