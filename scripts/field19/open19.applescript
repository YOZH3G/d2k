set urls to {"https://rutracker.org/", "https://fost.club/", "https://nnmclub.to/", "http://www.fast-torrent.ru/", "https://lostfilm.tv/", "https://kinozal.me/", "https://bible-center.ru/", "https://ru.numista.com/", "https://rua.gr/", "https://enimerosi.com/", "https://romfea.gr/", "https://katzauction.com/", "https://spzh.eu/ru/", "https://flibusta.is/", "https://web.facebook.com/", "https://adguard.com/", "https://mailsuite.com/", "https://cloudflare.com/", "https://speed.cloudflare.com/"}
tell application "Safari"
	set oldids to get id of every window
	set previous to missing value
	if (count of oldids) > 0 then set previous to get id of front window
	make new document with properties {URL:item 1 of urls}
	set newids to get id of every window
	set created to {}
	repeat with x in newids
		set xid to contents of x
		if xid is not in oldids then set end of created to xid
	end repeat
	if (count of created) is not 1 then error "Safari: new window identity is ambiguous"
	set wid to (item 1 of created) as integer
	set w to first window whose id is wid
	-- Pinned tabs are inherited by new windows. Only the new document and
	-- the tabs appended below belong to this run.
	set firstOwned to count of tabs of w
	do shell script "printf '%s\\n' " & firstOwned & " > /tmp/d2k-safari-owned-" & wid
	if previous is not missing value then set index of (first window whose id is previous) to 1
	repeat with i from 2 to count of urls
		tell w to make new tab with properties {URL:item i of urls}
		delay 1
	end repeat
	return wid
end tell
