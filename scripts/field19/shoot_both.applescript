on run argv
	set outdir to item 1 of argv
	set wid to (item 2 of argv) as integer
	set chromeprof to item 3 of argv
	tell application "System Events" to set visible of application process "Terminal" to false
	tell application "Safari"
		activate
		set w to (first window whose id is wid)
		set index of w to 1
		delay 1
		set b to bounds of w
		set firstOwned to (do shell script "cat /tmp/d2k-safari-owned-" & wid) as integer
		if firstOwned < 1 or (count of tabs of w) < firstOwned + 18 then error "Safari: owned tabs are missing"
		repeat with i from 1 to 19
			set current tab of w to tab (firstOwned + i - 1) of w
			delay 1.2
			do shell script "screencapture -x -l " & wid & " " & quoted form of (outdir & "/s" & i & ".png")
		end repeat
	end tell
	set pid to do shell script "pgrep -f 'Google Chrome --user-data-dir=" & chromeprof & "' | head -1"
	tell application "System Events"
		set p to first application process whose unix id is (pid as integer)
		set frontmost of p to true
		delay 1
		set wpos to position of window 1 of p
		set wsz to size of window 1 of p
		keystroke "1" using command down
		repeat with i from 1 to 19
			if i > 1 then key code 124 using {command down, option down}
			delay 1.2
			do shell script "screencapture -x -R" & (item 1 of wpos) & "," & (item 2 of wpos) & "," & (item 1 of wsz) & "," & (item 2 of wsz) & " " & outdir & "/c" & i & ".png"
		end repeat
	end tell
	tell application "System Events" to set visible of application process "Terminal" to true
	return "ok"
end run
