tell application "iTerm2"
create window with profile "bc" command "java -cp '.:gson-2.8.2.jar' Blockchain 0"
create window with profile "bc" command "java -cp '.:gson-2.8.2.jar' Blockchain 1"
create window with profile "bc" command "java -cp '.:gson-2.8.2.jar' Blockchain 2"
end tell
