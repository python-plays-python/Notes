https://www.holidayhackchallenge.com/2019/winners/salaheldin/helptheelves/challenge3/


1. ed editor > derivative of vi editor

2. commands to locate a file in linux

which 
find
locate

3. Powershell

Get-Content to view the content of the files

Get-ChildItem Env: to get the environment variable

Get-childItem will also get you the content of the folders
for ex-  `Get-ChildItem /etc -Recurse | sort LastWriteTime`

Expand-Archive to expand the archive - 
`Expand-Archive -Path /etc/apt/archive -DestinationPath /home/elf/archive`

Searching for an item by hash -

`Get-ChildItem -File -Recurse | Get-FileHash -Algorithm MD5 | Where-Object hash -eq 25520151A320B5B0D21561F92C8F6224 | Select-Object path`

Custom file finding

`Get-ChildItem -File -recurse | Select-Object FullName,@{Name="NameLength";Expression={$_.fullname.length}} | Sort-Object NameLength -Descending | Select-Object -first 1 | Format-Table -Wrap`

Get-Process
Stop-Process

4. Splunk

to search `index=main keyword`
example : `index=main sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational powershell EventCode=3`



