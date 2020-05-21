https://www.kaspersky.com/blog/signature-virus-disinfection/13233/

## Virus signatures 

 virus signature is a continuous sequence of bytes that is common for a certain malware sample. That means it’s contained within the malware or the infected file and not in unaffected files.

 Nowadays, signatures are far from sufficient to detect malicious files. Malware creators obfuscate, using a variety of techniques to cover their tracks. That’s why modern antivirus products must use more advanced detection methods. Antivirus databases still contain signatures (they account for more than half of all database entries), but they include more sophisticated entries as well.

 https://www.sciencedirect.com/topics/computer-science/virus-signature

 ## Network Antivirus concept w.r.t IDS

 Antivirus detects executable files. And to a lesser extent data files. A network antivirus inspects the file downloads in client to server flows. 

 Anti virus consists of - application protocol engine and pattern signature updates. decodes content file types as well as file transfer protocols.

 Antivirus provides engines for the following file transfer application protocols:

    HTTP (downloads, server-to-client flows) ICAP

    FTP (downloads, server-to-client flows)

    POP3 (download, server-to-client flows)

    IMAP (downloads, server-to-client flows)

    SMTP (uploads, client-to-server flows) ICAP

These engines decode the file transfer application protocol, and scan for files. Finding a file, they then decode file formats, unpacking and decompressing as needed, checking for virus signatures. 

Because the protocol engine must buffer the file, and this buffer must fit in memory, scanning is limited to small and medium-sized files. 

Content must be buffered and then reassembled before scanning, which might increase delay. This may be perceptible for interactive applications like HTTP.

## Malware protection

A running antivirus application will help to prevent viruses and other potential attacks from compromising the investigator’s equipment and evidence collected. 

1. The first and most prevalent technique uses antivirus signatures, which are … “a string of characters or numbers that makes up the signature that anti-virus programs are designed to detect. One signature may contain several virus signatures, which are algorithms or hashes that uniquely identify a specific virus”

Antivirus software searches for these signatures on the hard drive and removable media (including the boot sectors of the disks) and Random Access Memory.

2. Another method is heuristic analysis. In this approach, the antivirus software allows a suspected program to run in a controlled environment on the system before allowing it run on the user’s system








