# Get certificates
$fileFormat = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
$certs = Get-ChildItem -Path cert:\LocalMachine\Root
# Create export direcroty
New-Item -ItemType Directory -Path "C:\Exported Root Certificates" -ErrorAction SilentlyContinue
# Export certificates
foreach($cert in $certs)
{
    # Find a good file name
    $name = $cert.Subject
    $isMatched = $name -Match "CN=([a-zA-Z0-9\ \(\)\-\.]+)"
    if ($isMatched) 
    {
        $name = $matches[1]
    }
    else
    {
        $isMatched = $name -Match "OU=([a-zA-Z0-9\ \(\)\-\.]+)"
        if ($isMatched) 
        {
            $name = $matches[1]
        }
        else
        {
            echo "Could not extract certificate name from this subject:"
            echo $name
        }
    }
    # Write to file
    $path = "C:\Exported Root Certificates\" + $name + ".der"
    [System.IO.File]::WriteAllBytes($path, $cert.export($fileFormat) ) 
}
