<#
.SYNOPSIS
Encryptes or Decrypts Strings or Byte-Arrays with AES
 
.DESCRIPTION
Takes a String or File and a Key and encrypts or decrypts it with AES256 (CBC)
 
.PARAMETER Mode
Encryption or Decryption Mode
 
.PARAMETER Key
Key used to encrypt or decrypt
 
.PARAMETER Text
String value to encrypt or decrypt
 
.PARAMETER Path
Filepath for file to encrypt or decrypt
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Text "Secret Text"
 
Description
-----------
Encrypts the string "Secret Test" and outputs a Base64 encoded cipher text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Decrypt -Key "p@ssw0rd" -Text "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs="
 
Description
-----------
Decrypts the Base64 encoded string "LtxcRelxrDLrDB9rBD6JrfX/czKjZ2CUJkrg++kAMfs=" and outputs plain text.
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin
 
Description
-----------
Encrypts the file "file.bin" and outputs an encrypted file "file.bin.aes"
 
.EXAMPLE
Invoke-AESEncryption -Mode Encrypt -Key "p@ssw0rd" -Path file.bin.aes
 
Description
-----------
Decrypts the file "file.bin.aes" and outputs an encrypted file "file.bin"
#>

param ([string]$cmd, [string]$secret, [string]$password)

function Invoke-AESEncryption {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Encrypt', 'Decrypt')]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path
    )

    Begin {
        # $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
        $aesManaged = New-Object System.Security.Cryptography.AesManaged
        $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
        #$aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aesManaged.BlockSize = 128
        $aesManaged.KeySize = 256
    }

    Process {
        $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))

        switch ($Mode) {
            'Encrypt' {
                if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}

                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $lastPlainByte = $plainBytes[$plainBytes.Length-1]
                    if ($lastPlainByte -eq 0)
                    {
                        Write-Warning -Message "Source file contains trailing zeros. File will not decrypt with same filehash!"
                    }
                    $outPath = $File.FullName + ".aes"
                }

                $encryptor = $aesManaged.CreateEncryptor()
                $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
                $encryptedBytes = $aesManaged.IV + $encryptedBytes
                $aesManaged.Dispose()

                if ($Text) {Write-Output -InputObject ([System.Convert]::ToBase64String($encryptedBytes))}

                if ($Path) {
                    if ($PSCmdlet.ShouldProcess($outPath, "write encrypted file")) {
                        [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                        (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    }
                    Write-Verbose -Message "File encrypted to $outPath"
                }
            }

            'Decrypt' {
                if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}

                if ($Path) {
                    $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                    if (!$File.FullName) {
                        Write-Error -Message "File not found!"
                        break
                    }
                    $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                    $outPath = $File.FullName -replace ".aes"
                }

                $aesManaged.IV = $cipherBytes[0..15]
                $decryptor = $aesManaged.CreateDecryptor()
                $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
                $aesManaged.Dispose()

                if ($Text) {Write-Output -InputObject ([System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0))}

                if ($Path) {
                    if ($PSCmdlet.ShouldProcess($outPath, "write decrypted file")) {
                        $indexOflastNonzero = $decryptedBytes.Length
                        while ($decryptedBytes[$indexOflastNonzero-1] -eq 0) { $indexoflastnonzero-- }
                        $deryptedBytesNoZeroPadding = [byte[]]::new($indexOflastNonzero)
                        [System.Array]::Copy($decryptedBytes,0,$deryptedBytesNoZeroPadding,0,$indexOflastNonzero)
                        [System.IO.File]::WriteAllBytes($outPath, ($deryptedBytesNoZeroPadding))
                        (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
                    }
                    Write-Verbose -Message "File decrypted to $outPath"
                }
            }
        }
    }

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
}
Function pause ($message)
{
    # Check if running Powershell ISE
    if ($psISE)
    {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show("$message")
    }
    else
    {
        Write-Host "$message" -ForegroundColor Yellow
        $x = $host.ui.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

switch($cmd){
   "encrypt" {
        echo "Encrypted string: "
        Invoke-AESEncryption -Mode Encrypt -Key $password -Text $secret
    }
   "decrypt" {
        echo "Decrypted string: "
        Invoke-AESEncryption -Mode Decrypt -Key $password -Text $secret
   }
}

#pause("Press any key to terminate")
