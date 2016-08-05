<#
// --------------------------------------------------------------------
//
//  Copyright (c) Microsoft Corporation.
//
// --------------------------------------------------------------------

ASR  VMWare to Hyper-V  Discover and Protect Workflow.
Linux Edition.



Prereq :
    Posh-SSH powershell module
    VMWare Powe CLI module
    ASR InMage Scout setup

#>

<#
Important notes for Linux disk mapping

Get-VHD --> get disk ID.
Linux --> ls /dev/disk/by-id -lt

match the last 12 chars of DiskID (get-VHD) to SCSI-XXXXXXXX(Last12). Get the device name in format /dev/sdx where X is a character.
Ensure /dev/sdx does not have any child devices in naming format such as /dev/sdxy , where y is a number.



Recreate partitions on /dev/sdx
configure multipath to ignore disk
run partprobe to update kernel partition view
mkfs.extx /dev/sdxy for linux partitions
mkswap /dev/dexy for swap volume

Checks : call fuser -v /dev/sdx to check for locking service

call protect and replicate API and perform device to device mapping in call.


#>
#############################################################################
<#Global variable for storing Scoutsetting object.
This object will be used for all specified functions below.
#>

          $ScoutSettings = New-Object PSObject
            $ScoutSettings | Add-Member -Type NoteProperty -Name CXServerIP -Value $null                         # CS Server IP
            $ScoutSettings | Add-Member -Type NoteProperty -Name PSServerIP -Value $null                         # Process server IP  
            $ScoutSettings | Add-Member -Type NoteProperty -Name AUTHMethod -Value "CXAuth"
            $ScoutSettings | Add-Member -Type NoteProperty -Name CXUserName -Value $null     
            $ScoutSettings | Add-Member -Type NoteProperty -Name CXPassword -Value $null     
            $ScoutSettings | Add-Member -Type NoteProperty -Name CXAccessSignature -Value $null     
            $ScoutSettings | Add-Member -Type NoteProperty -Name CXHTTPPort -Value "80"
            $ScoutSettings | Add-Member -Type NoteProperty -Name CXRequestPage -Value "/ScoutAPI/CXAPI.php"
            $ScoutSettings | Add-Member -Type NoteProperty -Name RestApiErrorCodes -Value ("304","400","403","409","411","412","413","416","500","503")
#############################################################################3
<#
Add supporting functions in this block

Index : Function Name : Description

#>



    
    #this function writes log to a specified output file.
    function Write-Log
    {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        [Parameter(Mandatory=$false)]
        [Alias('LogPath')]
        [string]$Path='C:\Logs\PowerShellLog.log',
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",
        
        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
        # Set VerbosePreference to Continue so that verbose messages are displayed.
        $VerbosePreference = 'SilentlyContinue'
    }
    Process
    {
        
        # If the file already exists and NoClobber was specified, do not write to the log.
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
            Return
            }

        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # Nothing to see here yet.
            }

        # Format Date for our Log File
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # Write message to error, warning, or verbose pipeline and specify $LevelText
        switch ($Level) {
            'Error' {
                Write-Verbose $Message
                $LevelText = 'ERROR:'
                }
            'Warn' {
                Write-Verbose $Message
                $LevelText = 'WARNING:'
                }
            'Info' {
                Write-Verbose $Message
                $LevelText = 'INFO:'
                }
            }
        
        # Write log entry to $Path
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
    }
    End
    {
    }
}

    
    # Get MD5 checksum from string. 
    Function Get-MD5Checksum() 
    { 
        param
                ( 
                [string]$StringInput=$(throw("You must specify a string as input.")) 
                ) 
        $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider 
        $utf8 = New-Object -TypeName System.Text.UTF8Encoding 
        return ([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($StringInput))).Replace("-", "")).tolower()
    } 


    Function Initialize-InMageProtectionEnvironment
    {

    Param
        (
            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings = $global:ScoutSettings
         )

    <#
            Error codes
            0 : no errors
            1 : failed to connect 
            2 : Posh-SSH module not found
            3 : Vmware CLI not found
        #>
    #Ensure Posh-SSH Module is present from powershell gallery. Requires PowerShell 4.0 and above
    try
    {
	    Import-module Posh-SSH
    }
    catch
    {
	    Write-Error "Error Locating PowerShell Posh-SSH  module."
        return 2
    }


    #Ensure PowerCLI is present
    try 
    {
	    #check if the VMWare Powershell .Net Libraries are loaded.	
        Add-PSSnapin VMware.VimAutomation.Core *>&1 | Out-Null
    }
    #Catch exception.
    catch{Write-error "VMWare PowerCLI binaries not available."
        return 3}
    
        # Initialize Temp directory for module
        $TMPPath =  $(Get-ChildItem env:temp).Value
        
         #Build the Server connection String
         $temp = "http://" + $ScoutSettings.CXServerIP + ":" + $ScoutSettings.CXHTTPPort + $ScoutSettings.CXRequestPage
         $ScoutSettings.CXRequestPage = $temp


         #Set the credentials objects
         $ScoutSettings.CXPassword = Get-MD5Checksum -StringInput $ScoutSettings.CXPassword


         #test Connection to CXServer
         $Response = (Invoke-WebRequest -Uri $ScoutSettings.CXRequestPage)
         if($Response.StatusCode -eq 200)
         {
            Write-host -ForegroundColor Green "InMage API Page at url $($CXRequestPage) connected with status code 200."
         }
         else
         {
            Write-Error "Error : Could not connect to url $($CXRequestPage)."
         }  

         #test connection to Process Server
         $Result = Test-Connection -ComputerName $ScoutSettings.PSServerIP -Quiet

         if ($result -eq $false)
         {
            Write-Error "Error connecting to PS Server IP address $($Scoutsettings.PSServerIP)."
            return 1
         }
         return $ScoutSettings
}

    #modifying to return error when IPaddress is not network reachable.
    Function Get-OSBuild
    {
    Param
    (
        [Parameter(Mandatory=$true)]
        #[ValidateScript({ Test-Connection $_ -quiet })]
        [string] $ComputerName,

        [Parameter(ParameterSetName='NoPrompt',Mandatory=$false)]
        [System.Management.Automation.Credential()] $OSCredential,

        [Int]$RPCPort = 445,
        [Int]$SSHPort = 22
    )

    #create custom object to store VM details


            $Object = New-Object PSObject
            $Object | Add-Member -Type NoteProperty -Name OSVersion -Value $null
            $Object | Add-Member -Type NoteProperty -Name OSArchitecture -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorMessage -Value $null
            $Object | Add-Member -Type NoteProperty -Name MachineType -Value $null

            <#
            Error codes
            0 : No errors.
            1 : Failed to connect to machine.
            2 : Unknown OS build.
            3 : Remote Powershell failed.
            4 : Remote WMI failed
            5 : Remote SSH failed
            6 : Machine is VMWare VM, but failed to connect to VI Server /VI server details are unavailable.
            7 : Failed to execute SSH command on remote host

            #>



            #test for Windows, test for RPC port


            $resultWin = Test-NetConnection -ComputerName $ComputerName -Port $RPCPort 
            #ping test must be sucessfull. Check for test on RPC port.
            if (($resultWin.TcpTestSucceeded -eq $true)  -and ($resultWin.PingSucceeded -eq $true))
            {
                ###RPC is open.
                ####Validate credentials and WSMAN works.
                try
                {
                    $SrcCmpPSSession = New-PSSession -Computer $ComputerName -Credential $OSCredential 
                }
                catch
                {
                    ###exception has happened. Store values and return to parent call
                    $Object.OSVersion = "Windows"
                    $object.OSArchitecture = "Unknown"
                    $object.ErrorCode = 3
                    $object.ErrorMessage = "Failed to remote powershell into remote computer.Please check WSMAN configuration and Credentials provided."
                    $object.MachineType = "Unknown"
                    return $Object
                }

                #try to get OS details and return back to parent call
                try
                {
                    $VMOSDetails = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -Credential $OSCredential 
                    $Object.OSVersion = (($VMOSDetails.Name).split("|"))[0]
                    $object.OSArchitecture = $VMOSDetails.OSArchitecture
                    $Object.ErrorCode = 0
                    $object.ErrorMessage = ""
                    #get remote computer motherboard. If Tag is VMWare/Microsoft, it is a VM
                    $VMOSMotherboard = Get-WmiObject Win32_ComputerSystem -ComputerName $ComputerName -Credential $OSCredential 
                    if ($VMOSMotherboard.Model -contains "*Virtual*")
                    {
                        $Object.MachineType = "Virtual"
                    }
                    else
                    {
                        $Object.MachineType = "Physical"
                    }


                    return $Object
                }

                catch
                {
                    ###exception has happened. Store values and return to parent call
                    $Object.OSDetails = "Windows"
                    $object.OSArchitecture = "Unknown"
                    $object.ErrorCode = 4
                    $object.ErrorMessage = "Failed to Call remote WMI procedure.Please check WMI,Firewall configuration and Credentials provided."
                    $object.MachineType = "Unknown"
                    return $Object
                }
            }

            #check for Linux
            $resultLin = Test-NetConnection -ComputerName $ComputerName -Port $SSHPort
            #ping test must be sucessfull. Check for test on SSH port.
            if (($resultLin.TcpTestSucceeded -eq $true)  -and ($resultWin.PingSucceeded -eq $true))
            {
                ###SSH is open.
                ###Open an SSH session and validate credentials
                try
                {
                    $SSHSession = New-SSHSession -ComputerName $computerName -Credential $OSCredential -AcceptKey -ConnectionTimeout 30
                    #get OS release name
                }

                catch
                {
                    #cannot connect to SSH. Possible cred or SSH port/service issue.
                    $Object.OSVersion = "Linux"
                    $object.OSArchitecture = "Unknown"
                    $object.ErrorCode = 5
                    $object.ErrorMessage = "Failed to Create SSH session to remote machine.Please check SSH service/port configuration and Credentials provided."
                    $object.MachineType = "Unknown"
                    return $Object
                }

                try
                {
                    #get OS release name
                    $SSHOutput = Invoke-SSHCommand -SSHSession $SSHSession -Command "cat /etc/system-release"
                    $op = $SSHOutput.Output
                    $Temp = $op.split(" ")
                    $OSName = $temp[0].Toupper()
                    $OSBuild = $Temp[2].Replace(".","U")
                    $Object.OSVersion = $OSName + $OSBuild
                

                    #get OS arch
                    $SSHOutput = Invoke-SSHCommand -SSHSession $SSHSession -Command "uname -m"
                    $OSArchitecture = $SSHOutput.Output

                    $Object.OSArchitecture = $OSArchitecture[0]
                    #Get OS machine type
                    $SSHOutput = Invoke-SSHCommand -SSHSession $SSHSession -Command "cat /sys/class/dmi/id/sys_vendor"
                    $OSVendorDetail = $SSHOutput.Output 
                    if  ( ($OSVendorDetail -like "*Microsoft*") -or ($OSVendorDetail -like "*VMWare*") -or ($OSVendorDetail -like "*KVM*") )
                    {
                        $Object.MachineType = "Virtual"
                    }
                    else
                    {
                        $Object.MachineType = "Physical"
                    }
                    $Object.ErrorCode = 0
                    return $Object
                }
                catch
                {
                    #cannot execute SSH command on remote Linux box.
                    $Object.OSVersion = "Linux"
                    $object.OSArchitecture = "Unknown"
                    $object.ErrorCode = 6
                    $object.ErrorMessage = "Failed to execute SSH commands on remote computer."
                    $object.MachineType = "Unknown"
                    return $Object

                }
            }
            else
            {
                $Object.ErrorCode = 2
                $Object.ErrorMessage =  "Unknown Machine Type"
                $Object.OSArchitecture = "Unknown"
                $Object.OSVersion = "Unknown"
                $Object.MachineType = "Unknwown"
                return $Object
            }

}


        Function Get-InMageAgentInstallationStatus
    {
            Param
            (
                [parameter(Mandatory=$True)]
                [ValidateScript({$_ -eq [ipaddress]$_})]
                [String]$MachineIP,

                [parameter(Mandatory=$False)]
                [PSObject]$ScoutSettings =$global:ScoutSettings
            )


###################################### XML body for REST calls.#################################3
#region
                [XML]$GetAgentInstallationXML=
                @'
<Request Id="0001" Version="1.0">
<Header>
    <Authentication>
		<AccessKeyID>A23FF8784CFE3F858A07B2CDEB25CBD27AA99808</AccessKeyID>
		<AuthMethod>CXAuth</AuthMethod>
		<CXUserName>admin</CXUserName>
		<CXPassword>5f4dcc3b5aa765d61d8327deb882cf99</CXPassword>
		<AccessSignature></AccessSignature>
	</Authentication> 
</Header>
<Body> 
<FunctionRequest Name="GetInstallationStatus" Include="No">
    <Parameter Name="HostIP1" Value="10.0.1.24" />  
</FunctionRequest>
</Body> 
</Request>
'@
#endregion

###################################################Get agent status
        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes


        $GetAgentInstallationXML.Request.Header.Authentication.CXUserName = $CXUserName
        $GetAgentInstallationXML.Request.Header.Authentication.CXPassword = $CXPassword

        #currently we are only supporting CSAuth method of authentication.
        if ($AuthMethod -eq "CXAuth")
        {
            $GetAgentInstallationXML.Request.Header.Authentication.AuthMethod = $AuthMethod
            #populate remaining code here iis required
        }
        else
        {
            ####################populate code for MessageAuth based authentication.
        }
    

        

        ($GetAgentInstallationXML.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "HostIP1"}).Value = $MachineIP
        #Push servers are common for all OS in this release of InMage Scout.
            try
            {
                $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $GetAgentInstallationXML -ContentType "text/xml"
            }
            catch
            {
                Write-Error "Failed to call 'Get agent installation status' Call  to API Url $($CXRequestPage)".
                return "Invalid"
            }

            #check for API call response.
            if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
            {
                Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
                return "Invalid"
            }
           
                $XML =   [XML]($Response.Content)
                $Status = $XML.Response.Body.Function
                $Code = ($Status | Where-Object {$_.Name -eq "GetInstallationStatus"}).ReturnCode
                #TODO : account for multiple PushServers being returned
            
                if ($Code -ne 0)
                {
                    return "Invalid"
                }
                Else
                {
                    $SubXML = $Status.FunctionResponse.ParameterGroup.Parameter
                    $Code = ($SubXML | Where-Object {$_.Name -eq "Status"}).Value
                    return $Code
                }

    }



    #TODO : functional testing    
    Function Install-InMageHostAgent
    {
        Param
        (
            [parameter(Mandatory=$True)]
            [ValidateScript({$_ -eq [ipaddress]$_})]
            [String]$MachineIP,


            [parameter(Mandatory=$False)]
            [ValidateSet("Windows","RHEL4-32","RHEL4-64","RHEL5-32","RHEL5U10-32","RHEL5-64","RHEL5U10-64","RHEL6-32","RHEL6-64","OL5-32","OL5-64","OL6-32","OL6-64","SLES10-32","SLES10-64","SLES10-SP1-32","SLES10-SP1-64","SLES10-SP2-32","SLES10-SP2-64","SLES10-SP3-32","SLES10-SP3-64","SLES10-SP4-32","SLES10-SP4-64","SLES11-32","SLES11-64","SLES11-SP1-32","SLES11-SP1-64","SLES11-SP2-32","SLES11-SP2-64","UBUNTU-10.04.4-64","Solaris-5-8-Sparc","Solaris-5-9-Sparc","Solaris-5-10-Sparc","Solaris-5-10-x86-64","Solaris-5-11-x86-64","OpenSolaris-5-11-Sparc","OpenSolaris-5-11-x86-64","AIX53","AIX61","AIX71")]
            [String]$HostOS = "Windows",

            [parameter(Mandatory=$True)]
            [System.Management.Automation.PSCredential]$HostCredential,

            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings =$global:ScoutSettings,

            [Parameter(Mandatory = $false)]
            [Validatescript({$_ -le 300})]
            [int]$TimeOut = 60,

            [switch]$WaitforCompletion
        )


            #Error Codes for install agent
            <#
                0 : Success/Completed
                1 : Pending
                2 : InProgress
                3 : Failed
                4 : Invalid
                6 : Push server not found
                7 : Agent Installation Timed out
                8 : Agent Push API failed to call
                9 : Agent installation Pending
                10 : Agent Installation Failed
                11 : Agent installation Timeout
                12 : Agent installation in progress
            #>
            
###################################### XML body for REST calls.#################################3
#region
    [XML]$InstallAgentXML = 
@'
<Request Id="0001" Version="1.0">
<Header>  
    <Authentication>
		<AccessKeyID>A23FF8784CFE3F858A07B2CDEB25CBD27AA99808</AccessKeyID>
		<AuthMethod>CXAuth</AuthMethod>
		<CXUserName>admin</CXUserName>
		<CXPassword>5f4dcc3b5aa765d61d8327deb882cf99</CXPassword>
		<AccessSignature></AccessSignature>
	</Authentication> 
</Header>
<Body>   
<FunctionRequest Name="InstallAgent" Include="No">      
    <ParameterGroup Id="InstallAgentList1">
        <Parameter Name="HostIP" Value="10.0.6.44"/>
        <Parameter Name="OS" Value="Windows"/>
        <Parameter Name="Username" Value="administrator"/>
        <Parameter Name="Password" Value="inScott!"/>
        <Parameter Name="Domain" Value="dev-domain"/>
        <Parameter Name="PushServerId" Value="EF91F507-E8AD-7543-96881ACC71DADCF9"/>		
        <Parameter Name="CSIP" Value="10.0.1.94"/>		
        <Parameter Name="CXPort" Value="443"/>		
    </ParameterGroup>
</FunctionRequest> 
</Body> 
</Request>
'@


    [XML]$GetPushServerXML=
@'
<Request Id="0001" Version="1.0">
<Header>  
    <Authentication>
		<AccessKeyID>A23FF8784CFE3F858A07B2CDEB25CBD27AA99808</AccessKeyID>
		<AuthMethod>CXAuth</AuthMethod>
		<CXUserName>admin</CXUserName>
		<CXPassword>5f4dcc3b5aa765d61d8327deb882cf99</CXPassword>
		<AccessSignature></AccessSignature>
	</Authentication> 
</Header>
<Body> 
	<FunctionRequest Name="ListPushServers">
		<Parameter Name="PushServerOSType" Value="All"/>
	</FunctionRequest>
</Body>
</Request>
'@


#endregion
######################################## Create custom objects######################################
#region
        #custom object creation
            $Object = New-Object PSObject
            $object | Add-Member -Type NoteProperty -Name HostGUID -Value $null
            $object | Add-Member -Type NoteProperty -Name HostIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : Success/Completed",
                "1 : Pending",
                "2 : InProgress",
                "3 : Failed",
                "4 : Invalid",
                "6 : Push server not found",
                "7 : Agent Installation Timed out",
                "8 : Agent Push API failed to call",
                "9 : Agent installation Pending",
                "10 : Agent Installation Failed",
                "11 : Agent installation Timeout",
                "12 : Agent installation in progress")
#endregion
######################################Code section to build the XML 
        #region


        $Temp = $InstallAgentXML.Clone()
        $Temp2 = $GetPushServerXML.Clone()
        

        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes



        Write-verbose "Commencing Installation of agent for Host : $($HostIP) for OS type : $($HostOS)"
        #Populate Request header for Temp1, Temp2, Temp3 XML 

        #region
        $Temp.Request.Header.Authentication.CXUserName = $CXUserName
        $Temp.Request.Header.Authentication.CXPassword = $CXPassword

        $Temp2.Request.Header.Authentication.CXUserName = $CXUserName
        $Temp2.Request.Header.Authentication.CXPassword = $CXPassword
        #currently we are only supporting CSAuth method of authentication.
        if ($AuthMethod -eq "CXAuth")
        {
            $Temp.Request.Header.Authentication.AuthMethod = $AuthMethod
            $Temp2.Request.Header.Authentication.AuthMethod = $AuthMethod
            #populate remaining code here iis required
        }
        else
        {
            ####################populate code for MessageAuth based authentication.
        }
        


        ##############################populate required parameters for Request Body
        
        
            $HostUserName = $HostCredential.GetNetworkCredential().UserName
            $HostPassword = $HostCredential.GetNetworkCredential().Password
            $Domain = $HostCredential.GetNetworkCredential().Domain

            if ([string]::IsNullOrEmpty($Domain))
            {
                $Domain = "."
            }

            #Push servers are common for all OS in this release of InMage Scout.
            try
            {
                $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp2 -ContentType "text/xml"
            }
            catch
            {
                Write-Error "Failed to call 'ListPushservers' Call  to API Url $($CXRequestPage)".
                $Object.ErrorCode = 6
                $Object.Message = "Failed to get PushServer details from CS Server. Please ensure Scout Infrastructure is working." 
                $Object.HostIP = $MachineIP
                $object.HostGUID = "N/A"
                return $Object
            }

            #Write-Debug "Output Response to GetPushServer: $Response.Content"

            #check for API call response.
            if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
            {
                Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
                $Object.ErrorCode = 6
                $Object.Message = "The REST Api call failed with error : $($Response.StatusDescription)." 
                $Object.HostIP = $MachineIP
                return $object
            }
            else
            {
                $XML =   [XML]($Response.Content)
                $PushServerID = ($XML.Response.Body.Function.FunctionResponse.ParameterGroup.Parameter | Where-Object {$_.Name -eq "PushServerId"}).Value
                #TODO : account for multiple PushServers being returned
            }


                #Populate Agent Push details           
                #set the values

            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "HostIP"}).Value = $MachineIP
            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "OS"}).Value = $HostOS
            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "Username"}).Value = $HostUserName
            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "Password"}).Value = $HostPassword
            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "PushServerId"}).Value = $PushServerID
            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "CSIP"}).Value = $CXServerIP
            ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "CXPort"}).Value = $CXHttpPort

            if($HostOS -eq "Windows")
            {
                ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "Domain"}).Value = $Domain
            }
            else
            {
                ($temp.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "Domain"}).Value = ""
            }
        
        #endregion
        #Write-Debug $Temp.OuterXml
        
        #############################call Web request API
        #region
        try
        {
            $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp -ContentType "text/xml"
        }
        catch
        {
                $Object.ErrorCode = 8
                $Object.Message = "Failed to get Call Installagent API to CS Server. Please ensure Scout Infrastructure is working." 
                $Object.HostIP = $MachineIP
                $object.HostGUID = "N/A"
                Write-Error "Failed to call Agent installation  call to API Url $($CXRequestPage)".
                return $Object
        }

       # Write-Debug "Output Response : $Response.Content"

        

        
        ########################check for API call response.
        if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
        {
            Write-Error "The REST Api call failed with error : $($Response.StatusDescription)."
            $Object.ErrorCode = 8
            $object.Message = "Error : InstallAgentAPI failed to call on API Url : $($CXRequestPage)"
            $object.HostIP = $MachineIP
            return $Object
        }
        else  # else .... check response and proceed with ops.
        {
           $Returnvalue = [xml]($Response.Content)    
           #create a custom object to store error code and message
       
            <#     
            API error code

            3001	Installation already initiated
            3002	No Push Server registered with CS
            3003	No Push Client found
            3004	Agent Build not Found in CS
                       
            #>
            
            #check for API call status
            $ReturnCode = ($Returnvalue.Response.Body.Function).Returncode 
            if ($ReturnCode -ne 0)
            {
                $object.ErrorCode = 3
                $object.Message = ($Returnvalue.Response.Body.Function).Message
                $object.HostIP = $MachineIP
                return $Object
            }
            
            #else   continue to next block to wait for installation to complete.              
       }     

       #endregion 



#################################Code section to validate agent installation status
#Wait for specified threshold and check if the agent is installed or not.
#On Timeout, return error code and agent installation status

#region

            if ($WaitforCompletion -eq $false)
            {
                #return the Installation status object immediately
                Write-Verbose "Returning Output Object."
                Write-verbose $Returnvalue
                $Object.ErrorCode = 12
                $Object.HostIP = $MachineIP
                $Object.Message = "Agent installation initiated on Target $machineIP"
                
                #return the Object
                return $object                
                
            }
            else
            {
                Write-Verbose "Installation started on HostIP : $MachineIP"

                #initialize Counter
                $Threshold = New-TimeSpan -Seconds $TimeOut
                $secondCounter = [diagnostics.stopwatch]::StartNew()
                while ($secondCounter.elapsed -le $Threshold)
                {
                    $status = Get-InMageAgentInstallationStatus -MachineIP $MachineIP -ScoutSettings $ScoutSettings
                    If ( ($status -eq "Failed")  -or (($status -eq "Invalid")) )
                    {
                        #exit function with error message.
                        $Object.ErrorCode = 10
                        $Object.Message = "Agent installation failed with message : $Status.Message"
                        $object.HostIP = $MachineIP
                        Return $object 
                    }
                    If ($status -eq "Completed")
                    {
                        #exit function with Success message.
                        $Object.ErrorCode = 0
                        $Object.Message = "Agent installation Successful with message : $Status.Message"
                        $object.HostIP = $MachineIP

                        #get the Agent GUID and populate the Return Object
                        $hostAgent = List-InMageRegisteredHosts -MachineIP $MachineIP -ScoutSettings $ScoutSettings
                        $Object.HostGUID = $hostAgent.HostAgentGUID
                        Return $object
                    }

                }

                 #check if installation status is still incomplete/failed/pending even after timeout.
                 #store appropiate messages and return to user.
                    if (($secondCounter.elapsed -gt $Threshold) )
                    {
                        if ($status -eq "Pending")    
                        {
                            $Object.ErrorCode = 9
                            $Object.Message  = "Installation is still pending on Target IP."
                            $object.HostIP = $MachineIP
                            Return $object 
                        }
                        If ($status -eq "Completed")
                        {
                            #exit function with Success message.
                            $Object.ErrorCode = 0
                            $Object.Message = "Agent installation Successful with message : $Status.Message"
                            $object.HostIP = $MachineIP
                            #get the Agent GUID and populate the Return Object
                            $hostAgent = List-InMageRegisteredHosts -MachineIP $MachineIP -ScoutSettings $ScoutSettings
                            $Object.HostGUID = $hostAgent.HostAgentGUID
                            Return $object 
                        }
                        if ($status -eq "InProgress")    
                        {
                            $Object.ErrorCode = 2
                            $Object.Message  = "Installation is still Progressing on Target IP."
                            $object.HostIP = $MachineIP
                            Return $object 
                        }
                        else
                        {
                            $Object.ErrorCode = 3
                            $Object.Message  = "Agent Installation Failed."
                            $object.HostIP = $MachineIP
                            Return $object 
                        }  
                    }
           }   
}



    Function List-InMageRegisteredHosts
    {
       Param
       (
        #[ValidateNotNullOrEmpty()]
        [String]$MachineIP = $null,

        #[ValidateNotNullOrEmpty()]
        [String]$MachineGUID = $null,
        
        [parameter(Mandatory=$false)]
        [PSObject]$ScoutSettings = $global:ScoutSettings
       )

        #assign values to variables for CX Server connectivity

        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes



        [xml]$Temp =  @'
<Request Id="0001" Version="1.0">
<Header>  
  <Authentication>
		<AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
		<AuthMethod>CXAuth/MessageAuth</AuthMethod>
		<CXUserName>admin</CXUserName>
		<CXPassword>5f4dcc3b5aa765d61d8327deb882cf99</CXPassword>
		<AccessSignature></AccessSignature>
	</Authentication>   
</Header>
<Body>
<FunctionRequest Name="ListHosts" Include="No"/>
</Body>
</Request>
'@

        $Temp.Request.Header.Authentication.CXUserName = $CXUserName
        $Temp.Request.Header.Authentication.CXPassword = $CXPassword

        #currently we are only supporting CSAuth method of authentication.
        if ($AuthMethod -eq "CXAuth")
        {
            $Temp.Request.Header.Authentication.AuthMethod = $AuthMethod
            #populate remaining code here iis required
        }
        else
        {
            #populate code for MessageAuth based authentication.
        }
        #call Web request
        try
        {
            $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp -ContentType "text/xml"
        }
        catch
        {
            Write-Error "Failed to call List Registered Hosts detail call to API Url $($CXRequestPage)".
        }



        #check for API call response.
        if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
        {
            Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
        }
        else
        {
            #all clean. Return response value.
            $ResponseValue = [XML]($Response.Content)
            #create a custom object
            $Object = New-Object PSObject
            $object | Add-Member -Type NoteProperty -Name HostIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name HostName -Value $null
            $Object | Add-Member -Type NoteProperty -Name HostAgentGUID -Value $null

            Write-Verbose "Found $($ResponseValue.Response.Body.Function.FunctionResponse.ParameterGroup.Count) Values from InMage server URL $($CXRequestPage)"

            $ReturnObject = @()
            foreach ( $entry in $ResponseValue.Response.Body.Function.FunctionResponse.ParameterGroup)
            {
                $ObjTemp = $Object | select *
                $ObjTemp.HostAgentGUID = ($entry.Parameter | Where-Object {$_.Name -eq "HostAgentGUID"}).Value
                $ObjTemp.HostIP = ($entry.Parameter | Where-Object {$_.Name -eq "HostIP"}).Value
                $ObjTemp.HostName = ($entry.Parameter | Where-Object {$_.Name -eq "HostName"}).Value
                $ReturnObject += $ObjTemp
            }


            if ([string]::IsNullOrEmpty($MachineIP) -eq $false)
            {
               $filterObject = $ReturnObject | Where-Object {$_.HostIP -eq $MachineIP}
               return $filterObject
            }
            
            elseif ([string]::IsNullOrEmpty($MachineGUID) -eq $false)
            {
               $filterObject = $ReturnObject | Where-Object {$_.HostAgentGUID -eq $MachineGUID}
               return $filterObject
            }
            
            else
            {
                #return the Object
                return $ReturnObject
            }
        }

    }


    #Update code to trigger auto refresh agent information in Scout before retrieving the information
    #update 1 : Code updated to trigger autorefresh Scout Cache before calling GetHostInfo
    #Update 2 : Seperated the Autorefresh code to seperate function to prevent un-necessary processing delays.
    Function Get-InMageHostDetails
    {
        <#
        Error Codes
        0 : Success
        1 : No Matching Host found.
        3 : Failed to connect to CX Server
        4 : Failed to execute REST API call.
        #>       




        Param
        (
            [parameter(Mandatory=$False)]
            [String]$MachineIP,

            [parameter(Mandatory=$false)]
            [PSObject]$ScoutSettings = $global:ScoutSettings
        )


        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes


        #XML file for retrieving Host information
        [xml]$RequestXML = @'
        <Request Id="0001" Version="1.0">
<Header>
	<Authentication> 
	    <AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
	    <AccessSignature></AccessSignature>
    </Authentication> 
</Header>
<Body> 
	<FunctionRequest Name="GetHostInfo" Include="Yes">
      	<Parameter Name="HostGUID" Value="cf9b6bc7-fad6-4ffe-94f5-b9a578b85457" />
		<Parameter Name="InformationType" Value="All" />    
	</FunctionRequest>
</Body> 
</Request>
'@


        #create custom object
        #create a custom object
            $Object = New-Object PSObject
            $object | Add-Member -Type NoteProperty -Name HostIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name HostGUID -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name HostDetailsXML -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : Success","1 : No Matching Host found.","3 : Failed to connect to CX Server","4 : Failed to execute REST API call.")

        Write-verbose "Retrieving Host Details for Machine  : $($MachineIP)"
        $FilteredHost = List-InMageRegisteredHosts -ScoutSettings $ScoutSettings -MachineIP $MachineIP      
        
        if ($FilteredHost -eq $null)
        {
            $Object.ErrorCode = 1
            $Object.HostIP = $MachineIP
            $object.Message = "No Host found in Scout Database with specified IP :$MachineIP"
            return $object
        }

        #endregion

      
            #call Web request
            try
            {
                
                ($RequestXML.Request.Body.FunctionRequest.Parameter | Where-object {$_.Name -eq "HostGUID"}).Value = $FilteredHost.HostAgentGUID
                $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $RequestXML -ContentType "text/xml"
            }
            catch
            {
                Write-Error "Failed to call GetHostInfo to API Url : $($CXRequestPage)"
                $Object.ErrorCode = 4
                $Object.Message = "Failed to execute 'GetHostInfo' API Call."
                $Object.HostIP = $MachineIP
                $Object.HostDetailsXML = $Response.Message
                return $Object
            }    
 
 
            
            $HostDetails = [xml]$Response.Content
            $Object.HostDetailsXML = $hostDetails.Response.Body.Function.FunctionResponse.OuterXml
            $Object.ErrorCode = 0
            $Object.Message = "Retrieved host details successfully."
            $Object.HostIP = $MachineIP
            $Object.HostGUID = $FilteredHost.HostAgentGUID
            return $Object
        
        
    }


    #Function triggers host info refresh on specified IP address.
    #The function may take upto 30 seconds to force an update of information on to CS Server. Change timeout via provided input.
    #The Machine agent must be online and should be able to communicate with CS server.



    Function Sync-InMageHostDetails
    {
        <#
        Error Codes
        0 : Success
        1 : No Matching Host found.
        3 : Failed to connect to CX Server
        4 : Failed to execute REST API call.
        5 : Host info refresh failed.
        6 : Host info refresh operation timed out.
        #>       




        Param
        (
            [parameter(Mandatory=$true)]
            [String]$MachineIP,

            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings = $global:ScoutSettings,

            [parameter(Mandatory=$False)]
            [int]$TimeoutSeconds = 30
        )

        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes




        #XML file for triggering Scout agent information refresh from Agent host.

        [XML]$RefreshHostInfo =   @'
<Request Id="0009" Version="1.0"> 
<Header> 
	<Authentication>   
		<AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
	    <AccessSignature></AccessSignature>
	</Authentication> 
</Header> 
<Body> 
	<FunctionRequest Name="RefreshHostInfo" Include="No"> 
		<ParameterGroup Id="Host1">
			<Parameter Name="HostGUID" Value="DFD6BDAA-6259-EC47-AA3A2125F58D71A8" />
			<Parameter Name="Option" Value="sss" />
		</ParameterGroup>
	</FunctionRequest> 
</Body> 
</Request>
'@

        
        #XML file for host reg
        [XML]$ValidateHostinfoRefresh = @'
<Request Id="0009" Version="1.0"> 
<Header> 
	<Authentication>   
		<AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
	    <AccessSignature></AccessSignature>
	</Authentication> 
</Header> 
<Body> 
	<FunctionRequest Name="RefreshHostInfoStatus" Include="No"> 
		<Parameter Name="RequestId" Value="" />
	</FunctionRequest> 
</Body> 
</Request>    


'@





        Write-verbose "Retrieving Host Details for Machine  : $($MachineIP)"
        #Populate Request header.CXU


        #custom object creation
            $Object = New-Object PSObject
            $object | Add-Member -Type NoteProperty -Name HostGUID -Value $null
            $object | Add-Member -Type NoteProperty -Name HostIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null

        #get the Host from registered List
        $FilteredHost = List-InMageRegisteredHosts -MachineIP $MachineIP -ScoutSettings $ScoutSettings
        if ($FilteredHost -eq $null )
        {
           $Object.ErrorCode = 1
           $Object.Message = "No Matching Host Found."
           $Object.HostIP = $MachineIP
           return $Object
        }
        else
        {
            $object.HostGUID = $FilteredHost.HostAgentGUID
            $Object.HostIP = $MachineIP


            #call Web request
            try
            {
                
                ($RefreshHostInfo.Request.Body.FunctionRequest.ParameterGroup.Parameter | Where-Object {$_.Name -eq "HostGUID"} ).Value = $FilteredHost.HostAgentGUID
                $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $RefreshHostInfo -ContentType "text/xml"

                #get the response ID
                    $RequestId = ( ([XML]($Response.Content)).Response.Body.Function.FunctionResponse.Parameter | Where-Object {$_.Name -eq "RequestId"} ).Value
                    $RefreshStatus = $false

                    $timeoutcounter = 0
                    #Write-Debug "RequestID : $RequestId"
                    $Threshold = New-TimeSpan -Seconds $TimeoutSeconds
                    $secondCounter = [diagnostics.stopwatch]::StartNew()
                    while ( ($RefreshStatus -eq $false) -or ($secondCounter.elapsed -le $Threshold ))
                    {
                         ($ValidateHostinfoRefresh.Request.Body.FunctionRequest.Parameter | Where-Object { $_.Name -eq "RequestId"} ).Value = $RequestId

                         $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $ValidateHostinfoRefresh -ContentType "text/xml"
                         $Status =  (([xml]($response.Content)).Response.Body.Function.FunctionResponse.Parameter | Where-Object { $_.Name -eq "Statusofallhosts"}).Value
                         if($status -eq "Success")
                         {
                            $RefreshStatus = $true
                         }

                         if($status -eq "Failed")
                         {
                           $Object.ErrorCode = 5
                           $Object.Message = "Error : Host $MachineIP information refresh via CS agent update failed. Please ensure Machine is online and is able to communicate with CS Server :$CXServerIP." 
                           return $Object
                         }
                    }

                        if  (($secondCounter.elapsed -ge $Threshold) -and ($RefreshStatus -eq $false) ) 
                         {
                            $object.ErrorCode = 6
                            $Object.Message = "Host: $MachineIP info refresh operation timed out. Please check if the Host is online and can communicate with CS Server. If required, please refresh via UI."
                            return $object
                         }


                    Write-Verbose "Success : refreshed Agent host information $machineIP in CS Server $csserverip."
                    #Write-Debug "Loop refreshstatus flags status : $status."
                    #Write-Debug "Refresh time taken : $($timeoutcounter * $TimeoutSeconds)" 

            }
            catch
            {
                Write-Error "Failed to call RefreshHostInfo to API Url : $($CXRequestPage)"
                $Object.ErrorCode = 4
                $Object.Message = "Failed to execute 'RefreshHostInfo' API Call.`n
                Message : $($Response.Message)"
                $Object.HostIP = $MachineIP
                return $Object
            }    
            
            $HostDetails = [xml]$Response.Content
            $Object.ErrorCode = 0
            $Object.Message = "Host details successfully."
            return $Object
        }
        
    }



############Main function to trigger replication from Source --> Target
#TODO : cleanup code in case of failure of protection.
#TODO : Add verification of protection pair after running protection.
#TODO : remove dependency from Posh-SSH for mapping disk to device ID on master target.
    # GethostInfo works, but no way to extract logocalblock and physicalblock
    #update : Logical/physical block sizes are not mandatory. Replication works anyway


    Function  Protect-InMageMachine
    {
    #this function calls the primary function Start-InMageDiskProtection to protect entire machine, 
    #It will also take care of cleanup in case machine protection fails
     Param
        (
            [parameter(Mandatory=$False)]
            [PSobject]$ScoutSettings = $global:ScoutSettings,

            [parameter(Mandatory=$True)]
            [String]$SourceIP,
            
            [parameter(Mandatory=$True)]
            [String]$TargetIP,

            [parameter(Mandatory=$True)]
            [String]$TargetHyperVIP,

            # Source Computer Credential
            <# Not needed any more
            [parameter(Mandatory=$false)]
            [System.Management.Automation.PSCredential]$SrcCmpCredential,
          
            
            # Source Computer Credential
            [parameter(Mandatory=$false)]
            [System.Management.Automation.PSCredential]$TrgCmpCredential,

            #>

            [Switch]$CleanuponFailure,

            [parameter(Mandatory=$True)]
            [System.Management.Automation.PSCredential]$TrgHyperVCmpCredential,

            [parameter(Mandatory=$false)]
            [ValidateSet("Linux","Windows")]
            [String]$OSbuild = "Windows",


            [parameter(Mandatory=$true)]
            [ValidateScript( {$_.Endswith("\")})]
            [String]$TargetVHDPath,

            [parameter(Mandatory=$false)]
            [int]$RPCPort = 445,

            [parameter(Mandatory=$false)]
            [int]$SSHPort = 22,

            [parameter(Mandatory=$false)]
            [ValidateSet(512,4096)]
            [Int]$logicalSectorSize = 512,

            [parameter(Mandatory=$false)]
            [ValidateSet(512,4096)]
            [Int]$PhysicalSectorSize = 512

         )   

         
###########################################Create custom object
#region

            <#Error Codes
            "0 : No Errors",
            "1 : Error retrieving Source details from CS",
            "2 : Error retrieving Target details from CS",
            "3 : Error connecting to Hyper-V Server.",
            "4 : Source VM could not be protected.",
            "5 : Source VM could not be protected.Backup files have been cleaned up..",
            "6 : Master Target not located on specified Hyper-V Target.",
            "99 : Generic Error"
            #>




            #This must be returned to parent call for Validation
            $Object = New-Object PSObject
            $Object | Add-Member -Type NoteProperty -Name SourceIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name ProtectionStatus -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : No Errors",
            "1 : Error retrieving Source details from CS",
            "2 : Error retrieving Target details from CS",
            "3 : Error connecting to Hyper-V Server.",
            "4 : Source VM could not be protected.",
            "5 : Source VM could not be protected.Backup files have been cleaned up..",
            "6 : Master Target not located on specified Hyper-V Target.",
            "99 : Generic Error")



            $Object.SourceIP = $SourceIP
            $Object.TargetIP = $TargetIP


#endregion


#############################################################Start region##############################################33
#region
#validate the Source IP, Target IP, hyper-V IP, HyperV credential

            #validate SourceIP exists on CS Server
            $Response = List-InMageRegisteredHosts -MachineIP $SourceIP -ScoutSettings $ScoutSettings
            if ($Response -eq $null)
            {
                $Object.ErrorCode = 1
                $Object.Message = "Source machine $SourceIP does not exists on CS Server $CXServerIP."
                return $Object    
            }
            #Get SourceVM details
            $SourceObject = Get-InMageHostDetails -MachineIP $SourceIP -ScoutSettings $ScoutSettings
            $SourceXML = [xml]($SourceObject.HostDetailsXML)
            



            #validate TargetIP exists on CS Server
            $Response = List-InMageRegisteredHosts -MachineIP $SourceIP -ScoutSettings $ScoutSettings
            if ($Response -eq $null)
            {
                $Object.ErrorCode = 2
                $Object.Message = "Target machine $SourceIP does not exists on CS Server $CXServerIP."
                return $Object    
            }
            #Get TargetVM details
            $TargetObject = Get-InMageHostDetails -MachineIP $TargetIP -ScoutSettings $ScoutSettings
            $TargetXML = [xml]($TargetObject.HostDetailsXML)




            #Validate if the HyperV server can be connected to .
            #Assumption : Target Hyper-V Server is currently a single host.
            try
            {
                $PSSession = New-PSSession -ComputerName $TargetHyperVIP -Credential $TrgHyperVCmpCredential 
            }
            catch
            {
                $Object.ErrorCode = 3
                $Object.Message = "Error connecting to HyperV Server $TargetHyperVIP."
                return $Object     
            }
            #validate if the Target is located on Hyper-V
            $TargetNICS = ($targetXML.FunctionResponse.ParameterGroup | Where-Object {$_.Id -eq "MacAddressList"}).ParameterGroup
                #get the Mac address
                $TargetMAC  = ($TargetNICS[0].Parameter | Where-Object {$_.Name -eq "MacAddress"}).Value
                $TargetMAC = ($TargetMAC.Replace(":","")).ToUpper()
                    #search the Hyper-V for VM with specified NIC
                    #TODO : update the code if you intend to search cluster or VMM
                    $VMName = Invoke-Command -Session $PSSession -ArgumentList $TargetMAC -ScriptBlock {
                                $MAC = $args[0];
                                $VMName = (get-VM | Get-VMNetworkAdapter | Where-Object {$_.MacAddress -eq "00155D05F11A"}).VMName;
                                return $VMName                 
                                }

                    if ([string]::IsNullOrEmpty($VMName))
                    {
                        $Object.ErrorCode = 6
                        $Object.Message = "Master Target $TargetIP not found on HyperV  Server $TargetHyperVIP"
                        Remove-PSSession -Session $PSSession 
                        return $Object
                    }


#endregion

#######################################Initiate Machine protection
#region

    if ($OSbuild -eq "Linux")
    {

        #get the disk details from Source IP
        $SourceDisks = $SourceXML.FunctionResponse.ParameterGroup[0].ParameterGroup

        #run protection for each disk
        foreach ($Disk in $SourceDisks)
        {
            $DiskSource = ($Disk.Parameter | Where-Object {$_.Name -eq "DiskName"}).Value
            $status = Start-InMageDiskProtection -ScoutSettings $ScoutSettings -SourceIP $SourceIP -TargetIP $TargetIP -TargetHyperVIP $TargetHyperVIP -SourceDiskIdentifier $DiskSource -TrgHyperVCmpCredential $TrgHyperVCmpCredential -OSbuild Linux -TargetVHDPath $TargetVHDPath
            #wait for completion and check for status

            if ($status.ErrorCode -ne 0)
            {
                #drop everything and return error
                $Object.ErrorCode = 4
                $Object.Message = "Source Machine could not be protected."
                 Remove-PSSession -Session $PSSession -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                return $Object
            }
            else
            {
                $Object.ErrorCode = 0
                $Object.Message = "Source Machine Protected."
            }
        }
         Remove-PSSession -Session $PSSession -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        return $Object
    }

#endregion
}




    


    ###################Use this function for individual disk protection
    #TODO : stringent error checking
    #TODO : Check if disk is already not protected.
    #TODO : add error handling for VHD already existing on Hyper-V 
     Function Start-InMageDiskProtection
    {
        Param
        (
            [parameter(Mandatory=$False)]
            [PSobject]$ScoutSettings = $global:ScoutSettings,

            [parameter(Mandatory=$True)]
            [String]$SourceIP,
            
            [parameter(Mandatory=$True)]
            [String]$TargetIP,

            [parameter(Mandatory=$True)]
            [String]$TargetHyperVIP,

            [parameter(Mandatory=$True)]
            [String]$SourceDiskIdentifier,


            # Source Computer Credential
            <# Not needed any more
            [parameter(Mandatory=$false)]
            [System.Management.Automation.PSCredential]$SrcCmpCredential,
          
            
            # Source Computer Credential
            [parameter(Mandatory=$false)]
            [System.Management.Automation.PSCredential]$TrgCmpCredential,

            #>

            [parameter(Mandatory=$True)]
            [System.Management.Automation.PSCredential]$TrgHyperVCmpCredential,

            [parameter(Mandatory=$false)]
            [ValidateSet("Linux","Windows")]
            [String]$OSbuild = "Windows",


            [parameter(Mandatory=$true)]
            [ValidateScript( {$_.Endswith("\")})]
            [String]$TargetVHDPath,

            [parameter(Mandatory=$false)]
            [int]$RPCPort = 445,

            [parameter(Mandatory=$false)]
            [int]$SSHPort = 22,

            [parameter(Mandatory=$false)]
            [ValidateSet(512,4096)]
            [Int]$logicalSectorSize = 512,

            [parameter(Mandatory=$false)]
            [ValidateSet(512,4096)]
            [Int]$PhysicalSectorSize = 512

         )   


            $CXServerIP = $ScoutSettings.CXServerIP
            $PSServerIP = $ScoutSettings.PSServerIP
            $AUTHMethod = $ScoutSettings.AUTHMethod
            $CXUserName = $ScoutSettings.CXUserName
            $CXPassword = $ScoutSettings.CXPassword
            $CXAccessSignature = $ScoutSettings.CXAccessSignature
            $CXHTTPPort = $ScoutSettings.CXHTTPPort
            $CXRequestPage = $ScoutSettings.CXRequestPage
            $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes



#################################################Create custom object######################################
#region

            <#Error Codes
            "0 : No Errors",
            "1 : Error retrieving Source details from CS",
            "2 : Error retrieving Target details from CS",
            "3 : Source Disk does not exists on SourceIP (Linux)",
            "4 : Source Disk does not exists on SourceIP (Windows)",
            "5 : Error creating VHD on Hyper-V Server.",
            "6 : Error mounting VHD/VHDX on target.",
            "7 : Error Calling Pairing API to CS Server",
            "8 : Insufficient SCSI slots in Master Target.",
            "9 : Target disk not registered in CS Database .",
            "10 : Master Target not located on specified Hyper-V Target.",
            "11 : Error connecting to Hyper-V Server.",
            "99 : Generic Error"
            #>




            #This must be returned to parent call for Validation
            $Object = New-Object PSObject
            $Object | Add-Member -Type NoteProperty -Name SourceIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name SourceDisk -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetDisk -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetVHDPath -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : No Errors",
                                                                                    "1 : Error retrieving Source details from CS",
                                                                                    "2 : Error retrieving Target details from CS",
                                                                                    "3 : Source Disk does not exists on SourceIP (Linux)",
                                                                                    "4 : Source Disk does not exists on SourceIP (Windows)",
                                                                                    "5 : Error creating VHD on Hyper-V Server.",
                                                                                    "6 : Error mounting VHD/VHDX on target.",
                                                                                    "7 : Error Calling Pairing API to CS Server",
                                                                                    "8 : Insufficient SCSI slots in Master Target.",
                                                                                    "9 : Target disk not registered in CS Database .",
                                                                                    "10 : Master Target not located on specified Hyper-V Target.",
                                                                                    "11 : Error connecting to Hyper-V Server.",
                                                                                    "99 : Generic Error")

#endregion


############################################Declare XML objects for calling API############################
#region
            [XML]$CreateProtectionXML =
                @'
<Request Id="0001" Version="1.0">
<Header>
    <Authentication>
		<AccessKeyID>A23FF8784CFE3F858A07B2CDEB25CBD27AA99808</AccessKeyID>
		<AuthMethod>CXAuth</AuthMethod>
		<CXUserName>admin</CXUserName>
		<CXPassword>5f4dcc3b5aa765d61d8327deb882cf99</CXPassword>
		<AccessSignature></AccessSignature>
	</Authentication>
</Header>
<Body> 
<FunctionRequest Name="CreateProtection" Include="No">
    <Parameter Name="SourceIP" Value="192.168.1.101" />
    <Parameter Name="TargetIP" Value="192.168.1.100" />   
    <Parameter Name="ProcessServerIP" Value="192.168.1.10" />     
    <Parameter Name="RetentionVolume" Value="/mnt/retention"/>
	<Parameter Name="UsePSNATForSource" Value="No"/>
	<Parameter Name="UsePSNATForTarget" Value="No"/>
	<ParameterGroup Id="PairDetails">
        <ParameterGroup Id="Pair1">
			<Parameter Name="SourceVolume" Value="/dev/sdb"/>
			<Parameter Name="TargetVolume" Value="/dev/sdd"/>
		</ParameterGroup>
</ParameterGroup>
</FunctionRequest>
</Body> 
</Request>
'@
#endregion

############################################Perform Error checking#########################################
#region
            $Object.SourceIP = $SourceIP
            $Object.TargetDisk = $TargetIP
            $Object.SourceDisk = $SourceDiskIdentifier
            

            #validate SourceIP exists on CS Server
            $Response = List-InMageRegisteredHosts -MachineIP $SourceIP -ScoutSettings $ScoutSettings
            if ($Response -eq $null)
            {
                $Object.ErrorCode = 1
                $Object.Message = "Source machine $SourceIP does not exists on CS Server $CXServerIP."
                return $Object    
            }



            #Validate if the HyperV server can be connected to .
            #Assumption : Target Hyper-V Server is currently a single host.
            try
            {
                $PSSession = New-PSSession -ComputerName $TargetHyperVIP -Credential $TrgHyperVCmpCredential 
                Write-Verbose "PSsession ID : $($PSSession.Id), Name : $($PSsession.Name)"
            }
            catch
            {
                $Object.ErrorCode = 10
                $Object.Message = "Error connecting to HyperV Server $TargetHyperVIP."
                return $Object     
            }

            #assuming Hyper-V is connected, validate Target VM is present on Hyper-V
            #get Server details 
            #Match with MAC addresses.

                #Get TargetVM details
                $TargetObject = Get-InMageHostDetails -MachineIP $TargetIP -ScoutSettings $ScoutSettings
                $TargetXML = [xml]($TargetObject.HostDetailsXML)
                $TargetNICS = ($targetXML.FunctionResponse.ParameterGroup | Where-Object {$_.Id -eq "MacAddressList"}).ParameterGroup
                    #get the Mac address
                $TargetMAC  = ($TargetNICS[0].Parameter | Where-Object {$_.Name -eq "MacAddress"}).Value
                $TargetMAC = ($TargetMAC.Replace(":","")).ToUpper()
                    #search the Hyper-V for VM with specified NIC
                    #TODO : update the code if you intend to search cluster or VMM
                    $VMName = Invoke-Command -Session $PSSession -ArgumentList $TargetMAC -ScriptBlock {
                                $MAC = $args[0];
                                $VMName = (get-VM | Get-VMNetworkAdapter | Where-Object {$_.MacAddress -eq "00155D05F11A"}).VMName;
                                return $VMName                 
                                }

                    if ([string]::IsNullOrEmpty($VMName))
                    {
                        $Object.ErrorCode = 9
                        $Object.Message = "Master Target $TargetIP not found on HyperV  Server $TargetHyperVIP"
                        Remove-PSSession -Session $PSSession 
                        return $Object
                    }

            #Get SourceVM details
            $SourceObject = Get-InMageHostDetails -MachineIP $SourceIP -ScoutSettings $ScoutSettings
            $SourceXML = [xml]($SourceObject.HostDetailsXML)
            
                                
            ####assuming VM is present on target, check if sufficient SCSI slots are available
                #get total disks connected to SCSI controllers.
                $SCSIControllerDiskCount = Invoke-Command -Session $PSSession -ArgumentList $VMName -ScriptBlock {
                                    $VMname = $args[0];
                                    $SCSIController = get-VM -Name $VMname| Get-VMScsiController;  
                                    $Count = 0;                            
                                                foreach ($controller in $SCSIController)
                                                {
                                                    $Count += $controller.Driver.count                                              
                                                }     
                                    return $Count
                                    }

                if ($SCSIControllerDiskCount -eq 255 )
                {
                    $Object.ErrorCode = 8
                    $Object.Message = "Insufficient SCSI slots in Master Target $TargetIP"
                    Remove-PSSession -Session $PSSession
                    return $Object
                }

#endregion

############################################Create disk for mounting on Master Target########################
#region

            #get Source Name and Disk XML

            $SourceName = ($SourceXML.FunctionResponse.Parameter | Where-Object {$_.Name -eq "HostName"}).Value
            $SourceGUID = ($SourceXML.FunctionResponse.Parameter | Where-Object {$_.Name -eq "HostGUID"}).Value
                #get disk ID
            $DiskXML = ($SourceXML.FunctionResponse.ParameterGroup[0]).ParameterGroup


            #get list of any protection or existing pairs
            $ExistingPairs = Get-InMageConfiguredPair -ScoutSettings $ScoutSettings -SourceIP $SourceIP -TargetIP $TargetIP -TargetHyperVIP $TargetHyperVIP -HyperVCredentials $TrgHyperVCmpCredential
            
            if ($ExistingPairs.DiskPairing.Count -ne 0)
            {
                #check if Source disk is being already protected.
                if ($ExistingPairs.DiskPairing.SourceDevice.Contains($SourceDiskIdentifier) )
                {
                    #update and return back to parent caller
                    $Object.ErrorCode = 0;
                    $Object.Message = "Source disk : $SourceDiskIdentifier is already being protected.";
                    Remove-PSSession -Session $PSSession
                    return $Object
                }
            }


                         
            $diskLabel = $null
            $diskNumber = $null
            $DiskSizeBytes = $null
            #get the Disk ID from CS Server. Also checks if the provided Disk identifier for protection actually exists at the moment. Better to refresh the host infor before calling protection
            $Disk = $DiskXML | Where-Object {  ($_.Parameter | Where-Object { $_.Name -eq "DiskName"}).Value  -eq $SourceDiskIdentifier }

            if ($Disk -eq $null)
            {
                if($OSbuild -eq "Linux")
                {$Object.ErrorCode =  3}
                else
                {$Object.ErrorCode =  4}
                $Object.Message = "Source Disk : $SourceDiskIdentifier not found on Source IP : $SourceIP."
                Remove-PSSession -Session $PSSession
                return $Object
            }

                $DiskDevice = ($Disk.Parameter | Where-Object {$_.Name -eq "DiskName"}).Value
                $diskNumber = $Disk.Id
                $DiskSizeBytes = ($Disk.Parameter | Where-Object {$_.Name -eq "Size"} ).Value
                

            #Let us generate the complete VHD path. If the folder does not exists, the Hyper-V Service will accordingly create it.
            $DiskName = $SourceName + "_"  + $SourceGUID  +"_" + $diskNumber + ".VHDX"   
            if ($TargetVHDPath.EndsWith("\"))
            {
                $Diskpath = $TargetVHDPath + $DiskName  
            }
            else
            {
                $Diskpath = $TargetVHDPath + "\" + $DiskName  
            }
          



            #create the VHD file on Hyper-V Server

            try
            {
                #Preserve this object. This is serious !!!!
                #This object contains the disk identifier, that will be used to map the VHD to the actual disk inside the MT
                $VHDObject = Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName,$logicalSectorSize,$PhysicalSectorSize,$DiskSizeBytes -ScriptBlock{
                                    $DiskPath =  $args[0];
                                    $VMName = $args[1];
                                    $logicalSectorSize = $args[2];
                                    $PhysicalSectorSize = $args[3];
                                    $DiskSizeBytes = $args[4];
                                    $VM = get-VM -Name $VMName;
                                    $VHD = new-VHD -Path $DiskPath -LogicalSectorSizeBytes $logicalSectorSize -PhysicalSectorSizeBytes $PhysicalSectorSize -Dynamic -SizeBytes $DiskSizeBytes;                                                                                           
                                    # not doing this, as for windows , the VHD needs to be prepared on hyper-V server before mounting on to Master Target
                                    #$VM | Add-VMHardDiskDrive -ControllerType SCSI -Path $DiskPath;
                                    return $VHD                                
                                    }

            }
            catch
            {
                #error, cleanup the VHD and unmount from VM if required.
                Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock{
                                                $Diskpath = $args[0];
                                                $VMName = $args[1];
                                                if(Test-Path $Diskpath)
                                                {
                                                    #delete the VHD
                                                    remove-Item $Diskpath -Force -Confirm
                                                }
                                            }
                $Object.ErrorCode = 5    
                $Object.Message = "Error creating VHD on Hyper-V host $TargetHyperVIP."
                Remove-PSSession -Session $PSSession
                return $Object
           }
#endregion





##############################################Branch for OS type , prepare disk and call pairing
#region
                #self explainatory !!!!    
                if ($OSbuild -eq "Linux")
                {
                    #mount VHD on Master Target
                    try
                    {
                        # no return information is needed. We are all set for launch
                        Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock {
                                            $Diskpath = $args[0];
                                            $VMName = $args[1];
                                            Get-VM $VMName | Add-VMHardDiskDrive -ControllerType SCSI -Path $Diskpath                                                                                    
                                        }                                                                                        
                    }
                    catch
                    {
                        #something has gone wrong. Unmount the VHD/X from the VM and delete the file.
                        # the unmounting generally does not poses an issue on linux since the Disk has not been initialized. but watch out for error and patch accordingly in future.
                        Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock {
                                            $Diskpath = $args[0];
                                            $VMName = $args[1];
                                            $VHD = Get-VM -Name $VMName | select vmid | get-VHD | Where-Object {$_.Path -eq $Diskpath}
                                            if ($VHD -ne $null)
                                            {
                                                #unmount the VHD from VM

                                                #get SCSI controller number
                                                $SCSIControllerNumber = (Get-VM $VMName | Get-VMScsiController  | Where-Object {$_.Drives.Path -eq $Diskpath}).ControllerNumber
                                                Get-VMHardDiskDrive -VMName $VMName –ControllerType SCSI -ControllerNumber $SCSIControllerNumber | Remove-VMHardDiskDrive
                                           }
                                                #delete the VHD straight forward.No Mercy
                                                if(Test-Path $Diskpath)
                                                {
                                                    #delete the VHD
                                                    remove-Item $Diskpath -Force -Confirm
                                                }
                                       }
                                       #update object and return to parent
                                       $Object.ErrorCode = 6
                                       $Object.Message = "Error mounting VHD/VHDX : $Diskpath on target : $TargetIP on HyperV Server : $TargetHyperVIP."
                                       Remove-PSSession -Session $PSSession
                                       return $Object
                    }

                    #call function to refresh Target host info
                    $Response = Sync-InMageHostDetails -MachineIP $TargetIP -ScoutSettings $ScoutSettings

                    if ($Response.ErrorCode -ne 0)
                    {
                        $Object.ErrorCode = 99
                        $Object.Message = "Function Failed to call Sync host information for IP : $TargetIP."

                                    #unmount and delete disk from Master Target
                                    Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock {
                                            $Diskpath = $args[0];
                                            $VMName = $args[1];
                                            $VHD = Get-VM -Name $VMName | select vmid | get-VHD | Where-Object {$_.Path -eq $Diskpath}
                                            if ($VHD -ne $null)
                                            {
                                                #unmount the VHD from VM

                                                #get SCSI controller number
                                                $SCSIControllerNumber = (Get-VM $VMName | Get-VMScsiController  | Where-Object {$_.Drives.Path -eq $Diskpath}).ControllerNumber
                                                Get-VMHardDiskDrive -VMName $VMName –ControllerType SCSI -ControllerNumber $SCSIControllerNumber | Remove-VMHardDiskDrive
                                           }
                                                #delete the VHD straight forward.No Mercy
                                                if(Test-Path $Diskpath)
                                                {
                                                    #delete the VHD
                                                    remove-Item $Diskpath -Force -Confirm
                                                }
                                       }

                        Remove-PSSession -Session $PSSession
                        return $Object
                    }

                    #get the target Disk mapping on master target
                    #region
                        #last 12 char of VHD identifier is what will show up in CS host info Disk XML(lower case) as SCSI ID or WWAN  in Linux OS 
                      
                        $VHDIdentifier = ($VHDObject.DiskIdentifier.SubString($VHDObject.DiskIdentifier.Length - 12, 12)).Tolower()

                        #get the details of target from CS Server
                        $TargetXML = [xml](Get-InMageHostDetails -MachineIP $TargetIP -ScoutSettings $ScoutSettings).HostDetailsXML
                        $TargetDisks =  $TargetXML.FunctionResponse.ParameterGroup[0].ParameterGroup
                        
                        
                        #Select the disk device name which matches the VHDIdentifier
                        $TargetDisk = $TargetDisks | Where-Object {  ($_.Parameter | Where-Object {$_.Name -eq "ScsiId"}).value -like "*$VHDIdentifier" }
                        $TargetDiskIdentifier = ($TargetDisk.Parameter | Where-Object { $_.Name -eq "DiskName" }).Value
                         
                        if ( ($TargetDiskIdentifier -eq $null) -or ([string]::IsNullOrEmpty($TargetDiskIdentifier) ))
                        {
                            #something has gone wrong. Unmount disk from MT and delete the same
                             Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock {
                                            $Diskpath = $args[0];
                                            $VMName = $args[1];
                                            $VHD = Get-VM -Name $VMName | select vmid | get-VHD | Where-Object {$_.Path -eq $Diskpath}
                                            if ($VHD -ne $null)
                                            {
                                                #unmount the VHD from VM

                                                #get SCSI controller number
                                                $SCSIControllerNumber = (Get-VM $VMName | Get-VMScsiController  | Where-Object {$_.Drives.Path -eq $Diskpath}).ControllerNumber
                                                Get-VMHardDiskDrive -VMName $VMName –ControllerType SCSI -ControllerNumber $SCSIControllerNumber | Remove-VMHardDiskDrive
                                           }
                                                #delete the VHD straight forward.No Mercy
                                                if(Test-Path $Diskpath)
                                                {
                                                    #delete the VHD
                                                    remove-Item $Diskpath -Force -Confirm
                                                }
                                       }
                                       
                                       #update object and return to parent
                                       $Object.ErrorCode = 6
                                       $Object.Message = "Error mounting VHD/VHDX : $Diskpath on target : $TargetIP on HyperV Server : $TargetHyperVIP."
                                       Remove-PSSession -Session $PSSession
                                       return $Object
                        }



                    #endregion


                    #call the API to trigger protection

                            ###########################Populate Authentication details in XML
            
                            if($AUTHMethod -eq "CXAuth")
                            {
                                $CreateProtectionXML.Request.Header.Authentication.AuthMethod = "CXAuth"
                                #set username and password
                                $CreateProtectionXML.Request.Header.Authentication.CXPassword = $CXPassword
                                $CreateProtectionXML.Request.Header.Authentication.CXUserName = $CXUserName

                            }
                            else
                            {
                                #Else code for Mesg Authentication
                            }


                            #populate source and target IP address
                            ($CreateProtectionXML.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "SourceIP"}).Value = $SourceIP.ToString()
                            ($CreateProtectionXML.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "TargetIP"}).Value = $TargetIP.ToString()
                            ($CreateProtectionXML.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "ProcessServerIP"}).Value = $PSServerIP.ToString()
                    
                            
                            #retention volume for Linux is always /mnt/retention
                            ($CreateProtectionXML.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "RetentionVolume"}).Value = "/mnt/retention"

                            

                            #populate source and target disk mapping
                            (($CreateProtectionXML.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup).Parameter | Where-Object {$_.Name -eq "SourceVolume"}).value = $SourceDiskIdentifier.Tostring()
                            (($CreateProtectionXML.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup).Parameter | Where-Object {$_.Name -eq "TargetVolume"}).value = $TargetDiskIdentifier.Tostring()



                            #call the API
                            #call the XML request
                            try
                            {
                                $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $CreateProtectionXML -ContentType "text/xml"
                            }
                            catch
                            {
                                $Object.ErrorCode = 8
                                $Object.Message = "Failed to call Protection API to url : $($CXRequestPage)"
                                Remove-PSSession -Session $PSSession
                                return $Object
                            }

                            #check for API call response.
                            if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
                            {
                                $Object.ErrorCode = 99
                                $Object.Message = "API call failed with error message : $($Response.StatusDescription)"
                                Remove-PSSession -Session $PSSession
                                return $Object
                            }

                            #check for Response call response.This is within the Response Content to check if actual API threw an error or success.
                            if (([xml]($Response.Content)).Response.Returncode -ne 0)
                            {
                                $Object.ErrorCode = 99
                                $Object.Message = "API call failed with error message : $(([xml]($Response.Content)).Response.Message)"

                                #cleanup and unmount the virtual disk from MT
                                #something has gone wrong. Unmount disk from MT and delete the same
                                Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock {
                                            $Diskpath = $args[0];
                                            $VMName = $args[1];
                                            $VHD = Get-VM -Name $VMName | select vmid | get-VHD | Where-Object {$_.Path -eq $Diskpath}
                                            if ($VHD -ne $null)
                                            {
                                                #unmount the VHD from VM

                                                #get SCSI controller number
                                                $SCSIControllerNumber = (Get-VM $VMName | Get-VMScsiController  | Where-Object {$_.Drives.Path -eq $Diskpath}).ControllerNumber
                                                Get-VMHardDiskDrive -VMName $VMName –ControllerType SCSI -ControllerNumber $SCSIControllerNumber | Remove-VMHardDiskDrive
                                           }
                                                #delete the VHD straight forward.No Mercy
                                                if(Test-Path $Diskpath)
                                                {
                                                    #delete the VHD
                                                    remove-Item $Diskpath -Force -Confirm
                                                }
                                       }
                                Remove-PSSession -Session $PSSession
                                return $Object
                            }

           

                            # no errors here.
                            

#############################Validate if the pair is made or not
                            #region
                                
                                
                                #call the Function for getting pair details for current Source/Target.
                                $SourcePairing = Get-InMageConfiguredPair -ScoutSettings $ScoutSettings -SourceIP $SourceIP -TargetIP $TargetIP


                                if ( ($SourcePairing.DiskPairing.SourceDevice.contains($SourceDiskIdentifier)) -eq $false )
                                {
                                    $Object.ErrorCode = 7
                                    $Object.Message = "Error calling pairing for specified Disk $SourceDiskIdentifier on target $TargetIP.Recommend cleanup and restarting the operation."

                                    #delete the VHD and unmount from MT
                                        Invoke-Command -Session $PSSession -ArgumentList $Diskpath,$VMName -ScriptBlock {
                                            $Diskpath = $args[0];
                                            $VMName = $args[1];
                                            $VHD = Get-VM -Name $VMName | select vmid | get-VHD | Where-Object {$_.Path -eq $Diskpath}
                                            if ($VHD -ne $null)
                                            {
                                                #unmount the VHD from VM

                                                #get SCSI controller number
                                                $SCSIControllerNumber = (Get-VM $VMName | Get-VMScsiController  | Where-Object {$_.Drives.Path -eq $Diskpath}).ControllerNumber
                                                Get-VMHardDiskDrive -VMName $VMName –ControllerType SCSI -ControllerNumber $SCSIControllerNumber | Remove-VMHardDiskDrive
                                           }
                                                #delete the VHD straight forward.No Mercy
                                                if(Test-Path $Diskpath)
                                                {
                                                    #delete the VHD
                                                    remove-Item $Diskpath -Force -Confirm
                                                }
                                       }
                                        Remove-PSSession -Session $PSSession
                                        return $Object
                                }

                            #endregion

                            #############Else all good.
                            $Object.ErrorCode = 0
                            $Object.Message = "Success."
                            $object.TargetIP = $TargetIP
                            $Object.SourceIP = $SourceIP
                            $object.TargetDisk = $TargetDiskIdentifier
                            $Object.TargetVHDPath = $Diskpath
                            Remove-PSSession -Session $PSSession
                            return $Object

                }
                else
                {
                    #populate code for windows : WIP
                }

#endregion

}




    #TODO : pending deep testing
    #TODO : better error handling
    Function Rollback-InMageProtectionPair
    {
         Param(
            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings = $global:ScoutSettings,
        
        
            [parameter(Mandatory=$True)]
            [String]$SourceIP,

            [parameter(Mandatory=$True)]
            [String]$TargetIP,


            [Parameter(Mandatory=$false)]
            [Int]$TimeoutSeconds = 120
            
            )


##########################Local copies of Variables extracted for Function usage
        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes

###########################Custom object##############################

  #get Source Machine Info from CS server.

         <#
            Error Codes
            "0 : No Errors",
            "1 : Existing Rollback operation not completed",
            "2 : Replication state inconsistent"
            "3 : Rollback failed",
            "4 : Rollback failed due to incorrect Agent IP",
            "5 : No disk pair on specified source-target to perform roll back",
            "99 : Failed to attach VHD to Master Target. Please perform Cleanup."      
         #>
            

        #This must be returned to parent call for Validation
            $Object = New-Object PSObject
            $Object | Add-Member -Type NoteProperty -Name SourceIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : No Errors",
            "1 : Existing Rollback operation not completed",
            "2 : Replication state inconsistent",
            "3 : Rollback failed",
            "4 : Rollback failed due to incorrect Agent IP",
            "5 : No disk pair on specified source-target to perform roll back",
            "99 : Failed to attach VHD to Master Target. Please perform Cleanup." )



################Create XML Object for request


    [XML]$CreateRollback = 
    @'
<Request Id="0001" Version="1.0">
<Header>
	<Authentication>
		<AccessKeyID>A23FF8784CFE3F858A07B2CDEB25CBD27AA99808</AccessKeyID>
		<AuthMethod>CXAuth</AuthMethod>
		<CXUserName>admin</CXUserName>
		<CXPassword>5f4dcc3b5aa765d61d8327deb882cf99</CXPassword>
		<AccessSignature></AccessSignature>
	</Authentication> 
</Header>
<Body> 
<FunctionRequest Name="CreateRollback" >
   	<Parameter Name="SourceIP" Value="" />
	<Parameter Name="TargetIP"   Value="" />  
	<Parameter Name="RecoveryPoint"  Value="LATEST_TIME" /> <!-- This parameter is optional -->
</FunctionRequest>
</Body> 
</Request>

'@



##################Populate XML Authentication params


            if($AUTHMethod -eq "CXAuth")
            {
                $CreateRollback.Request.Header.Authentication.AuthMethod = "CXAuth"
                #$GetRollBackStatus.Request.Header.Authentication.AuthMethod = "CXAuth" 

                #set username and password
                $CreateRollback.Request.Header.Authentication.CXPassword = $CXPassword
                $CreateRollback.Request.Header.Authentication.CXUserName = $CXUserName

                #$GetRollBackStatus.Request.Header.Authentication.CXPassword = $CXPassword
                #$GetRollBackStatus.Request.Header.Authentication.CXUserName = $CXUserName

            }
            else
            {
                #Else code for Mesg Authentication
            }

####################Check if source - target has actually any mapping

                    $DiskPair = Get-InMageConfiguredPair -ScoutSettings $ScoutSettings -SourceIP $SourceIP -TargetIP $TargetIP
                    if ($DiskPair.Errorcode -eq 3)
                    {
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        $Object.ErrorCode = 5
                        $Object.Message = "No Pairs to perform rollback."
                        return $Object
                    }
                    

######################Call Rollback status first to check if any rollback ops is in progress
#######################TODO : This code does not works as intended , often
#region

                    
                    
                    <#
                    $temp2 = $GetRollBackStatus.Clone()


                    #set the Source and IP address
                    ($GetRollBackStatus.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "SourceIP"}).Value = $SourceIP
                    ($GetRollBackStatus.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "TargetIP"}).Value = $TargetIP

                    try
                    {
                        $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp2 -ContentType "text/xml"
                    }
                    catch
                    {
                        Write-Error "Failed to call API Url $($CXRequestPage)".
                        $Object.ErrorCode = 99
                        $Object.HostIP = $SourceIP
                        $Object.Message = "Failed to call GetRollBackup API to url : $($CXRequestPage)"
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                            
                        return $Object
                    }

                    #check if any rollback status is pending or in progress;If Yes, update Object and exit function
                    $ResponseContent = [xml]($Response.Content)

                    $ResponseStatus = ( $ResponseContent.Response.Body.Function.FunctionResponse.ParameterGroup.Parameter | Where-Object {$_.Name -eq "executionState"} ).Value
                    if(  ($ResponseStatus -ne "Completed") -and ($ResponseStatus -ne "Failed") )
                    {
                        #existing rollback is in progress
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        $Object.ErrorCode = 1
                        $Object.Message = "Existing rollback Operation in progress."
                        return $Object
                    }
                    #>
#endregion

##################################### Trigger Rollback operation#########################################33

#region
                    $temp  = $CreateRollback.clone()                   
                    ($temp.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "SourceIP" }).Value = $SourceIP
                    ($temp.Request.Body.FunctionRequest.Parameter | Where-Object {$_.Name -eq "TargetIP" }).Value = $TargetIP
                    
                    try
                    {
                        $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp -ContentType "text/xml"
                    }
                    catch
                    {
                        Write-Error "Failed to call API Url $($CXRequestPage)".
                        $Object.ErrorCode = 99
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        $Object.Message = "Failed to call RollBackup API to url : $($CXRequestPage)"
                        return $Object
                    }    

                        #check if Rollback operation was successfull
                         $ResponseContent = [xml]($Response.Content)


                    #check Code for returned rollback code
                    if ($ResponseContent.Response.Body.Function.Returncode -eq 14)
                    {
                        $object.ErrorCode = 4
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        $Object.Message = "Rollback failed due to incorrect source/target IP"
                        return $object
                    }
                    
                    #check code for Misc failures
                    if ( ($ResponseContent.Response.Body.Function.Returncode -eq 3064) -or ($ResponseContent.Response.Body.Function.Returncode -eq 406) )
                    {
                        $object.ErrorCode = 2
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        $Object.Message = "Source replication is inconsistent"
                        return $object
                    }

                    #check code for Misc failures that we could not account for due to missing documentations=
                    if ($ResponseContent.Response.Body.Function.Returncode -ne 0)
                    {
                        $object.ErrorCode = $ResponseContent.Response.Body.Function.Returncode
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        $Object.Message = $ResponseContent.Response.Body.Function.Message
                        return $object
                    }
                    


#endregion
##############################################Check and wait for rollback to complete#######################################                    
#region

                    #We run a looped counter till all disks dissapear from Disk pairs.
                    #Normally rollback takes < 2 min, if WAN link is good and replication data is minimum.
                    #start counter    
                    $Timeout = New-TimeSpan -Seconds $TimeoutSeconds
                    $Counter = [diagnostics.stopwatch]::StartNew()

                    
                    
                    While(($DiskPairStatus.Errorcode -ne "3")  -and ($Counter.Elapsed -le $Timeout) )
                    {
                            #get Disk pair status.
                            $DiskPairStatus = Get-InMageConfiguredPair -ScoutSettings $ScoutSettings -SourceIP $SourceIP -TargetIP $TargetIP
                    }



                     #check if current operation is still pending.

                    if  (( $DiskPairStatus.ErrorCode -eq 0 )  -and ($Counter.Elapsed -le $Timeout) )          # we still have pairs visible in CS scout
                    {
                        $Object.ErrorCode = 1
                        $Object.Message = "Rollback operation pending."
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        return $Object
                    }



                   else
                     {
                        #operation successfull. VM Warp jump successfull !!!!
                        $Object.ErrorCode = 0
                        $Object.Message = "Rollback operation completed."
                        $Object.SourceIP = $SourceIP
                        $Object.TargetIP = $TargetIP
                        return $Object
                     }





#endregion                            


                   
}




    #TODO: Pending Development
    Function Create-InMageProtectionSizing
    {
        Param
        (
            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings = $global:ScoutSettings,
            
            [parameter(Mandatory=$True)]
            [PSObject]$MachineList,

            [parameter(Mandatory=$True)]
            [PSObject]$MasterTargetList,

            [parameter(Mandatory=$True)]
            [PSObject]$HypervList
        )


    }




    #function deletes all pairs between Source and Target IP.
    #Function does not checks if Target is MT. Please ensure Target IP is correct.
    Function Delete-InMageConfiguredPair
    {
        Param(
            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings = $global:ScoutSettings,
        
        
            [parameter(Mandatory=$True)]
            [String]$SourceIP,

            [parameter(Mandatory=$True)]
            [String]$TargetIP,
            
            [Parameter(Mandatory=$false)]
            [Int]$TimeoutSeconds = 120
            
            )


##########################Local copies of Variables extracted for Function usage
        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes

###########################Custom object##############################

  #get Source Machine Info from CS server.

         <#
            Error Codes
            "0 : No Errors",
            "1 : Error retrieving Source details from CS",
            "2 : Target/Source does not exists in CS",
            "3 : No Pairs found in CS server for specified source-target",
            "4 : Error Calling Delete Pair API to CS server.",
            "5 : Error Calling Get Configured Pair API to CS server."
            "6 : Deletion of Replication Pair's timed out.",
            "99 : Failed to attach VHD to Master Target. Please perform Cleanup."   
    
         #>
            
###############Create Custom Object to store error messages and operation status.
#region
            #This must be returned to parent call for Validation
            $Object = New-Object PSObject
            $object | Add-Member -Type NoteProperty -Name SourceIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name SourceGUID -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetGUID -Value $null     # include object $machineObject declared below.
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : No Errors",
                                                                                "1 : Error retrieving Source details from CS",
                                                                                "2 : Target/Source does not exists in CS",
                                                                                "3 : No Pairs found in CS server for specified source-target",
                                                                                "4 : Error Calling Delete Pair API to CS server.",
                                                                                "5 : Error Calling Get Configured Pair API to CS server.",
                                                                                "6 : Deletion of Replication Pair's timed out.",
                                                                                "99 : Failed to attach VHD to Master Target. Please perform Cleanup.","99 : Generic Error)")


#endregion

########################## XML body for deleting and reading deleting status
#region

[xml]$DeletePairs = 
@'
<Request Id="0001" Version="1.0">
 	<Header>
  		<Authentication>
    		<AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
    		<AccessSignature></AccessSignature>
  		</Authentication>
 	</Header>
 	<Body>
  		<FunctionRequest Name="DeletePairs" Include="No">	
		<ParameterGroup Id="DeleteList_1">
		</ParameterGroup>
 		 </FunctionRequest>
 	</Body>
</Request>
'@


[xml]$GetConfiguredPair =
@'
<Request Id="0001" Version="1.0">
 	<Header>
  		<Authentication>
    		<AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
    		<AccessSignature></AccessSignature>
  		</Authentication>
 	</Header>
 	<Body>
  		<FunctionRequest Name="GetConfiguredPairs" Include="No">
		<ParameterGroup Id="HostLists">
		<ParameterGroup Id="HostList_1">
			<Parameter Name="SourceHostGUID" Value="082F3A9A-24D2-AE41-9C1BCBC99D8FBCD6" />
			<Parameter Name="TargetHostGUID" Value="5D99E358-B2A3-224F-A98887B9E36758AC" />
		</ParameterGroup>
		</ParameterGroup>
 		 </FunctionRequest>
 	</Body>
</Request>
'@

#endregion
#############################################################################
#region

#configure settings for XML file header
$temp = $DeletePairs.clone()
$temp2 = $GetConfiguredPair.Clone()


#Configure settings for XML get configured pair
    
    $SourceGUID = (List-InMageRegisteredHosts -MachineIP $SourceIP -ScoutSettings $ScoutSettings).HostAgentGUID
    $TargetGUID = (List-InMageRegisteredHosts -MachineIP $TargetIP -ScoutSettings $ScoutSettings).HostAgentGUID
    Write-Verbose $SourceGUID
    Write-Verbose $TargetGUID

    Write-Verbose '($temp2.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup.Parameter | Where-Object {$_.Name -eq "SourceHostGUID"}  ).Value'


    ($temp2.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup.Parameter | Where-Object {$_.Name -eq "SourceHostGUID"}  ).Value = $SourceGUID
    ($temp2.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup.Parameter | Where-Object {$_.Name -eq "TargetHostGUID"}  ).Value = $TargetGUID
#endregion
    
#################################get the configured pairs for specified source and target
#region
                    #call the REST api to 
                    try
                    {
                        $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp2 -ContentType "text/xml"
                    }
                    catch
                    {
                        Write-Error "Failed to call API Url $($CXRequestPage)".
                        $Object.ErrorCode = 5
                        $Object.HostIP = $MachineIP
                        $Object.Message = "Failed to call Get Configured Pair API to url : $($CXRequestPage)"
                            #Mark all disk pairings as failed , package and return object
                            foreach ($disk in $DiskArray)
                            {
                                $disk.PairingStatus = $false
                            }
                            $MachineObject.InformationObject = $DiskArray
                            $MachineObjectArray += $MachineObject
                            $Object.MachineObject = $MachineObjectArray

                        return $Object
                    }



                    #check for API call response.
                    if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
                    {
                        Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
                        $Object.ErrorCode = 99
                        $Object.HostIP = $MachineIP
                        $Object.Message = "API call failed with error message : $($Response.StatusDescription)"

                        #Mark all disk pairings as failed , package and return object
                            foreach ($disk in $DiskArray)
                            {
                                $disk.PairingStatus = $false
                            }
                            $MachineObject.InformationObject = $DiskArray
                            $MachineObjectArray += $MachineObject
                            $Object.MachineObject = $MachineObjectArray

                        return $Object
                        return $Object
                    }

                    $ResponseBody = [xml]($Response.Content)
                    if ($ResponseBody.Response.Body.Function.Returncode -eq 2)
                    {
                        $Object.ErrorCode = 3
                        $Object.Message = "No Pairs found"
                        $Object.SourceIP = $SourceIP
                        $Object.SourceGUID = $SourceGUID
                        $Object.TargetIP = $TargetIP
                        $object.TargetGUID = $TargetGUID
                        return $Object
                    }
#endregion


#################################Process existing pairs to create XML for deletion of pairs
#region
                    #else, parse the number of mappingg and populate the deletion pair XML
                    $Object.SourceGUID = $SourceGUID
                    $Object.SourceIP = $SourceIP
                    $Object.TargetGUID = $TargetGUID
                    $Object.TargetIP = $TargetIP

                    $PairCounter = 1
                    $XMLCodeBlock = $temp.CreateElement("Parameter")
                    $XMLCodeBlockAttribute = $temp.CreateAttribute("Name")
                    $XMLCodeBlockAttribute.Value = "TargetHostGUID" | out-null
                    $XMlCodeBlock.Attributes.Append($XMLCodeBlockAttribute) | out-null

                    $XMLCodeBlockAttribute = $temp.CreateAttribute("Value")
                    $XMLCodeBlockAttribute.Value = $TargetGUID
                    $XMlCodeBlock.Attributes.Append($XMLCodeBlockAttribute) | out-null

                    $Temp.Request.Body.FunctionRequest.ParameterGroup.AppendChild($XMLCodeBlock)

                    foreach($Pair in $ResponseBody.Response.Body.Function.FunctionResponse.ParameterGroup.ParameterGroup )
                    {
                        $XMLCodeBlock = $temp.CreateElement("Parameter")
                        
                        $XMLCodeBlockAttribute = $temp.CreateAttribute("Name")      
                        $XMLCodeBlockAttribute.Value = "Device$PairCounter"
                        $XMLCodeBlock.Attributes.Append($XMLCodeBlockAttribute) | out-null

                        $XMLCodeBlockAttribute = $temp.CreateAttribute("Value")      
                        $XMLCodeBlockAttribute.Value = ($pair.Parameter | Where-Object {$_.Name -eq "destDeviceName"}).Value
                        $XMLCodeBlock.Attributes.Append($XMLCodeBlockAttribute)

                        $Temp.Request.Body.FunctionRequest.ParameterGroup.AppendChild($XMLCodeBlock) | out-null

                        $PairCounter +=1

                    }
#endregion


#############################################call deletion of all pairs
#region
                    #call the REST api to 
                    try
                    {
                        $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp -ContentType "text/xml"
                    }
                    catch
                    {
                        Write-Error "Failed to call API Url $($CXRequestPage)".
                        $Object.ErrorCode = 5
                        $Object.HostIP = $MachineIP
                        $Object.Message = "Failed to call Get Configured Pair API to url : $($CXRequestPage)"
                            #Mark all disk pairings as failed , package and return object
                            foreach ($disk in $DiskArray)
                            {
                                $disk.PairingStatus = $false
                            }
                            $MachineObject.InformationObject = $DiskArray
                            $MachineObjectArray += $MachineObject
                            $Object.MachineObject = $MachineObjectArray

                        return $Object
                    }



                    #check for API call response.
                    if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
                    {
                        Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
                        $Object.ErrorCode = 99
                        $Object.HostIP = $MachineIP
                        $Object.Message = "API call failed with error message : $($Response.StatusDescription)"

                        #Mark all disk pairings as failed , package and return object
                            foreach ($disk in $DiskArray)
                            {
                                $disk.PairingStatus = $false
                            }
                            $MachineObject.InformationObject = $DiskArray
                            $MachineObjectArray += $MachineObject
                            $Object.MachineObject = $MachineObjectArray

                        return $Object
                        return $Object
                    }

#endregion
                    #sleep for 10 seconds to allow for pair deletions

                    start-sleep -Seconds 10

#################################################get configured pair and check if deletion was successfull
#region
                    #call the REST api to 
                    $TimeoutTag = New-TimeSpan -Seconds $TimeoutSeconds
                    $Counter = [diagnostics.stopwatch]::StartNew()

                    while ($Counter.Elapsed -le $TimeoutTag)
                    {

                        try
                        {
                            $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp2 -ContentType "text/xml"
                        }
                        catch
                        {
                            Write-Error "Failed to call API Url $($CXRequestPage)".
                            $Object.ErrorCode = 5
                            $Object.HostIP = $MachineIP
                            $Object.Message = "Failed to call Get Configured Pair API to url : $($CXRequestPage)"
                            #Mark all disk pairings as failed , package and return object
                            foreach ($disk in $DiskArray)
                            {
                                $disk.PairingStatus = $false
                            }
                            $MachineObject.InformationObject = $DiskArray
                            $MachineObjectArray += $MachineObject
                            $Object.MachineObject = $MachineObjectArray

                            return $Object
                        }


                        #check for API call response.
                        if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
                        {
                            Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
                            $Object.ErrorCode = 99
                            $Object.HostIP = $MachineIP
                            $Object.Message = "API call failed with error message : $($Response.StatusDescription)"

                            #Mark all disk pairings as failed , package and return object
                            foreach ($disk in $DiskArray)
                            {
                                $disk.PairingStatus = $false
                            }
                            $MachineObject.InformationObject = $DiskArray
                            $MachineObjectArray += $MachineObject
                            $Object.MachineObject = $MachineObjectArray

                            return $Object
                            return $Object
                        }

                        $ResponseBody = [xml]($Response.Content)
                        if ($ResponseBody.Response.Body.Function.Returncode -eq 2)
                        {
                        $Object.ErrorCode = 0
                        $Object.Message = "Pairs successfully deleted"
                        $Object.SourceIP = $SourceIP
                        $Object.SourceGUID = $SourceGUID
                        $Object.TargetIP = $TargetIP
                        $object.TargetGUID = $TargetGUID
                        return $Object
                    }
                    }




                    #is the timeout is completed and 
                    if ($ResponseBody.Response.Body.Function.Returncode -eq 2)
                        {
                            $Object.ErrorCode = 0
                            $Object.Message = "Pairs successfully deleted"
                            $Object.SourceIP = $SourceIP
                            $Object.SourceGUID = $SourceGUID
                            $Object.TargetIP = $TargetIP
                            $object.TargetGUID = $TargetGUID
                            return $Object
                    }
                        else
                        {
                            $Object.ErrorCode = 6
                            $Object.Message = "Pairs Deletion Time out."
                            $Object.SourceIP = $SourceIP
                            $Object.SourceGUID = $SourceGUID
                            $Object.TargetIP = $TargetIP
                            $object.TargetGUID = $TargetGUID
                            return $Object
                        }


#endregion



}





    #Function retrieves Disk/volume pairing from Source -Target IP.
    #currently retrieves only pairing shown in CS Server, and not VHD paths for Hyper-v target
    #TODO : Get target disk information for Windows 
    Function Get-InMageConfiguredPair
    {
        
        Param(
            [parameter(Mandatory=$False)]
            [PSObject]$ScoutSettings = $global:ScoutSettings,
        
        
            [parameter(Mandatory=$True)]
            [String]$SourceIP,

            [parameter(Mandatory=$True)]
            [String]$TargetIP,

            [parameter(Mandatory=$False)]
            [String]$TargetHyperVIP = $null,

            [parameter(Mandatory=$False)]
            [System.Management.Automation.PSCredential]$HyperVCredentials = $null,

            
            [Parameter(Mandatory=$false)]
            [Int]$TimeoutSeconds = 120
            
            )


##########################Local copies of Variables extracted for Function usage
        $CXServerIP = $ScoutSettings.CXServerIP
        $PSServerIP = $ScoutSettings.PSServerIP
        $AUTHMethod = $ScoutSettings.AUTHMethod
        $CXUserName = $ScoutSettings.CXUserName
        $CXPassword = $ScoutSettings.CXPassword
        $CXAccessSignature = $ScoutSettings.CXAccessSignature
        $CXHTTPPort = $ScoutSettings.CXHTTPPort
        $CXRequestPage = $ScoutSettings.CXRequestPage
        $RestApiErrorCodes = $ScoutSettings.RestApiErrorCodes

###########################Custom object##############################

  #get Source Machine Info from CS server.

         <#
            Error Codes
            "0 : No Errors",
            "1 : Error retrieving Source details from CS",
            "2 : Target/Source does not exists in CS",
            "3 : No Pairs found in CS server for specified source-target",
            "4 : Error Calling Delete Pair API to CS server.",
            "5 : Error Calling Get Configured Pair API to CS server."
            "6 : Deletion of Replication Pair's timed out.",
            "7 : Error connecting to Target HyperV server.",
            "8 : Error connecting to target VM on Target Hyper-V",
            "9 : VHD with matching ID not found on target.",
            "99 : Failed to attach VHD to Master Target. Please perform Cleanup."   
    
         #>
            
###############Create Custom Object to store error messages and operation status.
#region
            #This must be returned to parent call for Validation
            $Object = New-Object PSObject
            $Object | Add-Member -Type NoteProperty -Name SourceIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name SourceGUID -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetIP -Value $null
            $Object | Add-Member -Type NoteProperty -Name TargetGUID -Value $null     # include object $machineObject declared below.
            $Object | Add-Member -Type NoteProperty -Name TargetHyperV -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCode -Value $null
            $Object | Add-Member -Type NoteProperty -Name Message -Value $null
            $Object | Add-Member -Type NoteProperty -Name DiskPairing -Value $null
            $Object | Add-Member -Type NoteProperty -Name ErrorCodeTable -Value ("0 : No Errors",
                                                                                "1 : Error retrieving Source details from CS",
                                                                                "2 : Target/Source does not exists in CS",
                                                                                "3 : No Pairs found in CS server for specified source-target",
                                                                                "4 : Error Calling Delete Pair API to CS server.",
                                                                                "5 : Error Calling Get Configured Pair API to CS server.",
                                                                                "6 : Deletion of Replication Pair's timed out.",
                                                                                "7 : Error connecting to Target HyperV server.",
                                                                                "8 : Error connecting to target VM on Target Hyper-V",
                                                                                "9 : VHD with matching ID not found on target.",
                                                                                "99 : Failed to attach VHD to Master Target. Please perform Cleanup.","99 : Generic Error)")


            #custom object containing disk pair information
            $DiskPair =  New-Object PSObject
            $DiskPair | Add-Member -Type NoteProperty -Name SourceDevice -Value $null
            $DiskPair | Add-Member -Type NoteProperty -Name TargetDevice -Value $null
            $DiskPair | Add-Member -Type NoteProperty -Name TargetVHDPath -Value $null

            $DiskPairs = @()

#endregion

########################## XML body for Getting configured pair
#region

[xml]$GetConfiguredPair =
@'
<Request Id="0001" Version="1.0">
 	<Header>
  		<Authentication>
    		<AccessKeyID>DDC9525FF275C104EFA1DFFD528BD0145F903CB1</AccessKeyID>
    		<AccessSignature></AccessSignature>
  		</Authentication>
 	</Header>
 	<Body>
  		<FunctionRequest Name="GetConfiguredPairs" Include="No">
		<ParameterGroup Id="HostLists">
		<ParameterGroup Id="HostList_1">
			<Parameter Name="SourceHostGUID" Value="082F3A9A-24D2-AE41-9C1BCBC99D8FBCD6" />
			<Parameter Name="TargetHostGUID" Value="5D99E358-B2A3-224F-A98887B9E36758AC" />
		</ParameterGroup>
		</ParameterGroup>
 		 </FunctionRequest>
 	</Body>
</Request>
'@

#endregion
#############################################################################
#region

#configure settings for XML file header
$temp = $GetConfiguredPair.Clone()


#Configure settings for XML get configured pair
    
    $SourceGUID = (List-InMageRegisteredHosts -MachineIP $SourceIP -ScoutSettings $ScoutSettings).HostAgentGUID
    $TargetGUID = (List-InMageRegisteredHosts -MachineIP $TargetIP -ScoutSettings $ScoutSettings).HostAgentGUID

    ($temp.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup.Parameter | Where-Object {$_.Name -eq "SourceHostGUID"}  ).Value = $SourceGUID
    ($temp.Request.Body.FunctionRequest.ParameterGroup.ParameterGroup.Parameter | Where-Object {$_.Name -eq "TargetHostGUID"}  ).Value = $TargetGUID
#endregion
    
#################################get the configured pairs for specified source and target
#region
                    #call the REST api to 
                    try
                    {
                        $Response = Invoke-WebRequest -Uri $CXRequestPage -Method POST -Body $Temp -ContentType "text/xml"
                    }
                    catch
                    {
                        Write-Error "Failed to call API Url $($CXRequestPage)".
                        $Object.ErrorCode = 5
                        $Object.SourceIP = $SourceIP
                        $Object.Message = "Failed to call Get Configured Pair API to url : $($CXRequestPage)"
                        $object.SourceGUID = $SourceGUID
                        $Object.TargetGUID = $TargetGUID
                        $Object.TargetIP = $TargetIP 
                        Remove-PSSession $PSSession   
                        return $Object
                    }



                    #check for API call response.
                    if (  $RestApiErrorCodes.contains($Response.StatusCode) -eq $true )
                    {
                        Write-Error "The REST Api call failed with error : $($Response.StatusDescription)." 
                        $Object.ErrorCode = 99
                        $Object.SourceIP = $SourceIP
                        $object.SourceGUID = $SourceGUID
                        $Object.TargetGUID = $TargetGUID
                        $Object.TargetIP = $TargetIP
                        $Object.Message = "API call failed with error message : $($Response.StatusDescription)"
                        Remove-PSSession $PSSession
                        Return $Object
                    }

                    $ResponseBody = [xml]($Response.Content)
                    if ($ResponseBody.Response.Body.Function.Returncode -eq 2)
                    {
                        $Object.ErrorCode = 3
                        $Object.Message = "No Pairs found"
                        $Object.SourceIP = $SourceIP
                        $Object.SourceGUID = $SourceGUID
                        $Object.TargetIP = $TargetIP
                        $object.TargetGUID = $TargetGUID
                        return $Object
                    }

                    #else, get disk pair and return object
                    foreach ($Pair in $ResponseBody.Response.Body.Function.FunctionResponse.ParameterGroup.ParameterGroup)
                    {
                        $DiskPairTemp = $DiskPair | select *
                        $diskPair.Parameter
                        $DiskPairTemp.SourceDevice = ($Pair.Parameter | Where-Object {$_.Name -eq "sourceDeviceName"}).Value
                        $DiskPairTemp.TargetDevice = ($Pair.Parameter | Where-Object {$_.Name -eq "destDeviceName"}).Value
                        $DiskPairs += $DiskPairTemp
                    }

                    #$DiskPairs
                    #package objects 

                    $Object.SourceIP = $SourceIP
                    $Object.SourceGUID = $SourceGUID
                    $Object.TargetIP = $TargetIP
                    $Object.TargetGUID = $TargetGUID
                    $Object.DiskPairing = $DiskPairs
                    $object.ErrorCode = 0
                    $Object.Message = "Operation completed successfully."


#endregion
###########################################################################
#we check if Hyper-V IP is provided ,we will try to get Disk VHD path 
#region
                        if ( ($TargetHyperVIP -ne $null) -and ($HyperVCredentials -ne $null ) )
                        {
                    

                                    #Validate if the HyperV server can be connected to .
                                    #Assumption : Target Hyper-V Server is currently a single host.
                                    try
                                    {
                                        $PSSession = New-PSSession -ComputerName $TargetHyperVIP -Credential $HyperVCredentials 
                                    }
                                    catch
                                    {
                            $Object.ErrorCode = 7
                            $Object.Message = "Error connecting to HyperV Server $TargetHyperVIP."
                            Remove-PSSession $PSSession
                            return $Object     
                        }
                        
                                    #get Target Host details.
                                    $TargetObject = Get-InMageHostDetails -MachineIP $TargetIP -ScoutSettings $ScoutSettings

                                    #get Target's MAC address for fetching VM details from HyperV
                                    $TargetObject = Get-InMageHostDetails -MachineIP $TargetIP -ScoutSettings $ScoutSettings
                                    $TargetXML = [xml]($TargetObject.HostDetailsXML)
                                    $TargetDisks = $TargetXML.FunctionResponse.ParameterGroup[0].ParameterGroup
                                    $TargetNICS = ($TargetXML.FunctionResponse.ParameterGroup | Where-Object {$_.Id -eq "MacAddressList"}).ParameterGroup
                                    #get the Mac address
                                    $TargetMAC  = ($TargetNICS[0].Parameter | Where-Object {$_.Name -eq "MacAddress"}).Value
                                    $TargetMAC = ($TargetMAC.Replace(":","")).ToUpper()
                                    #search the Hyper-V for VM with specified NIC
                                    #TODO : update the code if you intend to search cluster or VMM
                    
                        
                                    $VMName = Invoke-Command -Session $PSSession -ArgumentList $TargetMAC -ScriptBlock {
                                $MAC = $args[0];
                                $VMName = (get-VM | Get-VMNetworkAdapter | Where-Object {$_.MacAddress -eq "00155D05F11A"}).VMName;
                                return $VMName                 
                                }
                                    if ([string]::IsNullOrEmpty($VMName))
                                    {
                        $Object.ErrorCode = 8
                        $Object.Message = "Master Target $TargetIP not found on HyperV Server $TargetHyperVIP"
                        Remove-PSSession $PSSession
                        return $Object
                    }


                                #get Target OS type
                                $OSType = ($TargetXML.FunctionResponse.Parameter | Where-Object {$_.Name -eq "OsType"}).Value
                    
                                if ($OSType -eq "Linux")
                                {
                                    foreach($disk in $object.Diskpairing)
                                    {
                                    $TargetDevice = $Disk.TargetDevice
                                    #get the disk object from TargetXML
                                    $TargetDisk = $TargetDisks | Where-Object { ($_.Parameter | Where-Object {$_.Name -eq "DiskName"} ).Value -eq  $targetDevice }

                                    $TargetSCSIID = (($TargetDisk.Parameter | Where-Object {$_.Name -eq "ScsiId"}).Value).Trim()
                                    #Get the last 12 char of the SCSIID , which will be used to match the VHD from hyper-V 
                                    $MatchID = $TargetSCSIID.Substring($TargetSCSIID.length - 12, 12)

                                    #get the VHD from Hyper-V which matches the scsi ID
                                    $VHDPath = Invoke-Command -Session $PSSession -ScriptBlock{
                                                    $VMName = $args[0];
                                                    $MatchID = $args[1];

                                                    $VM = get-VM -Name $VMname;
                                                    ($VM | select VMId | get-VHD | Where-Object {$_.DiskIdentifier -like "*$MatchID"}).Path
                                                    } -ArgumentList $VMName,$MatchID

                                    if($VHDPath -eq $null)
                                    {
                                        #no VHD's found for some reason,
                                        $Object.ErrorCode = 9
                                        $Object.Message = "VHd not found on target $TargetIP, on HypepV Server : $TargetHyperVIP."
                                        $Disk.TargetVHDPath = "Unknown"
                                    }
                                    else
                                    {
                                        $Disk.TargetVHDPath = $VHDPath
                                    }                            
                    
                                    }
                                }    
                                else
                                {
                                    #populate code for Windows as it uses a different logic
                                }

                                #delete the PSSsession
                                Remove-PSSession $PSSession
                     }
                     
#endregion
                    #$return object to parent call
                    return $Object


}


    

    Function IPCalculator
    {
    <#
.SYNOPSIS
ipcalc calculates the IP subnet information based
upon the entered IP address and subnet. 
.DESCRIPTION
ipcalc calculates the IP subnet information based
upon the entered IP address and subnet. It can accept
both CIDR and dotted decimal formats.
By: Jason Wasser
Date: 10/29/2013
.PARAMETER IPAddress
Enter the IP address by itself or with CIDR notation.
.PARAMETER Netmask
Enter the subnet mask information in dotted decimal 
form.
.EXAMPLE
ipcalc.ps1 -IPAddress 10.100.100.1 -NetMask 255.255.255.0
.EXAMPLE
ipcalc.ps1 10.10.100.5/24
#>
param (
    [Parameter(Mandatory=$True,Position=1)]
    [string]$IPAddress,
    [Parameter(Mandatory=$False,Position=2)]
    [string]$Netmask
    )

function toBinary ($dottedDecimal){
 $dottedDecimal.split(".") | %{$binary=$binary + $([convert]::toString($_,2).padleft(8,"0"))}
 return $binary
}
function toDottedDecimal ($binary){
 do {$dottedDecimal += "." + [string]$([convert]::toInt32($binary.substring($i,8),2)); $i+=8 } while ($i -le 24)
 return $dottedDecimal.substring(1)
}

function CidrToBin ($cidr){
    if($cidr -le 32){
        [Int[]]$array = (1..32)
        for($i=0;$i -lt $array.length;$i++){
            if($array[$i] -gt $cidr){$array[$i]="0"}else{$array[$i]="1"}
        }
        $cidr =$array -join ""
    }
    return $cidr
}

function NetMasktoWildcard ($wildcard) {
    foreach ($bit in [char[]]$wildcard) {
        if ($bit -eq "1") {
            $wildcardmask += "0"
            }
        elseif ($bit -eq "0") {
            $wildcardmask += "1"
            }
        }
    return $wildcardmask
    }


# Check to see if the IP Address was entered in CIDR format
if ($IPAddress -like "*/*") {
    $CIDRIPAddress = $IPAddress
    $IPAddress = $CIDRIPAddress.Split("/")[0]
    $cidr = [convert]::ToInt32($CIDRIPAddress.Split("/")[1])
    if ($cidr -le 32 -and $cidr -ne 0) {
        $ipBinary = toBinary $IPAddress
        $smBinary = CidrToBin($cidr)
        $Netmask = toDottedDecimal($smBinary)
        $wildcardbinary = NetMasktoWildcard ($smBinary)
        }
    else {
        Write-Warning "Subnet Mask is invalid!"
        Exit
        }
    }
else {
    if (!$Netmask) {
        $Netmask = Read-Host "Netmask"
        }
    $ipBinary = toBinary $IPAddress
    if ($Netmask -eq "0.0.0.0") {
        Write-Warning "Subnet Mask is invalid!"
        Exit
        }
    else {
        $smBinary = toBinary $Netmask
        $wildcardbinary = NetMasktoWildcard ($smBinary)
        }
    }

#how many bits are the network ID
$netBits=$smBinary.indexOf("0")
if ($netBits -ne -1) {
    $cidr = $netBits
    #validate the subnet mask
    if(($smBinary.length -ne 32) -or ($smBinary.substring($netBits).contains("1") -eq $true)) {
        Write-Warning "Subnet Mask is invalid!"
        Exit
        }
    #validate that the IP address
    if(($ipBinary.length -ne 32) -or ($ipBinary.substring($netBits) -eq "00000000") -or ($ipBinary.substring($netBits) -eq "11111111")) {
        Write-Warning "IP Address is invalid!"
        Exit
        }
    #identify subnet boundaries
    $networkID = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"0"))
    $firstAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"0") + "1")
    $lastAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"1") + "0")
    $broadCast = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"1"))
    $wildcard = toDottedDecimal ($wildcardbinary)
    $networkIDbinary = $ipBinary.substring(0,$netBits).padright(32,"0")
    $broadCastbinary = $ipBinary.substring(0,$netBits).padright(32,"1")
    $Hostspernet = ([convert]::ToInt32($broadCastbinary,2) - [convert]::ToInt32($networkIDbinary,2)) - 1
   }
else {
    #identify subnet boundaries
    $networkID = toDottedDecimal $($ipBinary)
    $firstAddress = toDottedDecimal $($ipBinary)
    $lastAddress = toDottedDecimal $($ipBinary)
    $broadCast = toDottedDecimal $($ipBinary)
    $wildcard = toDottedDecimal ($wildcardbinary)
    $Hostspernet = 1
    }


#Results

$Object = New-Object psobject

$object | add-member -MemberType NoteProperty -Name "Address" -Value $IPAddress
$object | add-member -MemberType NoteProperty -Name "Netmask" -Value $Netmask
$object | add-member -MemberType NoteProperty -Name "NetmaskCIDR" -Value $cidr
$object | add-member -MemberType NoteProperty -Name "Wildcard" -Value $wildcard
$object | add-member -MemberType NoteProperty -Name "Network" -Value "$networkID/$cidr"
$object | add-member -MemberType NoteProperty -Name "Broadcast" -Value $broadCast
$object | add-member -MemberType NoteProperty -Name "HostMin" -Value $firstAddress
$object | add-member -MemberType NoteProperty -Name "HostMax" -Value $lastAddress
$object | add-member -MemberType NoteProperty -Name "Hosts" -Value $Hostspernet

return $object


    }
