###############Install Agent Script Demo######################
<#
About :
This script is a demo code for demonstrating InMage agent installation on multiple machines, using the InMage Scout API Module.
The input is a CSV file with machine IP.
This script will attempt to identify the Source Machine OS and deploy the correct agent.
The current script uses a settings.XML to store Windows and Linux credentials.

End users are free to use their own means of providing settings for Agent installation

The script will produce another CSV with populated results which will be used for subsequent demo scripts "Protect" and "Failover"

#>




#parameters to input
    param
    (
        # Settings file
        #####This file contains Scout specific settings to be used during migration.
        [parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]$ConfigFile="C:\ASR\V2H\Scripts\Settings.xml",
       
        #this is file generated from Agent installation process. Please use this file to update any changes for Source, Target and Hyper-V. 
        [parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]$MachineFileName="C:\ASR\V2H\Scripts\Machines.CSV",


        # this file will be used for Performing Failover. Please preserve this output file.
        [parameter(Mandatory=$false)]
        [String]$OutputMachineFile="C:\ASR\V2H\Scripts\Machines.CSV",

        #This is a input parameter for ASR Scout Web service credential.
        [parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$CXCredential

       )
       



       #read the Settings.xML
        #read the Settings File
        $MigrationSetting = [xml](Get-Content $ConfigFile)
        #read the Migration  File
        $MachineFile = import-CSV -Path $MachineFileName
        $MachineFile |ft


        #nullify the Scout Setting object and re-init it 
        #Module should do it, but we are doing it any way as a workaround for an issue

            $ScoutSettings = $null
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

        #Important:
        #Hyper-V Credentials in Settings File is universal for Hyper-V host or Hyper-V cluster(future release)
        #Windows Credentials in settings File is universal in case Specific machine credentials are not provided. Same goes for Linux.
        #Linux Protection does not requires Credentials for Source or MasterTarget to initiate and trigger failover.
        #Windows requires Credentials for both source and target as volumes need to be mounted and identified. Linux replication is disk to disk.

        # Clustered disks on source are not supported in this release.
        # Disks with Multipath are not supported in this release
        # Linux OS detection requires OS credentials with access to /etc/os-release  file   and "uname -a"  command

#################################3#################perform input validation########################################
#region
                                if( [string]::IsNullOrEmpty($OutputMachineFile))
                                {
                                $OutputMachineFile = $MachineFileName
                                }
            
                        
                                ########Create Log file in specified directory.
                                ########Write-host "Initializing workflow logging." -foregroundcolor Green
                                ########initialize logging and return the Log file name
                                        $logDirectory = $MigrationSetting.Settings.ToolSettings.LogPath
                                        $logFile = "$(Get-date -Format MM_dd_yyyy-mm_hh).log"
                                        if ($logDirectory.Endswith("\"))
                                        {
                                            $logPath = $logDirectory + $logFile
                                        }
                                        else
                                        {
                                            $logPath = $logDirectory + "\" + $logFile
                                        }
                                     

                                        Write-host "Reading Module path and loading InMage API Powershell Module." -ForegroundColor Green

                                                                                
                                        
                                        #Write-Log -Message "Loading InMage Powershell API Module." -Path $logPath -Level Info 


                                        <#
                                        Updated Code : 30th July 2016
                                        Checks for module in local directory then goes for Settings.XML
                                        #>

                                        $PSRoot = $PSScriptRoot
                                        $ModulePath = Get-ChildItem -Filter "InMage-RESTModule.PSM1" -Path $PSRoot
                                        if  (($ModulePath -eq $null) -or ($ModulePath.Count -gt 1))
                                        {
                                            #import module from Settings.XML
                                            $ModulePath = $MigrationSetting.Settings.ToolSettings.ModulePath
                                        }
                                        else
                                        {
                                            $ModulePath = $ModulePath.FullName
                                        }

                                        
                                        Write-host "Loading module from : $ModulePath" -ForegroundColor Green
                                        #import the InMage API module
                                        try
                                        {
                                            Import-module $ModulePath
                                        }
                                        catch
                                        {
                                            #Write-Log -Message "Failed to load Powershell Module. Specified Module Path was : $ModulePath" -Path $logPath -Level Error
                                            Write-host "Failed to load Powershell Module. Specified Module Path was : $ModulePath" -ForegroundColor Red
                                            return 1
                                        }


                                        Write-Log -Message "Starting process for VM/Machine protection." -Path $logPath -Level Info 
                                        Write-host "Welcome to VMWare to Hyper-V Migration toolkit." -ForegroundColor Green


                                        Write-log -Message "Initializing Scout Connection" -Path $logPath -Level Info
                                        Write-host "`t* Initializing Scout Connection" -ForegroundColor Cyan


                                        #inline script block to populate Scout settings.
                                        $ScoutSettings.CXServerIP = $MigrationSetting.Settings.Scout.CXIPAddress
                                        $ScoutSettings.PSServerIP = $MigrationSetting.Settings.Scout.PSIPAddress
                               
                                        $ScoutSettings.CXUserName = $CXCredential.GetNetworkCredential().UserName
                                        $ScoutSettings.CXPassword = $CXCredential.GetNetworkCredential().Password
                                
                                        #Function processes and returns the ScoutSettings object with updated value, and encrypted MD5 checksum for Password.
                                        #this function is mandatory.
                                        $ScoutSettings =  Initialize-InMageProtectionEnvironment -ScoutSettings $ScoutSettings

                                        
                                        #get Windows and Linux credentials
                                        $Windowsuser = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Windows"}).UserName
                                        $WindowsPassword = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Windows"}).Password
                                        $WindowsDomain = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Windows"}).domain

                                        $secpasswd = ConvertTo-SecureString $WindowsPassword -AsPlainText -Force
                                        if( [string]::IsNullOrEmpty($WindowsDomain ))
                                        {
                                            $WindowsDomain = "."
                                        }

                                        #create Windows credential Object
                                        $WinCred = New-Object System.Management.Automation.PSCredential ("$WindowsDomain\$Windowsuser", $secpasswd)



                                        #create Linux credential Object
                                        $Linuxuser = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Linux"}).UserName
                                        $LinuxPassword = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Linux"}).Password
                                            

                                        $secpasswd = ConvertTo-SecureString $LinuxPassword -AsPlainText -Force
                                        $LinCreds = New-Object System.Management.Automation.PSCredential ($Linuxuser, $secpasswd)
                                


#endregion



###########################################Process the CSV file for Machines.
#region


    #rewamping entire code block to reflect new job tracking mechanism
    #clean all jobs for this scripting session
    get-job | remove-Job -Force 
    

     foreach ($machine in $MachineFile)
     {
        #$Machine should be an IP address
            $SourceIP = $machine.SourceIP
            
            Write-host "Running Installer for Machine :$SourceIP."
            Write-Log "Running Installer for Machine :$SourceIP." -Path $logPath -Level Info

            #Check if IP is already registered in CS Server.
            $GetHostDetails = List-InMageRegisteredHosts -MachineIP $SourceIP -ScoutSettings $ScoutSettings
            
            if ($GetHostDetails -ne $null)
            {
                    $Machine.SourceAgentGUID = $GetHostDetails.HostAgentGUID
                    #populate OS details
                $MachineDetails = Get-InMageHostDetails -MachineIP $SourceIP -ScoutSettings $ScoutSettings
                $MachineXML = [XML]($MachineDetails.HostDetailsXML)
                $machine.OSType = ($machineXML.FunctionResponse.Parameter | Where-Object {$_.Name -eq "OsType"}).Value
                $machine.OSBuild = ($machineXML.FunctionResponse.Parameter | Where-Object {$_.Name -eq "Caption"}).Value + "_" + ($machineXML.FunctionResponse.Parameter | Where-Object {$_.Name -eq "CPUArchitecture"}).Value
                $machine.AgentStatus = "Healthy"
                
                Write-Host "Source IP : $SourceIP is already registered with Agent GUID : $($Machine.SourceAgentGUID)." -ForegroundColor Green
                Write-Log "Source IP : $SourceIP is already registered with Agent GUID : $($Machine.SourceAgentGUID)." -Path $logPath -Level Info
            }
            else
            {
                #install OS Sequence
                    #Check OS type
                    $OSType = Get-OSBuild -ComputerName $SourceIP            
                    if ($OSType.OSVersion -eq "Unknown")
                    {
                        $machine.AgentStatus = "Failed"
                        $machine.SourceAgentGUID = "Unknown"
                        $machine.OSType = "Unknown"
                    }


                    #call the Function again to get OS specs.
                    if ($OSType.OSVersion -eq "Linux")
                    {
                        $OSType = Get-OSBuild -ComputerName $SourceIP -OSCredential $LinCreds            
                        $HostOS = $OSType.OSVersion
                        if ($HostOS -Like "*CENTOS*")
                        {
                            $HostOS = $HostOS.replace("CENTOS","RHEL")
                        }

                        if ($HostOS -Like "*6U*")
                        {
                            $Version = $HostOS.Substring(($HostOS.Length -3 ),3)
                            $HostOS = $HostOS.Replace($Version,"6")
                        }


                        
                        
                        if ($OSType.OSArchitecture -eq "x86")
                        {
                            $HostOS += "-32"
                        }
                        else
                        {
                            $HostOS += "-64"
                        } 
                        
                        $machine.OSType = "Linux"
                        $machine.OSBuild = $HostOS
                        
                        
                        #Call the install function
                        #TODO : Put this code in Job
                        #Job ID is Machine IP
                        
                        $jobID = $SourceIP

                        Start-Job -scriptblock { 
                            
                            Import-module $args[0] | out-null;
                            Install-InMageHostAgent -MachineIP $args[1] -HostOS $args[2] -HostCredential $args[3] -ScoutSettings $args[4] -WaitforCompletion
                            
                            } -ArgumentList $ModulePath,$SourceIP,$HostOS,$LinCreds,$ScoutSettings -Name $jobID
                           
                    }
                    else
                    {
                        $machine.OSType = "Windows"
                        $Machine.OSBuild = "Windows"
                        
                            $Job = Start-Job -scriptblock { 
                            Import-module $args[0];Install-InMageHostAgent -MachineIP $args[1] -HostOS $args[2] -HostCredential $args[3] -ScoutSettings $args[4] -WaitforCompletion
                            } -ArgumentList $ModulePath,$SourceIP,"Windows",$WinCred,$ScoutSettings -Name $SourceIP
                        
                    }
                    $machine.AgentStatus = "Installing"   
            }
    }

        #start counter
    #if counter > 10 min, stop everything and update sheet
    $TimeoutLimit = New-TimeSpan -Seconds 120
    $StopWatch = [diagnostics.stopwatch]::StartNew()

    $jobs = get-job

While( ($jobs.Count -gt 0) -or ($StopWatch.Elapsed -le $timeout) )
    {
        foreach ($job in $jobs)
        {
            $SourceMatchVariable = $job.Name
            if ($job.State -eq "Failed")
            {
                ($MachineFile | Where-Object {$_.SourceIP -eq "$SourceMatchVariable"}).AgentStatus = "Failed"
                $job | Remove-Job -Force
                Continue
            }
            if ($job.State -eq "Completed")
            {
                $Response = $Job | receive-job -Keep
                if ($response.ErrorCode -eq 0)
                {
                    #Client installed
                    ($MachineFile | Where-Object {$_.SourceIP -eq "$SourceMatchVariable"}).AgentStatus = "Healthy"
                    $job | Remove-Job -Force
                    Continue
                }
                if ( ($response.ErrorCode -eq 12) -or ($response.ErrorCode -eq 3))
                {
                    #Client installation is pending, but the job has timed out. Mark agent health as pending
                    ($MachineFile | Where-Object {$_.SourceIP -eq "$SourceIP"}).AgentStatus = "Pending"
                    $job | Remove-Job -Force
                    Continue
                }
                else
                {
                    ($MachineFile | Where-Object {$_.SourceIP -eq "$SourceMatchVariable"}).AgentStatus = "Error"
                    $job | Remove-Job -Force
                    Continue
                }
            }
            else
            {
                continue
            }

        }
        $jobs = get-job
    }



    #write the Machine file to output.
    Write-host "Writing Machine file to output path : $OutputMachineFile." -ForegroundColor Green
    $MachineFile | export-csV -LiteralPath $OutputMachineFile 




#endregion