#################################################ASR Scout VM protection Script#################################################33


#parameters to input
    param
    (
        # Settings file
        #####This file contains Scout specific settings to be used during migration.
        [parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]$ConfigFile="C:\Users\Administrator.ASR-CS\Desktop\Settings.xml",
       
        #this is file generated from Agent installation process. Please use this file to update any changes for Source, Target and Hyper-V. 
        [parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]$MachineFileName="C:\Users\Administrator.ASR-CS\Desktop\MachineProtection.CSV",


        # this file will be used for Performing Failover. Please preserve this output file.
        [parameter(Mandatory=$false)]
        [String]$OutputMachineFile="C:\Users\Administrator.ASR-CS\Desktop\Machines_op.CSV",

        #This is a input parameter for ASR Scout Web service credential.
        [parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$CXCredential,


        [Switch]$ProtectWindows,
        
        [Switch]$ProtectLinux      
        
       )
       
       
       
       
       
####################################################################################################################################



#endregion





    #read the Settings File
        $MigrationSetting = [xml](Get-Content $ConfigFile)
    #read the Migration  File
        $MachineFile = import-CSV -Path $MachineFileName


        Write-host "The Machine file output : " -ForegroundColor Cyan
        $MachineFile | ft
    #Important:
        #Hyper-V Credentials in Settings File is universal for Hyper-V host or Hyper-V cluster(future release)
        #Windows Credentials in settings File is universal in case Specific machine credentials are not provided. Same goes for Linux.
        #Linux Protection does not requires Credentials for Source or MasterTarget to initiate and trigger failover.
        #Windows requires Credentials for both source and target as volumes need to be mounted and identified. Linux replication is disk to disk.

        # Clustered disks on source are not supported in this release.
        # Disks with Multipath are not supported in this release
        # Linux OS detection requires OS credentials with access to /etc/os-release  file   and "uname -a"  command
        #Important:
        #Hyper-V Credentials in Settings File is universal for Hyper-V host or Hyper-V cluster(future release)
        #Windows Credentials in settings File is universal in case Specific machine credentials are not provided. Same goes for Linux.
        #Linux Protection does not requires Credentials for Source or MasterTarget to initiate and trigger failover.
        #Windows requires Credentials for both source and target as volumes need to be mounted and identified. Linux replication is disk to disk.

        # Clustered disks on source are not supported in this release.
        # Disks with Multipath are not supported in this release
        # Linux OS detection requires OS credentials with access to /etc/os-release  file   and "uname -a"  command


    
############################################### Declare all custom objects
#region

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

    
  
#endregion

#################perform input validation
                                if( [string]::IsNullOrEmpty($OutputMachineFile))
                                {
                                $OutputMachineFile = $MachineFile
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
                                     
                                        Write-Log -Message "Starting process for VM/Machine protection." -Path $logPath -Level Info 
                                        Write-host "Welcome to VMWare to Hyper-V Migration toolkit." -ForegroundColor Green
                                #load module
                                #Updated Code : 30th July 2016
                                #Checks for module in local directory then goes for Settings.XML
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

                                
                                Import-module $ModulePath -WarningAction SilentlyContinue



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
                                if ($ScoutSettings -eq 1)
                                {
                                    Write-host "Failed to connect to  CX Server. Exiting."
                                    Write-Log "Failure to connect to CX Server. Exiting code." -Path $logPath -Level Error
                                    return
                                }


                               
                                #Main block begins here
                                #TODO : Auto assign Mastertarget to each source VM/Machine, if the same is not provided
                                #TODO : Auto assign process server if the same is not defined.
                                #TODO : allow targeting to Hyper-V Cluster/SCVMM
                                #TODO : allow checking of input VM as having correct OS , properly filled target information
                                Write-host "`t`t*Validating Source Machine Parameters." -foregroundcolor Green
                                Write-log -Message "Validating Source Machine Parameters" -Path $logPath -Level Info

#########################################first check if all machines are properly valid
                                        Write-host "Validating Machines in Machine File." -ForegroundColor Green
                                        
                                        foreach ($machine in $MachineFile)
                                        {
                                            #check if Agent is registered or not.
                                            if ( ([string]::IsNullOrempty($machine.SourceAgentGUID) -eq $false) )
                                            {
                                                #get Agent details using GUID
                                                $AgentDetails = List-InMageRegisteredHosts -MachineGUID $Machine.SourceAgentGUID -ScoutSettings $ScoutSettings

                                                if ($AgentDetails -eq $null)
                                                {
                                                    #IP address was not found in CS server.
                                                    $machine.ProtectionStatus = "Failed"
                                                    $machine.ProtectAction = "No"
                                                    $machine.AgentStatus = "Not Registered"
                                                    $machine.SourceAgentGUID = ""
                                                    $machine.Message = "Source GUID is not registered in CS Server"
                                                }
                                                else
                                                {
                                                        $machine.SourceAgentGUID = $AgentDetails.HostAgentGUID
                                                        #update the Ip address anyway
                                                        $machine.SourceIP = $AgentDetails.HostIP
                                                        $machine.AgentStatus = "Healthy"
                                                }

                                            }
                                            else
                                            {
                                                #check using IP address instead
                                                $AgentDetails = List-InMageRegisteredHosts -MachineIP $Machine.SourceIP -ScoutSettings $ScoutSettings
                                                if ($AgentDetails -eq $null)
                                                {
                                                    $machine.ProtectionStatus = "Failed"
                                                    $machine.ProtectAction = "No"
                                                    $machine.AgentStatus = "Not Registered"
                                                    $machine.SourceAgentGUID = ""
                                                    $machine.Message = "Source IP is not registered in CS Server"
                                                }
                                                else
                                                {
                                                        $machine.SourceAgentGUID = $AgentDetails.HostAgentGUID
                                                        #update the Ip address anyway
                                                        $machine.SourceIP = $AgentDetails.HostIP
                                                        $machine.AgentStatus = "Healthy"
                                                }
                                            }


                                            #Check for Source OS and Master Target OS match from healthy agents
                                            if ($Machine.AgentStatus -eq "Healthy")
                                            {
                                                $SourceDetails = Get-InMageHostDetails -MachineIP $machine.SourceIP -ScoutSettings $ScoutSettings
                                                $TargetDetails = Get-InMageHostDetails -MachineIP $machine.TargetIP -ScoutSettings $ScoutSettings
                                                
                                                if($TargetDetails.ErrorCode -ne 0)
                                                {
                                                    $machine.ProtectionStatus = "Failed"
                                                    $machine.ProtectAction = "No"
                                                    $machine.Message = "Target IP is not registered in CS Server"
                                                    Continue
                                                }
                                                
                                                
                                                $SourceOSType =   (([xml]($SourceDetails.HostDetailsXML)).FunctionResponse.Parameter | where-object {$_.Name -eq "OsType"}).Value
                                                $TargetOSType = (([xml]($TargetDetails.HostDetailsXML)).FunctionResponse.Parameter | where-object {$_.Name -eq "OsType"}).Value

                                                if ($SourceOSType -ne $TargetOSType)
                                                {
                                                    $machine.ProtectionStatus = "Failed"
                                                    $machine.ProtectAction = "No"
                                                    $machine.Message = "Source and Target OS Type do not match."
                                                    continue
                                                }
                                                else
                                                {
                                                    $machine.OSType = $SourceOSType
                                                    $machine.TargetOS = $TargetOSType
                                                }
                                            }
                                        }

####################################################Main protection code starts here##############################3
#region

                                #loop through all machines and get Disk information
                                #delete all existing jobs on this powershell window
                                Write-host "Warning : all jobs on this powershell session are being flushed." -ForegroundColor Red
                                write-log "flushing All jobs on host powershell machine." -Path $logPath -Level Warn
                                get-job | remove-job -Force


                                #loop through all machines and run parallel jobs for executing machine protection
                                foreach ($machine in $MachineFile)
                                {
                                    if ( ($machine.AgentStatus -eq "Healthy") -and ($Machine.OSType -eq "Linux"))
                                    {

                                                    $SourceIP = $machine.SourceIP
                                                    $TargetIP = $machine.TargetIP
                                                    $TargetOS = $machine.OSType
                                                    $HyperVIP = $machine.HyperVIP
                                                    $VHDPath = $machine.TargetVHDPath
                                                    $HyperVHost = $MigrationSetting.Settings.HyperV.Host | Where-Object {$_.IPAddress -eq $Machine.HyperVIP}
                                                    $TargetOS = $machine.TargetOS

                                                    #read and validate the Hyper-V Credentials
                                                    if ($HyperVHost -eq $null)
                                                    {
                                                        Write-Log "Protection for machine $sourceIP has failed." -Path $logPath -Level Error
                                                        Write-Host "`t`t`tProtection for machine $sourceIP has failed." -ForegroundColor Red
                                                        $machine.ProtectionStatus = "Failed"
                                                        $Machine.Message = "Hyper-V Details missing in Migration XML."
                                                    }
                                                    else
                                                    {
                                                        $HVUser = $HyperVHost.Username
                                                        $HVPass = $HyperVHost.Password
                                                        $secpasswd = ConvertTo-SecureString $HVPass -AsPlainText -Force
                                                        $HVcreds = New-Object System.Management.Automation.PSCredential ($HVUser, $secpasswd)
                                                    }


                                                    #call the function Protect-inmageMachine to protect all disks in specified machine.

                                                    $JobName = $machine.SourceIP
                                                    
                                                    $job = Start-Job -Name $JobName -ScriptBlock {
                                                                $SourceIP = $args[0];
                                                                $TargetIP = $args[1];
                                                                $TargetOS = $args[2];
                                                                $HyperVIP = $args[3];
                                                                $VHDPath = $args[4];
                                                                $cred = $args[5];
                                                                $HyperVHost = $args[6];
                                                                $ScoutSettingsSource = $args[7];
                                                                $ModulePath = $args[8];
                                                                import-module $ModulePath | out-null
                                                                Protect-InMageMachine -ScoutSettings $ScoutSettingsSource -SourceIP $SourceIP -TargetIP $TargetIP -TargetHyperVIP $HyperVIP -TrgHyperVCmpCredential $cred -OSbuild $TargetOS -TargetVHDPath $VHDPath 
                                                                } -ArgumentList $SourceIP,$TargetIP,$Machine.TargetOS,$HyperVIP,$VHDPath,$HVcreds,$HyperVHost,$ScoutSettings,$ModulePath

                                            }                           
                                }                                
                                

                                Write-host "`nRunning $jobCounter Jobs for creating disk pairings.`n" -ForegroundColor Cyan 

                                #sleep for 300 seconds and then start checking
                                Write-host "`nSleeping for 5 min to allow for all Disks to complete pairing operation and initial Sync`n" -ForegroundColor Cyan 
                                Write-Log "Sleeping for 5 min to allow for jobs to finish running." -Path $logPath -Level Info

                                Start-Sleep -Seconds 300


                                #parse through all machines and get their respective jobs, till job counter is zero or timeout counter of 10 min is done.
                                $Timeout = New-TimeSpan -Minutes 10
                                $Counter = [diagnostics.stopwatch]::StartNew()
                                
                                #loop through all the jobs till they are completed or timedout
                                do
                                {
                                    foreach ($machine in $MachineFile)
                                    {
                                        if( ( $machine.ProtectionStatus -ne "Failed") -and ($Machine.AgentStatus -eq "Healthy") )
                                        {
                                                                                  
                                            $Job = Get-Job -Name $Machine.SourceIP -ErrorAction SilentlyContinue
                                         
                                            if (($job.State -eq "Failed") -or ($Job -eq $null))
                                            {
                                                $Machine.ProtectionStatus = "Failed"
                                                $machine.Message = "Protection Job Failed"
                                                $job | remove-Job -Force -ErrorAction SilentlyContinue
                                            }
                                            if ($job.State -eq "Completed")
                                            {
                                                $Response = $job | receive-job 
                                                if($response.errorCode -eq 0)
                                                {
                                                    $machine.ProtectionStatus = "Protected"
                                                    $Machine.Message = "Protected."
                                                }
                                                else
                                                {
                                                    $machine.ProtectionStatus = "Failed"
                                                    $machine.Message = $response.Message
                                                }
                                                $job | remove-Job -Force
                                            }
                                            if ($job.State -eq "Running")
                                            {
                                                $Machine.ProtectionStatus = "Pending"
                                                $Machine.Message = "Job running.Please Check UI for details"                                            
                                            }
                                        }
                                    }
                                }While( ($Counter.elapsed -le $Timeout) -and ( (get-job).Count -ne 0 ) )
                                

                                #check if counter and Jobcount match our criteria.
                                if ( ($Counter.elapsed -ge $Timeout) -and ( (get-job).Count -ne 0 ) )
                                {
                                    Write-Host "Protection jobs are still running. Please check Scout UI for details."
                                    Write-log "Protection Jobs are still running. check CSV file for pending machines." -Path $logPath -Level Warn
                                }
#endregion
         
                                #write output to specified location.
                                #Write-Host -ForegroundColor Green "Writing Report to location $OutputMachineFile."
                                Write-log -Message "Writing Report to location $OutputMachineFile." -Path $logPath -Level Info
                                $output | export-csv -NoTypeInformation -LiteralPath $OutputMachineFile
                                Get-PSSession | Remove-PSSession
     














