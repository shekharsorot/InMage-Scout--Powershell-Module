################Demo script to demonstrate the failover /rollback from VMWare to Hyper-V platform for Linux VM Only
################script input is Settings.XML and MachineFile.CSV from "ProtectVM" script




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
        [String]$MachineFile="C:\Users\Administrator.ASR-CS\Desktop\MachineProtection.CSV",


        # this file will be used for Performing Failover. Please preserve this output file.
        [parameter(Mandatory=$false)]
        [String]$OutputMachineFile="C:\Users\Administrator.ASR-CS\Desktop\Machines_op.CSV",

        #This is a input parameter for ASR Scout Web service credential.
        [parameter(Mandatory=$True)]
        [System.Management.Automation.PSCredential]$CXCredential

       )




####################################################################################################################################



#endregion





    #read the Settings File
        $MigrationSetting = [xml](Get-Content $ConfigFile)
    #read the Migration  File
        $MachineFile = import-CSV -Path $MachineFile

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

#create a custom object to store Disk mapping before we trigger rollback

    #create a custom object to store Disk mapping before we trigger rollback
    $Object = New-Object PSObject
    $Object | Add-Member -MemberType NoteProperty -Name "DiskPairing" -Value $null
    $Object | Add-Member -MemberType NoteProperty -Name "SourceIP" -Value $null
    $Object | Add-Member -MemberType NoteProperty -Name "TargetIP" -Value $null
    $Object | Add-Member -MemberType NoteProperty -Name "HyperVIP" -Value $null

    




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
                                Import-module $ModulePath



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

                               
                                #Main block begins here
                                #TODO : Auto assign Mastertarget to each source VM/Machine, if the same is not provided
                                #TODO : Auto assign process server if the same is not defined.
                                #TODO : allow targeting to Hyper-V Cluster/SCVMM
                                #TODO : allow checking of input VM as having correct OS , properly filled target information
                                Write-host "`t`t*Validating Source Machine Parameters." -foregroundcolor Green
                                Write-log -Message "Validating Source Machine Parameters" -Path $logPath -Level Info

#########################################first check if all machines are properly valid########################33
#################We will skip any machine that is not protected or with an unhealthy agent.
                                        

                                        #Update : Code not required. We expect the Agent health check to be finished from "ProtectVM" script stage.
                                        <#
                                        foreach ($machine in $MachineFile)
                                        {
                                            #check if Agent is registered or not.
                                            if ( [string]::IsNullOrWhiteSpace($machine.SourceAgentGUID) -or ($machine.SourceAgentGUID -ne "Unknown") )
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
                                                }
                                                else
                                                {
                                                        $machine.SourceAgentGUID = $AgentDetails.HostAgentGUID
                                                        #update the Ip address anyway
                                                        $machine.SourceIP = $AgentDetails.HostIP
                                                        $machine.AgentStatus = "Healthy"
                                                }
                                            }
                                        }
                                        #>



###############################################Start failover Process##################################################33
###Currently only targetting Linux
##############Part 1 : Create target VM's from CS information on target Hyper-V
#region
                foreach ($machine in $machineFile)
                {
                    #add a column in CSV for tracking target VM
                    #$Machine | add-member -MemberType NoteProperty -Name "VMname" -Value $null
                    #$Machine | add-member -MemberType NoteProperty -Name "Message" -Value $null

                    if (($machine.OSType -eq "Linux") -and ($machine.ProtectionStatus -eq "Protected"))
                    {


                        #Process the hyper-V connection
                        $HyperVHost = $MigrationSetting.Settings.HyperV.Host | Where-Object {$_.IPAddress -eq $machine.HyperVIP}
                        if ($HyperVHost -eq $null)
                        {
                            $machine.FailoverStatus = "Failed"
                            $machine.Message = "Failed due to Missing Hyper-V information in Settings XML"
                            break;
                        }
                        else
                        {                               #create Hyper-V credential Object
                                                        $HVUser = $HyperVHost.Username
                                                        $HVPass = $HyperVHost.Password
                                                        $secpasswd = ConvertTo-SecureString $HVPass -AsPlainText -Force
                                                        $HVcreds = New-Object System.Management.Automation.PSCredential ($HVUser, $secpasswd)
                        }


                        try
                        {
                                    $PSSession = New-PSSession -ComputerName $machine.HyperVIP -Credential $HVcreds 
                                    Write-Verbose "PSsession ID : $($PSSession.Id), Name : $($PSsession.Name)"
                        }
                        catch
                        {
                            $machine.FailoverStatus = "Failed"
                            $machine.Message = "Failed  to Connect to hyper-V server as per Setting XML."
                            break;  
                        }



                        #get Machine properties
                        $MachineDetails = [xml]((Get-InMageHostDetails -MachineIP $Machine.SourceIP -ScoutSettings $ScoutSettings).HostDetailsXML)
                        $VMCPU = ($MachineDetails.FunctionResponse.Parameter | Where-Object {$_.Name -eq "CPUCount"}).Value
                        $VMMemory = ($MachineDetails.FunctionResponse.Parameter | Where-Object {$_.Name -eq "MemSize"}).Value
                        $VMName = ($MachineDetails.FunctionResponse.Parameter | Where-Object {$_.Name -eq "HostName"}).Value + "_" + ($MachineDetails.FunctionResponse.Parameter | Where-Object {$_.Name -eq "HostGUID"}).Value

                        #Create the Basic VM on Hyper-V Host
                        $VM = Invoke-Command -Session $PSSession -ScriptBlock {
                                                                                   $VMName = $args[0];
                                                                                   $VMCPU = $args[1];
                                                                                   $VMMemory = $Args[2];         
                                                                                   $VM = New-VM -Name $VMName -MemoryStartupBytes $VMMemory -NoVHD -Generation 1;
                                                                                   $VM | Set-VMProcessor -Count $VMCPU;
                                                                                   return $VM
                                                                                    } -ArgumentList $VMName,$VMCPU,$VMMemory

                        
                        #create NIC's on VM 
                        $VMNics = (($MachineDetails.FunctionResponse.ParameterGroup)[1]).ParameterGroup
                        foreach ($VMNic in $VMNics)
                        {
                            $MAC = ($VMNic.Parameter | Where-Object {$_.Name -eq "MacAddress"}).Value
                            $MAC = $MAC.replace(":","")
                                
                            $IPAddress = (($VMnic.ParameterGroup).Parameter | Where-Object {$_.Name -eq "Ip"}).Value
                            $Subnet = (($VMnic.ParameterGroup).Parameter | Where-Object {$_.Name -eq "SubnetMask"}).Value

                            $network = (IPCalculator -IPAddress $IPAddress -Netmask $Subnet).Network



                            #get the corresponding switch from HyperV object with matching network

                            $HyperVhost = $MigrationSetting.Settings.HyperV.Host | Where-Object { $_.IPAddress -eq $machine.HyperVIP}

                            if ($HyperVhost -eq $null)
                            {
                                $machine.FailoverStatus = "Failed"
                                $VM | Remove-VM -Force
                                Remove-PSSession $PSSession
                                break;
                            }
                            #get Vswitch details
                            $Vswitch = $HyperVHost.vSwitch |  Where-Object {$_.AddressSpace.'#text' -eq $network}
                            
                            if ($Vswitch -eq $null)
                            {
                                $machine.FailoverStatus = "Failed"
                                $VM | Remove-VM -Force
                                Remove-PSSession $PSSession
                                break;
                            }

                            $VLAN = $Vswitch.AddressSpace.VLAN
                            #create NIC and attach to VM, return the GUID value as NIC name.
                            $Response=  Invoke-Command -Session $PSSession -ScriptBlock {      $VMName = $args[0];
                                                                                   $VSwitch = $args[1];
                                                                                   $VLAN = $Args[2];         
                                                                                   $MAC = $Args[3];

                                                                                   $VM = Get-VM -Name $VMname
                                                                                   $VM | Get-VMNetworkAdapter | Remove-VMNetworkAdapter

                                                                                   #create VNIC anad attache to VM
                                                                                   $NICName = [guid]::NewGuid()
                                                                                   $VM  | Add-VMNetworkAdapter -SwitchName $VSwitch -Name $NICName;
                                                                                   $VM | Get-VMNetworkAdapter -Name $NICName | Set-VMNetworkAdapter -StaticMacAddress $MAC

                                                                                   if ( [string]::IsNullOrEmpty($VLAN) -eq $false)
                                                                                   {
                                                                                        $VM | Get-VMNetworkAdapter -Name $NICName | Set-VMNetworkAdapter -VirtualSubnetId $VLAN
                                                                                   }

                                                                                   return $NICName
                                                                                    } -ArgumentList $VMName,$Vswitch.Name,$Vswitch.AddressSpace.VLAN,$MAC
                            $NicName = $response.GUID     
                                                                

                            #remove PS session object to free up connections.
                            Remove-PSSession -Session $PSSession

                        }
                        $machine.VMname = $VMname
                        $Machine.FailoverStatus = ""
                        $Machine.Message = "VM Created."
                        

                    }
                    else
                    {
                        $machine.FailoverStatus = "skipped"
                    }

                }

                #delete all orphaned PSSessions
                Get-PSSession | Remove-PSSession
#endregion



###################################Trigger Rollback operation on each Source - target Pair#############################3
#region
                    $ObjectArray = @()

                    foreach ($machine in $MachineFile)
                    {
                        if  (($Machine.FailoverStatus -ne "Failed") -and ($machine.ProtectionStatus -eq "Protected") ) # let us exclude machines that we have already filtered out as failed.
                        {
                                    #get the existing disk mapping for migrating VHD to new VM   , as the pairing will be deleted after Rollback
                                    $Object.SourceIP = $machine.SourceIP
                                    $Object.TargetIP = $machine.TargetIP
                                    $Object.HyperVIP = $machine.HyperVIP
                                    

                                        #create Hyper-V credential object
                                        #Process the hyper-V connection
                                        $HyperVHost = $MigrationSetting.Settings.HyperV.Host | Where-Object {$_.IPAddress -eq $machine.HyperVIP}
                                        if ($HyperVHost -eq $null)
                                        {
                                            $machine.FailoverStatus = "Failed"
                                            $machine.Message = "Failed due to Missing Hyper-V information in Settings XML"
                                            break;
                                        }
                                        else
                                        {                               #create Hyper-V credential Object
                                                                        $HVUser = $HyperVHost.Username
                                                                        $HVPass = $HyperVHost.Password
                                                                        $secpasswd = ConvertTo-SecureString $HVPass -AsPlainText -Force
                                                                        $HVcreds = New-Object System.Management.Automation.PSCredential ($HVUser, $secpasswd)
                                        }


                                        try
                                        {
                                                    $PSSession = New-PSSession -ComputerName $machine.HyperVIP -Credential $HVcreds 
                                                    Write-Verbose "PSsession ID : $($PSSession.Id), Name : $($PSsession.Name)"
                                        }
                                        catch
                                        {
                                            $machine.FailoverStatus = "Failed"
                                            $machine.Message = "Failed due to Connect to hyper-V server as per Setting XML."
                                            break;  
                                        }

                                        $Temp = (Get-InMageConfiguredPair -ScoutSettings $ScoutSettings -SourceIP $machine.SourceIP -TargetIP $machine.TargetIP -TargetHyperVIP $machine.HyperVIP -HyperVCredentials $HVcreds)
                                        # if there are no pairs , or pairs with no disk information, this machine is marked as failed.
                                        if ($temp -ne 0)
                                        {
                                            $Machine.FailoverStatus = "Failed"
                                            $machine.Message = "Failed due to no disk pairs or incorrect pairing on CS Server."
                                            break;  
                                        }
                                        else
                                        {
                                            $Object.DiskPairing = $Temp.DiskPairing
                                        }


                            #Create JobName for easy identification
                            $JobName = $machine.SourceIP

                            #start job
                            Start-Job -ScriptBlock { 
                                                    $ScoutSettingsObject = $args[0];
                                                    $Object = $args[1];
                                                    $ModulePath = $args[2];
                                                    import-module $ModulePath -WarningAction SilentlyContinue | out-null
                                                    Rollback-InMageProtectionPair -ScoutSettings $ScoutSettingsObject -SourceIP $Object.SourceIP -TargetIP $Object.TargetIP -TimeoutSeconds 120;
                                                    } -ArgumentList $ScoutSettings,$Object,$ModulePath -Name $JobName
                        
                            $ObjectArray += $Object
                            Remove-pssession $PSsession

                         }
                    }
                    #delete all orphaned PSSession
                    Get-PSSession | Remove-PSSession
#endregion


#####################################Detach disks from MT and mount to VM.
#region
                            #sleep for 5 min to allow for Rollback job to complete
                            Start-sleep -Seconds 300

                            foreach ($Job in $ObjectArray)
                            {
                                
                                #test each job if disks have been de-paired.
                                $SourceIP = $Job.SourceIP
                                $JobObject = get-Job -name $sourceIP -ErrorAction SilentlyContinue


                                #if no jobs....Machine is a fail.
                                if ($JobObject -ne $null)
                                {
                                    ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).FailoverStatus = "Failed"
                                    continue
                                }
                                #check Job output to see if rollover has completed or not.

                                $Response = $JobObject | Receive-Job -Keep
                                if ($Response.ErrorCode -ne 0)
                                {
                                    ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).FailoverStatus = "Failed"
                                    ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).Message = "Rollback failed. Please check pairing again and restart from protection stage."
                                    continue
                                }

                                
                                #else... get the vM name 
                                $VMname = ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).VMname
                                $HyperVIP = ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).HyperVIP

                                #get existing disk pairing information
                                $diskPairing = $Job.Diskpairing

                                        #create hyper-V credentials for connecting to Hyper-V server
                                        $HyperVHost = $MigrationSetting.Settings.HyperV.Host | Where-Object {$_.IPAddress -eq $HyperVIP}
                                        #create Hyper-V credential Object
                                        $HVUser = $HyperVHost.Username
                                        $HVPass = $HyperVHost.Password
                                        $secpasswd = ConvertTo-SecureString $HVPass -AsPlainText -Force
                                        $HVcreds = New-Object System.Management.Automation.PSCredential ($HVUser, $secpasswd)
                                        
                                        $PSSession = New-PSSession -ComputerName $HyperVIP -Credential $HVcreds
                                        $VHDS = $job.Diskpairing.TargetVHDPath

                                        #get the Master Target VM Name
                                        $MasterTarget = invoke-command -Session $PSSession -ScriptBlock { 
                                                            $TargetIP = $args[0];
                                                        (get-VM | Get-VMNetworkAdapter  |Where-Object {$_.Ipaddresses -eq $TargetIP}).VMname
                                                        } -ArgumentList $TargetIP

                                        #Unmount the VHD from MT 
                                        $Response = Invoke-Command -Session $PSSession -ScriptBlock {
                                                    $VMName =  $args[0];
                                                    $MasterTarget = $args[1]
                                                    $VHDs = $args[2];
                                                                        
                                                    #unmount VHD's
                                                    
                                                    foreach ($Vhd in $VHDS)
                                                    {
                                                        $SCSIControllerNumber = (Get-VM $MasterTarget | Get-VMScsiController  | Where-Object {$_.Drives.Path -eq $Vhd}).ControllerNumber
                                                        Get-VMHardDiskDrive -VMName $MasterTarget –ControllerType SCSI -ControllerNumber $SCSIControllerNumber | Remove-VMHardDiskDrive 
                                                        if($VHD -like "*Disk1*")
                                                        {
                                                            #This is a Gen 1 VM Code. First disk i.e *Disk1.VHDX always goes on                                          
                                                            Get-VM $VMName | Add-VMHardDiskDrive -ControllerType IDE -Path $VHD
                                                        }
                                                        else
                                                        {
                                                            Get-VM $VMName | Add-VMHardDiskDrive -ControllerType SCSI -Path $VHD
                                                        }

                                                    }
                                                    } -ArgumentList $VMName,$MasterTarget,$VHDS
                                        
                                        #mark the VHD transplant as success and continue
                                        ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).FailoverStatus = "Success"
                                        ($MachineFile | Where-Object {$_.SourceIP -eq $SourceIP}).Message = "VHD's migrated."
                                        $JobObject | Remove-Job
                                        Remove-PSSession $PSSession
                            }    



#endregion

######################################Shutdown the source and power on the target#######################333
#region
                        #create Linux credential object for connecting to linux source and perform shutdown.
                        $LinuxUser = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Linux"}).Username
                        $LinuxPass = ($MigrationSetting.Settings.SourceCredential.OS | Where-Object {$_.Type -eq "Linux"}).Password
                                $secpasswd = ConvertTo-SecureString $LinuxPass -AsPlainText -Force
                                $Lincreds = New-Object System.Management.Automation.PSCredential ($LinuxUser, $secpasswd)
                        Import-Module Posh-SSH -WarningAction SilentlyContinue                
                        Foreach ($job in $ObjectArray)
                        {
                            #connect to Linux machine 
                            try
                            {
                                $SSHSession = New-SSHSession -ComputerName $Job.SourceIP -Credential $Lincreds -Port 22 -AcceptKey -ConnectionTimeout 60 -
                            }
                            catch
                            {
                                ($MachineFile | Where-Object {$_.SourceIP -eq $job.SourceIP}).Message = "Unable to shutdown source.Please perform failover manually"
                                Continue
                            }


                            
                            
                                        #power on the Target VM
                                        $VMname = ($MachineFile | Where-Object {$_.SourceIP -eq $job.SourceIP}).VMname
                                        $HyperVIP = ($MachineFile | Where-Object {$_.SourceIP -eq $Job.SourceIP}).HyperVIP

                                          #create hyper-V credentials for connecting to Hyper-V server
                                        $HyperVHost = $MigrationSetting.Settings.HyperV.Host | Where-Object {$_.IPAddress -eq $HyperVIP}
                                        #create Hyper-V credential Object
                                        $HVUser = $HyperVHost.Username
                                        $HVPass = $HyperVHost.Password
                                        $secpasswd = ConvertTo-SecureString $HVPass -AsPlainText -Force
                                        $HVcreds = New-Object System.Management.Automation.PSCredential ($HVUser, $secpasswd)
                                        
                                        $PSSession = New-PSSession -ComputerName $HyperVIP -Credential $HVcreds


                                        #shutdown the source machine
                                        $Response = Invoke-SSHCommand -SSHSession $SSHSession -Command "halt"

                                        start-sleep -Seconds 120

                                        #power on the target VM
                                        Invoke-Command -Session $PSSession -ScriptBlock { 
                                                        Start-VM -Name $args;
                                                        } -ArgumentList $VMname
                                        Remove-PSSession $PSSession

                        }
#endregion



#write-CSV to output file

    $MachineFile | export-CSV -Path $OutputMachineFile
    Write-Host "Writing CSV to path  :$OutputMachineFile. Please check CSV file for Failover Operation results." -ForegroundColor Green
