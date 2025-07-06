<#
.SYNOPSIS
    Enhanced Network Scanner with Vulnerability Assessment
    
.DESCRIPTION
    A comprehensive network scanning tool with service detection, vulnerability assessment,
    memory monitoring, and intelligent resource management capabilities.
    
.PARAMETER NetworkRange
    The network range to scan (e.g., "192.168.1.0/24")
    
.PARAMETER Ports
    Array of ports to scan (default: common ports)
    
.PARAMETER OutputPath
    Path for output files (default: current directory)
    
.PARAMETER MaxThreads
    Maximum number of concurrent threads (auto-calculated if not specified)
    
.PARAMETER Timeout
    Timeout in milliseconds for network operations (default: 2000)
    
.PARAMETER EnableEmail
    Enable email notifications
    
.PARAMETER EmailTo
    Email address for notifications
    
.PARAMETER SMTPServer
    SMTP server for email notifications
    
.PARAMETER SMTPUsername
    SMTP username for authentication
    
.PARAMETER EnableVulnScan
    Enable vulnerability assessment
    
.PARAMETER MemoryLimitMB
    Memory limit in MB before triggering garbage collection (default: 200)
    
.PARAMETER VerboseOutput
    Enable verbose output
    
.EXAMPLE
    .\Enhanced_Network_Scanner.ps1 -NetworkRange "192.168.1.0/24" -EnableVulnScan -VerboseOutput
    
.EXAMPLE
    .\Enhanced_Network_Scanner.ps1 -NetworkRange "10.0.0.0/16" -Ports @(80,443,22,21) -OutputPath "C:\Scans"
    
.NOTES
    Author: Enhanced Network Scanner
    Version: 2.0
    Created: July 2025
    
    Requirements:
    - PowerShell 5.1 or higher
    - Network connectivity to target ranges
    - Appropriate permissions for network scanning
#>

#region SCRIPT MAP - Navigation Guide
<#
================================================================================
                              SCRIPT MAP
================================================================================

1. GLOBAL CONFIGURATION & PARAMETERS
   - Script parameters and global variables
   - Configuration constants and enums

2. CORE INFRASTRUCTURE
   - Logging system
   - Error handling framework
   - Performance monitoring

3. NETWORK SCANNING ENGINE
   - Host discovery functions
   - Port scanning capabilities
   - Service detection and banner grabbing

4. VULNERABILITY ASSESSMENT
   - Security checks and assessments
   - Compliance validation

5. THREAD MANAGEMENT
   - Intelligent thread optimization
   - Resource management

6. REPORTING & OUTPUT
   - Result formatting and export
   - Email notifications

7. MAIN EXECUTION FLOW
   - Parameter validation
   - Scanning orchestration
   - Cleanup and finalization

================================================================================
#>
#endregion

#region 1. GLOBAL CONFIGURATION & PARAMETERS

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Network range to scan (e.g., '192.168.1.0/24')")]
    [ValidateScript({ 
        if ([string]::IsNullOrEmpty($_)) { return $true }
        return $_ -match '^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$'
    })]
    [string]$NetworkRange,
    
    [Parameter(HelpMessage = "Array of ports to scan")]
    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080),
    
    [Parameter(HelpMessage = "Output directory path")]
    [ValidateScript({ Test-Path -Path $_ -IsValid })]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(HelpMessage = "Maximum number of concurrent threads")]
    [ValidateRange(1, 5000)]
    [int]$MaxThreads,
    
    [Parameter(HelpMessage = "Timeout in milliseconds for network operations")]
    [ValidateRange(500, 30000)]
    [int]$Timeout = 2000,
    
    [Parameter(HelpMessage = "Host discovery method")]
    [ValidateSet("ICMP", "TCP", "Both", "Aggressive")]
    [string]$Discovery = "Both",
    
    [Parameter(HelpMessage = "Enable email notifications")]
    [switch]$EnableEmail,
    
    [Parameter(HelpMessage = "Email address for notifications")]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$EmailTo,
    
    [Parameter(HelpMessage = "SMTP server for email notifications")]
    [string]$SMTPServer = "smtp.gmail.com",
    
    [Parameter(HelpMessage = "SMTP username for authentication")]
    [string]$SMTPUsername,
    
    [Parameter(HelpMessage = "Enable vulnerability assessment")]
    [switch]$EnableVulnScan,
    
    [Parameter(HelpMessage = "Memory limit in MB before triggering garbage collection")]
    [ValidateRange(50, 2048)]
    [int]$MemoryLimitMB = 200,
    
    [Parameter(HelpMessage = "Enable verbose output")]
    [switch]$VerboseOutput,
    
    [Parameter(HelpMessage = "Enable interactive mode for prompts")]
    [switch]$Interactive
)

# Load required assemblies for HTML encoding
[System.Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

# Script-level variables for interactive mode
$script:NetworkRange = if ([string]::IsNullOrWhiteSpace($NetworkRange)) { $null } else { $NetworkRange }
$script:EnablePortScanning = $true
$script:EnableServiceDetection = $true
$script:EnableVulnScan = $EnableVulnScan

# Global script variables
$Global:ScriptConfig = @{
    StartTime               = Get-Date
    LogFile                = Join-Path $OutputPath "NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    ReportFile             = Join-Path $OutputPath "NetworkScan_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    TotalHosts             = 0
    ScannedHosts           = 0
    LiveHosts              = 0
    TotalOpenPorts         = 0
    VulnerabilitiesFound   = 0
    ProcessId              = $PID
    EnablePerformanceCounters = $true
    MemoryMonitor          = $null
    MemoryTimer            = $null
    PerformanceProfiler    = $null
}

# Common service ports mapping
$Global:ServicePorts = @{
    21    = "FTP"
    22    = "SSH"
    23    = "Telnet"
    25    = "SMTP"
    53    = "DNS"
    80    = "HTTP"
    110   = "POP3"
    135   = "RPC"
    139   = "NetBIOS"
    143   = "IMAP"
    443   = "HTTPS"
    445   = "SMB"
    993   = "IMAPS"
    995   = "POP3S"
    1433  = "SQL Server"
    1521  = "Oracle"
    3306  = "MySQL"
    3389  = "RDP"
    5432  = "PostgreSQL"
    5900  = "VNC"
    6379  = "Redis"
    8080  = "HTTP-Alt"
    8443  = "HTTPS-Alt"
    27017 = "MongoDB"
    161   = "SNMP"
    389   = "LDAP"
    636   = "LDAPS"
}

# Host discovery methods
enum DiscoveryMethod {
    ICMP
    TCP
    Both
    Aggressive
}

# Host status enumeration
enum HostStatus {
    Unknown
    Alive
    NotResponding
    Filtered
    Unreachable
    TimedOut
}

# Vulnerability severity levels
enum VulnerabilitySeverity {
    Low
    Medium
    High
    Critical
}

# Log levels
enum LogLevel {
    INFO
    WARNING
    ERROR
    DEBUG
}

#endregion


#region 2. CORE INFRASTRUCTURE
<#
================================================================================
                          REGION 2: CORE INFRASTRUCTURE MAP
================================================================================

This region provides the foundational building blocks for the script, including:

1. Logging System
   - Write-Log
   - Initialize-LoggingSystem

2. Performance Monitoring
   - Start-PerformanceMonitoring
   - Stop-PerformanceMonitoring

3. Error Handling
   - Invoke-ErrorHandler

4. System Diagnostics
   - Test-SystemInformation

Each function is designed to be reusable and robust, supporting the main scanning engine and all other script regions.

Quick Reference:
    Write-Log                # Centralized logging with color and file output
    Initialize-LoggingSystem # Prepares log files and headers
    Start-PerformanceMonitoring / Stop-PerformanceMonitoring # Memory and resource monitoring
    Invoke-ErrorHandler      # Consistent error handling and logging
    Test-SystemInformation   # Diagnostic and system info gathering

================================================================================
#>

function Write-Log {
    <#
    .SYNOPSIS
        Centralized logging function with multiple output options
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [LogLevel]$Level = [LogLevel]::INFO,
        
        [Parameter()]
        [switch]$NoConsole,
        
        [Parameter()]
        [switch]$NoFile
    )
    
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        
        # Console output with color coding
        if (-not $NoConsole) {
            switch ($Level) {
                ([LogLevel]::ERROR) { Write-Host $logEntry -ForegroundColor Red }
                ([LogLevel]::WARNING) { Write-Host $logEntry -ForegroundColor Yellow }
                ([LogLevel]::DEBUG) { 
                    if ($VerboseOutput) { Write-Host $logEntry -ForegroundColor Cyan }
                }
                default { Write-Host $logEntry -ForegroundColor White }
            }
        }
        
        # File output
        if (-not $NoFile -and $Global:ScriptConfig.LogFile) {
            Add-Content -Path $Global:ScriptConfig.LogFile -Value $logEntry -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Warning "Logging failed: $($_.Exception.Message)"
    }
}

function Initialize-LoggingSystem {
    <#
    .SYNOPSIS
        Initialize the logging system and create log files
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Ensure output directory exists
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        # Initialize log file
        $logHeader = @"
================================================================================
Network Scanner Log File
Started: $(Get-Date)
User: $env:USERNAME
Computer: $env:COMPUTERNAME
PowerShell Version: $($PSVersionTable.PSVersion)
================================================================================

"@
        Set-Content -Path $Global:ScriptConfig.LogFile -Value $logHeader
        Write-Log "Logging system initialized. Log file: $($Global:ScriptConfig.LogFile)"
    }
    catch {
        Write-Warning "Failed to initialize logging system: $($_.Exception.Message)"
    }
}

function Start-PerformanceMonitoring {
    <#
    .SYNOPSIS
        Start memory and performance monitoring
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$MemoryLimitMB = 4096  # Default to 4GB, can be overridden by user
    )
    
    try {
        if (-not $Global:ScriptConfig.EnablePerformanceCounters) { 
            Write-Log "Performance monitoring disabled" -Level ([LogLevel]::DEBUG)
            return 
        }
        
        # Create and configure the timer
        $timer = New-Object System.Timers.Timer
        $timer.Interval = 5000  # 5 seconds
        $timer.AutoReset = $true
        
        # Register the event handler
        $Global:ScriptConfig.MemoryMonitor = Register-ObjectEvent -InputObject $timer -EventName Elapsed -Action {
            try {
                $process = Get-Process -Id $using:Global:ScriptConfig.ProcessId -ErrorAction SilentlyContinue
                if ($process) {
                    $memoryUsageMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
                    $memoryLimit = $Event.MessageData
                    
                    if ($memoryUsageMB -gt $memoryLimit) {
                        Write-Warning "Memory usage (${memoryUsageMB}MB) exceeds limit (${memoryLimit}MB)"
                        
                        # Trigger garbage collection
                        [System.GC]::Collect()
                        [System.GC]::WaitForPendingFinalizers()
                        [System.GC]::Collect()
                        
                        Write-Log "Forced garbage collection due to high memory usage: ${memoryUsageMB}MB" -Level ([LogLevel]::WARNING)
                    }
                }
            }
            catch {
                Write-Log "Memory monitoring error: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
            }
        } -MessageData $MemoryLimitMB
        
        # Store the timer reference
        $Global:ScriptConfig.MemoryTimer = $timer
        
        # Start the timer
        $timer.Enabled = $true
        $timer.Start()
        
        Write-Log "Performance monitoring started with memory limit: $MemoryLimitMB MB" -Level ([LogLevel]::INFO)
    }
    catch {
        Write-Log "Failed to start performance monitoring: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
    }
}

function Stop-PerformanceMonitoring {
    <#
    .SYNOPSIS
        Stop performance monitoring and clean up resources
    #>
    [CmdletBinding()]
    param()
    
    try {
        if ($Global:ScriptConfig.MemoryMonitor) {
            # Stop and dispose of the timer
            if ($Global:ScriptConfig.MemoryTimer) {
                $Global:ScriptConfig.MemoryTimer.Stop()
                $Global:ScriptConfig.MemoryTimer.Dispose()
                $Global:ScriptConfig.MemoryTimer = $null
            }
            
            # Unregister the event
            Unregister-Event -SourceIdentifier $Global:ScriptConfig.MemoryMonitor.Name -ErrorAction SilentlyContinue
            $Global:ScriptConfig.MemoryMonitor = $null
            
            Write-Log "Performance monitoring stopped" -Level ([LogLevel]::INFO)
        }
    }
    catch {
        Write-Log "Error stopping performance monitoring: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
    }
}

function Invoke-ErrorHandler {
    <#
    .SYNOPSIS
        Centralized error handling function
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        
        [Parameter()]
        [switch]$Fatal
    )
    
    $errorMessage = "Operation '$Operation' failed: $($ErrorRecord.Exception.Message)"
    
    if ($ErrorRecord.Exception.InnerException) {
        $errorMessage += " Inner Exception: $($ErrorRecord.Exception.InnerException.Message)"
    }
    
    Write-Log $errorMessage -Level ([LogLevel]::ERROR)
    
    if ($VerboseOutput) {
        Write-Log "Stack Trace: $($ErrorRecord.ScriptStackTrace)" -Level ([LogLevel]::DEBUG)
    }
    
    if ($Fatal) {
        Write-Log "Fatal error encountered. Stopping execution." -Level ([LogLevel]::ERROR)
        Stop-PerformanceMonitoring
        exit 1
    }
}

function Test-SystemInformation {
    <#
    .SYNOPSIS
        Diagnostic function to test various methods of gathering system information
    #>
    [CmdletBinding()]
    param()
    
    Write-Log "=== System Information Diagnostic ===" -Level ([LogLevel]::INFO)
    
    # Test Method 1: CIM
    try {
        $cpu = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        Write-Log "CIM Method: SUCCESS" -Level ([LogLevel]::INFO)
        Write-Log "  - CPU Cores: $($cpu.NumberOfLogicalProcessors)" -Level ([LogLevel]::INFO)
        Write-Log "  - Free Memory: $([math]::Round($os.FreePhysicalMemory / 1024))MB" -Level ([LogLevel]::INFO)
        Write-Log "  - Total Memory: $([math]::Round($os.TotalPhysicalMemory / 1024 / 1024))MB" -Level ([LogLevel]::INFO)
    }
    catch {
        Write-Log "CIM Method: FAILED - $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
    }
    
    # Test Method 2: WMI
    try {
        $cpu = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        
        Write-Log "WMI Method: SUCCESS" -Level ([LogLevel]::INFO)
        Write-Log "  - CPU Cores: $($cpu.NumberOfLogicalProcessors)" -Level ([LogLevel]::INFO)
        Write-Log "  - Free Memory: $([math]::Round($os.FreePhysicalMemory / 1024))MB" -Level ([LogLevel]::INFO)
        Write-Log "  - Total Memory: $([math]::Round($os.TotalPhysicalMemory / 1024 / 1024))MB" -Level ([LogLevel]::INFO)
    }
    catch {
        Write-Log "WMI Method: FAILED - $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
    }
    
    # Test Method 3: Environment Variables
    try {
        $cores = [int]$env:NUMBER_OF_PROCESSORS
        $memoryBytes = [System.GC]::GetTotalMemory($false)
        
        Write-Log "Environment Method: SUCCESS" -Level ([LogLevel]::INFO)
        Write-Log "  - CPU Cores: $cores" -Level ([LogLevel]::INFO)
        Write-Log "  - Current Process Memory: $([math]::Round($memoryBytes / 1MB))MB" -Level ([LogLevel]::INFO)
        
        # Try to get total system memory
        try {
            $computerInfo = Get-ComputerInfo -Property TotalPhysicalMemory -ErrorAction Stop
            Write-Log "  - Total System Memory: $([math]::Round($computerInfo.TotalPhysicalMemory / 1MB))MB" -Level ([LogLevel]::INFO)
        }
        catch {
            Write-Log "  - Could not determine total system memory" -Level ([LogLevel]::DEBUG)
        }
    }
    catch {
        Write-Log "Environment Method: FAILED - $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
    }
    
    # Test enhanced thread calculation for different scenarios
    Write-Log "=== Thread Calculation Tests ===" -Level ([LogLevel]::INFO)
    
    $testScenarios = @(
        @{ Targets = 100; Description = "Small scan (100 hosts)" },
        @{ Targets = 500; Description = "Medium scan (500 hosts)" },
        @{ Targets = 1022; Description = "Current scan size (1022 hosts)" },
        @{ Targets = 2000; Description = "Large scan (2000 hosts)" },
        @{ Targets = 5000; Description = "Massive scan (5000 hosts)" }
    )
    
    foreach ($scenario in $testScenarios) {
        $threads = Get-OptimalThreadCount -DefaultThreads 500 -TotalTargets $scenario.Targets
        Write-Log "  - $($scenario.Description): $threads threads" -Level ([LogLevel]::INFO)
    }
    
    Write-Log "=== End System Information Diagnostic ===" -Level ([LogLevel]::INFO)
}

#endregion

#region 2.5. INTERACTIVE FUNCTIONS

function Get-LocalNetworkRange {
    <#
    .SYNOPSIS
        Auto-detect the local network range from the active network adapter
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Auto-detecting local network range from active network adapter..." -Level ([LogLevel]::INFO)
        
        # Get active network adapters with IP addresses
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.Virtual -eq $false }
        
        foreach ($adapter in $activeAdapters) {
            try {
                # Get IP configuration for this adapter
                $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
                           Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" }
                
                if ($ipConfig) {
                    foreach ($config in $ipConfig) {
                        $ipAddress = $config.IPAddress
                        $prefixLength = $config.PrefixLength
                        
                        # Calculate network address
                        $ipBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
                        [Array]::Reverse($ipBytes)
                        $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
                        
                        # Create subnet mask
                        $maskInt = [UInt32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $prefixLength))
                        $networkInt = $ipInt -band $maskInt
                        
                        # Convert back to IP
                        $networkBytes = [System.BitConverter]::GetBytes($networkInt)
                        [Array]::Reverse($networkBytes)
                        $networkIP = [System.Net.IPAddress]::new($networkBytes)
                        
                        $networkRange = "$($networkIP.ToString())/$prefixLength"
                        
                        Write-Log "Detected network range: $networkRange (Adapter: $($adapter.Name))" -Level ([LogLevel]::INFO)
                        return $networkRange
                    }
                }
            }
            catch {
                Write-Log "Failed to get IP configuration for adapter $($adapter.Name): $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
                continue
            }
        }
        
        # Fallback: try to detect from default gateway
        try {
            $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Sort-Object RouteMetric | Select-Object -First 1
            if ($defaultRoute) {
                $gatewayIP = $defaultRoute.NextHop
                
                # Assume /24 network for common home/office networks
                $gatewayBytes = [System.Net.IPAddress]::Parse($gatewayIP).GetAddressBytes()
                $gatewayBytes[3] = 0  # Set host portion to 0
                $networkIP = [System.Net.IPAddress]::new($gatewayBytes)
                $networkRange = "$($networkIP.ToString())/24"
                
                Write-Log "Fallback detection using default gateway: $networkRange" -Level ([LogLevel]::INFO)
                return $networkRange
            }
        }
        catch {
            Write-Log "Failed to detect network range from default gateway: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
        }
        
        # Final fallback
        Write-Log "Unable to auto-detect network range, using fallback: 192.168.1.0/24" -Level ([LogLevel]::WARNING)
        return "192.168.1.0/24"
    }
    catch {
        Write-Log "Error in network range auto-detection: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
        return "192.168.1.0/24"
    }
}

function Get-UserInput {
    <#
    .SYNOPSIS
        Get user input with a prompt and default value
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,
        
        [Parameter()]
        [string]$DefaultValue = "",
        
        [Parameter()]
        [switch]$IsYesNo = $false,
        
        [Parameter()]
        [string]$DefaultYesNo = "Y"
    )
    
    try {
        if ($IsYesNo) {
            $fullPrompt = "$Prompt [Y/N] (default: $DefaultYesNo): "
            Write-Host $fullPrompt -ForegroundColor Yellow -NoNewline
            $userInput = Read-Host
            
            if ([string]::IsNullOrWhiteSpace($userInput)) {
                $userInput = $DefaultYesNo
            }
            
            return $userInput.ToUpper().StartsWith("Y")
        }
        else {
            if ($DefaultValue) {
                $fullPrompt = "$Prompt (default: $DefaultValue): "
            }
            else {
                $fullPrompt = "${Prompt}: "
            }
            
            Write-Host $fullPrompt -ForegroundColor Yellow -NoNewline
            $userInput = Read-Host
            
            if ([string]::IsNullOrWhiteSpace($userInput) -and $DefaultValue) {
                return $DefaultValue
            }
            
            return $userInput
        }
    }
    catch {
        Write-Log "Error getting user input: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
        if ($IsYesNo) {
            return $DefaultYesNo.ToUpper().StartsWith("Y")
        }
        else {
            return $DefaultValue
        }
    }
}

function Initialize-InteractiveSession {
    <#
    .SYNOPSIS
        Handle interactive prompts and parameter setup
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`n" -NoNewline
        Write-Host "================================================================================================" -ForegroundColor Cyan
        Write-Host "                          Enhanced Network Scanner v2.0 - Interactive Setup" -ForegroundColor White
        Write-Host "================================================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # 1. Network Range Input
        if ([string]::IsNullOrWhiteSpace($script:NetworkRange)) {
            $autoDetectedRange = Get-LocalNetworkRange
            $networkInput = Get-UserInput -Prompt "Enter network range to scan (CIDR notation)" -DefaultValue $autoDetectedRange
            
            # Validate network range format
            if ($networkInput -match '^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$') {
                $script:NetworkRange = $networkInput
                Write-Host "✓ Network range set to: $script:NetworkRange" -ForegroundColor Green
            }
            else {
                Write-Host "✗ Invalid network range format. Using auto-detected: $autoDetectedRange" -ForegroundColor Red
                $script:NetworkRange = $autoDetectedRange
            }
        }
        else {
            Write-Host "✓ Network range provided: $script:NetworkRange" -ForegroundColor Green
        }
        
        # Generate and display host list preview
        Write-Host "`nGenerating host list..." -ForegroundColor Cyan
        $hostList = Get-NetworkHosts -NetworkRange $script:NetworkRange
        Write-Host "✓ Generated ordered host list: $($hostList.Count) hosts" -ForegroundColor Green
        
        # Show first few and last few hosts for confirmation
        if ($hostList.Count -le 10) {
            Write-Host "  Hosts to scan: $($hostList -join ', ')" -ForegroundColor Gray
        }
        else {
            $preview = $hostList[0..4] + @("...") + $hostList[-5..-1]
            Write-Host "  Hosts to scan: $($preview -join ', ')" -ForegroundColor Gray
        }
        
        # 2. Port Scanning Option
        Write-Host ""
        $enablePortScan = Get-UserInput -Prompt "Perform port scanning on responding hosts?" -IsYesNo -DefaultYesNo "Y"
        if ($enablePortScan) {
            Write-Host "✓ Port scanning enabled for responding hosts" -ForegroundColor Green
            $script:EnablePortScanning = $true
        }
        else {
            Write-Host "✗ Port scanning disabled" -ForegroundColor Yellow
            $script:EnablePortScanning = $false
        }
        
        # 3. Service Detection and Banner Grabbing Option
        if ($script:EnablePortScanning) {
            $enableServiceDetection = Get-UserInput -Prompt "Perform service detection and banner grabbing?" -IsYesNo -DefaultYesNo "Y"
            if ($enableServiceDetection) {
                Write-Host "✓ Service detection and banner grabbing enabled" -ForegroundColor Green
                $script:EnableServiceDetection = $true
            }
            else {
                Write-Host "✗ Service detection and banner grabbing disabled" -ForegroundColor Yellow
                $script:EnableServiceDetection = $false
            }
        }
        else {
            $script:EnableServiceDetection = $false
            Write-Host "✗ Service detection disabled (requires port scanning)" -ForegroundColor Gray
        }
        
        # 4. Vulnerability Assessment Option
        if ($script:EnablePortScanning) {
            $enableVulnAssessment = Get-UserInput -Prompt "Perform vulnerability assessment?" -IsYesNo -DefaultYesNo "Y"
            if ($enableVulnAssessment) {
                Write-Host "✓ Vulnerability assessment enabled" -ForegroundColor Green
                $script:EnableVulnScan = $true
            }
            else {
                Write-Host "✗ Vulnerability assessment disabled" -ForegroundColor Yellow
                $script:EnableVulnScan = $false
            }
        }
        else {
            $script:EnableVulnScan = $false
            Write-Host "✗ Vulnerability assessment disabled (requires port scanning)" -ForegroundColor Gray
        }
        
        # Summary
        Write-Host "`n" -NoNewline
        Write-Host "================================================================================================" -ForegroundColor Cyan
        Write-Host "                                    SCAN CONFIGURATION SUMMARY" -ForegroundColor White
        Write-Host "================================================================================================" -ForegroundColor Cyan
        Write-Host "Network Range:           $script:NetworkRange" -ForegroundColor White
        Write-Host "Total Hosts:             $($hostList.Count)" -ForegroundColor White
        Write-Host "Port Scanning:           $(if ($script:EnablePortScanning) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($script:EnablePortScanning) { 'Green' } else { 'Yellow' })
        Write-Host "Service Detection:       $(if ($script:EnableServiceDetection) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($script:EnableServiceDetection) { 'Green' } else { 'Yellow' })
        Write-Host "Vulnerability Assessment: $(if ($script:EnableVulnScan) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($script:EnableVulnScan) { 'Green' } else { 'Yellow' })
        Write-Host "Ports to Scan:           $($Ports -join ', ')" -ForegroundColor White
        Write-Host "Discovery Method:        $Discovery" -ForegroundColor White
        Write-Host "Output Directory:        $OutputPath" -ForegroundColor White
        Write-Host "================================================================================================" -ForegroundColor Cyan
        
        # Final confirmation
        Write-Host ""
        $confirmStart = Get-UserInput -Prompt "Start network scan with above configuration?" -IsYesNo -DefaultYesNo "Y"
        if (-not $confirmStart) {
            Write-Host "✗ Scan cancelled by user" -ForegroundColor Red
            exit 0
        }
        
        Write-Host "✓ Starting network scan..." -ForegroundColor Green
        Write-Host ""
        
        return $hostList
    }
    catch {
        Write-Log "Error in interactive session: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
        throw
    }
}

#endregion

#region 3. NETWORK SCANNING ENGINE

function Get-NetworkHosts {
    <#
    .SYNOPSIS
        Generate list of IP addresses from network range
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$NetworkRange
    )
    
    try {
        Write-Log "Generating host list for network range: $NetworkRange" -Level ([LogLevel]::INFO)
        
        $parts = $NetworkRange.Split('/')
        $network = $parts[0]
        $cidr = [int]$parts[1]
        
        $networkBytes = [System.Net.IPAddress]::Parse($network).GetAddressBytes()
        [Array]::Reverse($networkBytes)
        $networkInt = [System.BitConverter]::ToUInt32($networkBytes, 0)
        
        $hostBits = 32 - $cidr
        $hostCount = [Math]::Pow(2, $hostBits) - 2  # Exclude network and broadcast
        
        $hosts = @()
        for ($i = 1; $i -le $hostCount; $i++) {
            $hostInt = $networkInt + $i
            $hostBytes = [System.BitConverter]::GetBytes($hostInt)
            [Array]::Reverse($hostBytes)
            $hostIP = [System.Net.IPAddress]::new($hostBytes)
            $hosts += $hostIP.ToString()
        }
        
        $Global:ScriptConfig.TotalHosts = $hosts.Count
        Write-Log "Generated $($hosts.Count) host addresses for scanning" -Level ([LogLevel]::INFO)
        
        return $hosts
    }
    catch {
        Invoke-ErrorHandler -Operation "Generate Network Hosts" -ErrorRecord $_ -Fatal
    }
}

function Test-HostConnectivity {
    <#
    .SYNOPSIS
        Enhanced host connectivity testing with multiple discovery methods
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter()]
        [int]$TimeoutMs = 2000,
        
        [Parameter()]
        [int]$MaxRetries = 2,
        
        [Parameter()]
        [DiscoveryMethod]$Method = [DiscoveryMethod]::Both,
        
        [Parameter()]
        [int[]]$CommonPorts = @(80, 443, 22, 21, 25, 53, 135, 139, 445, 993, 995, 1433, 3389)
    )
    
    $result = @{
        IPAddress    = $IPAddress
        IsAlive      = $false
        ResponseTime = 0
        Error        = $null
        Status       = [HostStatus]::Unknown
        Method       = "None"
        Details      = @()
    }
    
    try {
        Write-Log "Testing connectivity for $IPAddress using method: $Method" -Level ([LogLevel]::DEBUG)
        
        switch ($Method) {
            ([DiscoveryMethod]::ICMP) {
                $result = Test-ICMPConnectivity -IPAddress $IPAddress -TimeoutMs $TimeoutMs -MaxRetries $MaxRetries
            }
            
            ([DiscoveryMethod]::TCP) {
                $result = Test-TCPConnectivity -IPAddress $IPAddress -TimeoutMs $TimeoutMs -CommonPorts $CommonPorts
            }
            
            ([DiscoveryMethod]::Both) {
                # Try ICMP first (faster)
                $icmpResult = Test-ICMPConnectivity -IPAddress $IPAddress -TimeoutMs $TimeoutMs -MaxRetries $MaxRetries
                
                if ($icmpResult.IsAlive) {
                    $result = $icmpResult
                    $result.Details += "ICMP ping successful"
                }
                else {
                    # ICMP failed, try TCP probes
                    Write-Log "ICMP failed for $IPAddress, attempting TCP discovery..." -Level ([LogLevel]::DEBUG)
                    $tcpResult = Test-TCPConnectivity -IPAddress $IPAddress -TimeoutMs ($TimeoutMs / 2) -CommonPorts $CommonPorts[0..4]  # Test fewer ports for speed
                    
                    if ($tcpResult.IsAlive) {
                        $result = $tcpResult
                        $result.Details += "ICMP blocked, TCP probe successful"
                    }
                    else {
                        $result = $icmpResult  # Return ICMP result with failure details
                        $result.Details += "Both ICMP and TCP probes failed"
                        $result.Status = [HostStatus]::NotResponding
                    }
                }
            }
            
            ([DiscoveryMethod]::Aggressive) {
                $result = Test-AggressiveDiscovery -IPAddress $IPAddress -TimeoutMs $TimeoutMs -CommonPorts $CommonPorts
            }
        }
        
        # Log discovery result
        Write-Log "Host discovery result for $IPAddress`: Status=$($result.Status), Method=$($result.Method), ResponseTime=$($result.ResponseTime)ms" -Level ([LogLevel]::DEBUG)
        
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Status = [HostStatus]::Unknown
        Write-Log "Host discovery failed for $IPAddress`: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
    }
    
    return $result
}

function Test-ICMPConnectivity {
    <#
    .SYNOPSIS
        Test ICMP connectivity with detailed status reporting
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter()]
        [int]$TimeoutMs = 2000,
        
        [Parameter()]
        [int]$MaxRetries = 2
    )
    
    $result = @{
        IPAddress    = $IPAddress
        IsAlive      = $false
        ResponseTime = 0
        Error        = $null
        Status       = [HostStatus]::Unknown
        Method       = "ICMP"
        Details      = @()
    }
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        $ping = $null
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($IPAddress, $TimeoutMs)
            
            switch ($reply.Status) {
                "Success" {
                    $result.IsAlive = $true
                    $result.ResponseTime = $reply.RoundtripTime
                    $result.Status = [HostStatus]::Alive
                    $result.Details += "ICMP Echo Reply received in $($reply.RoundtripTime)ms"
                    break
                }
                "TimedOut" {
                    $result.Status = [HostStatus]::TimedOut
                    $result.Details += "ICMP timeout (attempt $attempt/$MaxRetries)"
                }
                "DestinationNetworkUnreachable" {
                    $result.Status = [HostStatus]::Unreachable
                    $result.Error = "Network unreachable"
                    break
                }
                "DestinationHostUnreachable" {
                    $result.Status = [HostStatus]::Unreachable
                    $result.Error = "Host unreachable"
                    break
                }
                default {
                    $result.Status = [HostStatus]::Filtered
                    $result.Details += "ICMP blocked or filtered: $($reply.Status)"
                }
            }
        }
        catch {
            if ($attempt -eq $MaxRetries) {
                $result.Error = $_.Exception.Message
                $result.Status = [HostStatus]::Unknown
            }
        }
        finally {
            if ($ping) { $ping.Dispose() }
        }
        
        if ($result.IsAlive -or $result.Status -in @([HostStatus]::Unreachable)) {
            break
        }
        
        if ($attempt -lt $MaxRetries) {
            Start-Sleep -Milliseconds 200
        }
    }
    
    return $result
}

function Test-TCPConnectivity {
    <#
    .SYNOPSIS
        Test TCP connectivity to common ports for host discovery
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter()]
        [int]$TimeoutMs = 1000,
        
        [Parameter()]
        [int[]]$CommonPorts = @(80, 443, 22, 21, 25, 53, 135, 139, 445)
    )
    
    $result = @{
        IPAddress    = $IPAddress
        IsAlive      = $false
        ResponseTime = 0
        Error        = $null
        Status       = [HostStatus]::NotResponding
        Method       = "TCP"
        Details      = @()
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $openPorts = @()
    
    foreach ($port in $CommonPorts) {
        $tcpClient = $null
        try {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connection = $tcpClient.BeginConnect($IPAddress, $port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
            
            if ($wait) {
                $tcpClient.EndConnect($connection)
                $result.IsAlive = $true
                $result.Status = [HostStatus]::Alive
                $openPorts += $port
                $result.Details += "TCP connection successful to port $port"
                
                # Found one open port, host is alive - can stop here for discovery
                break
            }
        }
        catch {
            # Connection failed - continue to next port
        }
        finally {
            if ($tcpClient) {
                $tcpClient.Close()
                $tcpClient.Dispose()
            }
        }
    }
    
    $stopwatch.Stop()
    $result.ResponseTime = $stopwatch.ElapsedMilliseconds
    
    if ($result.IsAlive) {
        $result.Details += "Host discovered via TCP probe in $($result.ResponseTime)ms"
        $result.Method = "TCP-$($openPorts -join ',')"
    }
    else {
        $result.Details += "No TCP connections successful to common ports"
        $result.Error = "All TCP probes failed"
    }
    
    return $result
}

function Test-AggressiveDiscovery {
    <#
    .SYNOPSIS
        Aggressive discovery using multiple techniques
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter()]
        [int]$TimeoutMs = 2000,
        
        [Parameter()]
        [int[]]$CommonPorts = @(80, 443, 22, 21, 25, 53, 135, 139, 445, 993, 995, 1433, 3389)
    )
    
    $result = @{
        IPAddress    = $IPAddress
        IsAlive      = $false
        ResponseTime = 0
        Error        = $null
        Status       = [HostStatus]::NotResponding
        Method       = "Aggressive"
        Details      = @()
    }
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    # 1. Try ICMP first
    $icmpResult = Test-ICMPConnectivity -IPAddress $IPAddress -TimeoutMs ($TimeoutMs / 3) -MaxRetries 1
    if ($icmpResult.IsAlive) {
        $result = $icmpResult
        $result.Method = "Aggressive-ICMP"
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
        return $result
    }
    
    # 2. Try TCP to more ports
    $tcpResult = Test-TCPConnectivity -IPAddress $IPAddress -TimeoutMs ($TimeoutMs / 3) -CommonPorts $CommonPorts
    if ($tcpResult.IsAlive) {
        $result = $tcpResult
        $result.Method = "Aggressive-TCP"
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
        return $result
    }
    
    # 3. Try UDP probes to common services
    $udpResult = Test-UDPConnectivity -IPAddress $IPAddress -TimeoutMs ($TimeoutMs / 3)
    if ($udpResult.IsAlive) {
        $result = $udpResult
        $result.Method = "Aggressive-UDP"
        $stopwatch.Stop()
        $result.ResponseTime = $stopwatch.ElapsedMilliseconds
        return $result
    }
    
    # 4. ARP table check for local network
    if (Test-LocalNetwork -IPAddress $IPAddress) {
        $arpResult = Test-ARPConnectivity -IPAddress $IPAddress
        if ($arpResult.IsAlive) {
            $result = $arpResult
            $result.Method = "Aggressive-ARP"
            $stopwatch.Stop()
            $result.ResponseTime = $stopwatch.ElapsedMilliseconds
            return $result
        }
    }
    
    $stopwatch.Stop()
    $result.ResponseTime = $stopwatch.ElapsedMilliseconds
    $result.Details += "All aggressive discovery methods failed"
    $result.Error = "Host unresponsive to all probes"
    
    return $result
}

function Test-UDPConnectivity {
    <#
    .SYNOPSIS
        Test UDP connectivity to common services
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter()]
        [int]$TimeoutMs = 1000
    )
    
    $result = @{
        IPAddress    = $IPAddress
        IsAlive      = $false
        ResponseTime = 0
        Error        = $null
        Status       = [HostStatus]::NotResponding
        Method       = "UDP"
        Details      = @()
    }
    
    # Common UDP services for discovery
    $udpPorts = @{
        53  = "DNS"
        161 = "SNMP"
        123 = "NTP"
        67  = "DHCP"
    }
    
    foreach ($portInfo in $udpPorts.GetEnumerator()) {
        $port = $portInfo.Key
        $service = $portInfo.Value
        
        try {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = $TimeoutMs
            
            switch ($service) {
                "DNS" {
                    # Send DNS query
                    $dnsQuery = @(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01)
                    $udpClient.Send($dnsQuery, $dnsQuery.Length, $IPAddress, $port) | Out-Null
                }
                "SNMP" {
                    # Send SNMP GetRequest
                    $snmpQuery = @(0x30, 0x19, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x0c, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00)
                    $udpClient.Send($snmpQuery, $snmpQuery.Length, $IPAddress, $port) | Out-Null
                }
                default {
                    # Generic UDP probe
                    $genericProbe = @(0x00, 0x01, 0x02, 0x03)
                    $udpClient.Send($genericProbe, $genericProbe.Length, $IPAddress, $port) | Out-Null
                }
            }
            
            # Try to receive response
            $remoteEndPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $response = $udpClient.Receive([ref]$remoteEndPoint)
            
            if ($response -and $response.Length -gt 0) {
                $result.IsAlive = $true
                $result.Status = [HostStatus]::Alive
                $result.Details += "UDP response from $service on port $port"
                break
            }
        }
        catch {
            # UDP probe failed or no response - continue
        }
        finally {
            if ($udpClient) { $udpClient.Close() }
        }
    }
    
    return $result
}

function Test-ARPConnectivity {
    <#
    .SYNOPSIS
        Check ARP table for local network host discovery
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    $result = @{
        IPAddress    = $IPAddress
        IsAlive      = $false
        ResponseTime = 0
        Error        = $null
        Status       = [HostStatus]::NotResponding
        Method       = "ARP"
        Details      = @()
    }
    
    try {
        # Check Windows ARP table
        $arpOutput = arp -a | Where-Object { $_ -match $IPAddress }
        
        if ($arpOutput) {
            $result.IsAlive = $true
            $result.Status = [HostStatus]::Alive
            $result.Details += "Found in ARP table: $arpOutput"
            $result.ResponseTime = 0  # ARP lookup is instant
        }
        else {
            $result.Details += "Not found in ARP table"
        }
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Test-LocalNetwork {
    <#
    .SYNOPSIS
        Determine if IP address is on local network
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    try {
        $localIPs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "127\.|169\.254\." }
        
        foreach ($localIP in $localIPs) {
            $network = [System.Net.IPAddress]::Parse($localIP.IPAddress).GetAddressBytes()
            $target = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $prefixLength = $localIP.PrefixLength
            
            # Simple subnet check
            $networkMask = [uint32]((0xFFFFFFFF) -shl (32 - $prefixLength))
            $networkAddr = [System.BitConverter]::ToUInt32($network, 0) -band $networkMask
            $targetAddr = [System.BitConverter]::ToUInt32($target, 0) -band $networkMask
            
            if ($networkAddr -eq $targetAddr) {
                return $true
            }
        }
        
        return $false
    }
    catch {
        return $false
    }
}

function Get-ServiceInfo {
    <#
    .SYNOPSIS
        Enhanced service detection with banner grabbing
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [int]$Port,
        
        [Parameter()]
        [int]$TimeoutMs = 2000
    )
    
    $serviceInfo = @{
        Port      = $Port
        Service   = if ($Global:ServicePorts.ContainsKey($Port)) { $Global:ServicePorts[$Port] } else { "Unknown" }
        Version   = "Unknown"
        Banner    = ""
        IsSecure  = $false
        IsOpen    = $false
    }
    
    $tcpClient = $null
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connection = $tcpClient.BeginConnect($IPAddress, $Port, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        
        if ($wait) {
            $tcpClient.EndConnect($connection)
            $serviceInfo.IsOpen = $true
            
            # Banner grabbing for specific services
            if ($Port -in @(21, 22, 25, 80, 110, 143, 443)) {
                try {
                    $stream = $tcpClient.GetStream()
                    $stream.ReadTimeout = 1000
                    
                    # Send appropriate probe based on service
                    switch ($Port) {
                        80 { 
                            $probe = "GET / HTTP/1.0`r`n`r`n"
                            $writer = New-Object System.IO.StreamWriter($stream)
                            $writer.Write($probe)
                            $writer.Flush()
                            $writer.Dispose()
                        }
                        443 { 
                            $serviceInfo.IsSecure = $true 
                        }
                        default { 
                            # For other services, just read banner
                        }
                    }
                    
                    $buffer = New-Object byte[] 1024
                    $bytesRead = $stream.Read($buffer, 0, 1024)
                    
                    if ($bytesRead -gt 0) {
                        $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                        $serviceInfo.Banner = $banner.Substring(0, [math]::Min(200, $banner.Length)).Trim()
                        
                        # Extract version information
                        if ($banner -match "(\d+\.\d+\.?\d*)") {
                            $serviceInfo.Version = $matches[1]
                        }
                        
                        # Update service name based on banner
                        switch -Regex ($banner) {
                            "nginx"         { $serviceInfo.Service = "nginx" }
                            "Apache"        { $serviceInfo.Service = "Apache" }
                            "Microsoft-IIS" { $serviceInfo.Service = "IIS" }
                            "OpenSSH"       { $serviceInfo.Service = "OpenSSH" }
                            "vsftpd"        { $serviceInfo.Service = "vsftpd" }
                            "Postfix"       { $serviceInfo.Service = "Postfix" }
                            "Microsoft"     { $serviceInfo.Service = "Microsoft" }
                        }
                    }
                    
                    $stream.Dispose()
                }
                catch {
                    # Banner grabbing failed, but port is open
                    Write-Log "Banner grab failed for $IPAddress`:$Port - $($_.Exception.Message)" -Level ([LogLevel]::DEBUG)
                }
            }
        }
    }
    catch {
        # Connection failed - port is closed
        Write-Log "Connection failed for $IPAddress`:$Port - $($_.Exception.Message)" -Level ([LogLevel]::DEBUG)
    }
    finally {
        if ($tcpClient) {
            $tcpClient.Close()
            $tcpClient.Dispose()
        }
    }
    
    return $serviceInfo
}

function Invoke-PortScan {
    <#
    .SYNOPSIS
        Comprehensive port scanning with service detection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [int[]]$PortList,
        
        [Parameter()]
        [int]$TimeoutMs = 2000
    )
    
    $scanResult = @{
        IPAddress    = $IPAddress
        OpenPorts    = @()
        Services     = @()
        TotalPorts   = $PortList.Count
        ScanTime     = 0
        Errors       = @()
    }
    
    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        foreach ($port in $PortList) {
            try {
                $serviceInfo = Get-ServiceInfo -IPAddress $IPAddress -Port $port -TimeoutMs $TimeoutMs
                if ($serviceInfo.IsOpen) {
                    $scanResult.OpenPorts += $port
                    $scanResult.Services += $serviceInfo
                    $Global:ScriptConfig.TotalOpenPorts++
                }
            }
            catch {
                $scanResult.Errors += "Port scan failed for port $port`: $($_.Exception.Message)"
            }
        }
        
        $stopwatch.Stop()
        $scanResult.ScanTime = $stopwatch.ElapsedMilliseconds
        
        Write-Log "Port scan completed for $IPAddress - Found $($scanResult.OpenPorts.Count) open ports in $($scanResult.ScanTime)ms" -Level ([LogLevel]::DEBUG)
    }
    catch {
        Invoke-ErrorHandler -Operation "Port Scan for $IPAddress" -ErrorRecord $_
    }
    
    return $scanResult
}

function Invoke-ComprehensiveHostScan {
    <#
    .SYNOPSIS
        Enhanced host scanning with early termination for non-responding hosts
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [int[]]$PortList,
        
        [Parameter()]
        [int]$TimeoutMs = 2000,
        
        [Parameter()]
        [DiscoveryMethod]$DiscoveryMethod = [DiscoveryMethod]::Both
    )
    
    $hostResult = @{
        IPAddress       = $IPAddress
        IsAlive         = $false
        ResponseTime    = 0
        OpenPorts       = @()
        Services        = @()
        Vulnerabilities = @()
        ScanTime        = 0
        Errors          = @()
        Status          = [HostStatus]::Unknown
        DiscoveryMethod = $DiscoveryMethod
        DiscoveryDetails = @()
    }
    
    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Enhanced connectivity test with multiple methods
        $connectivityResult = Test-HostConnectivity -IPAddress $IPAddress -TimeoutMs $TimeoutMs -Method $DiscoveryMethod
        
        $hostResult.IsAlive = $connectivityResult.IsAlive
        $hostResult.ResponseTime = $connectivityResult.ResponseTime
        $hostResult.Status = $connectivityResult.Status
        $hostResult.DiscoveryDetails = $connectivityResult.Details
        
        if ($connectivityResult.Error) {
            $hostResult.Errors += $connectivityResult.Error
        }
        
        # CRITICAL: Only proceed with port scanning if host is confirmed alive
        if ($hostResult.IsAlive -and $hostResult.Status -eq [HostStatus]::Alive) {
            $Global:ScriptConfig.LiveHosts++
            
            Write-Log "Host $IPAddress is alive (via $($connectivityResult.Method)), proceeding with port scan..." -Level ([LogLevel]::DEBUG)
            
            $portScanResult = Invoke-PortScan -IPAddress $IPAddress -PortList $PortList -TimeoutMs $TimeoutMs
            $hostResult.OpenPorts = $portScanResult.OpenPorts
            $hostResult.Services = $portScanResult.Services
            $hostResult.Errors += $portScanResult.Errors
            
            # Perform vulnerability assessment if enabled AND ports are open
            if ($EnableVulnScan -and $hostResult.OpenPorts.Count -gt 0) {
                $hostResult.Vulnerabilities = Test-HostVulnerabilities -IPAddress $IPAddress -OpenPorts $hostResult.OpenPorts -Services $hostResult.Services
                $Global:ScriptConfig.VulnerabilitiesFound += $hostResult.Vulnerabilities.Count
            }
        }
        else {
            # Host is not alive - skip all further scanning
            Write-Log "Host $IPAddress is not responsive (Status: $($hostResult.Status)) - skipping port scan and vulnerability assessment" -Level ([LogLevel]::DEBUG)
            
            # Add reason for skipping
            switch ($hostResult.Status) {
                ([HostStatus]::NotResponding) { 
                    $hostResult.Errors += "Host appears to be offline or unreachable"
                }
                ([HostStatus]::Filtered) { 
                    $hostResult.Errors += "Host is filtered (firewall blocking discovery probes)"
                }
                ([HostStatus]::TimedOut) { 
                    $hostResult.Errors += "Host discovery timed out"
                }
                ([HostStatus]::Unreachable) { 
                    $hostResult.Errors += "Host or network is unreachable"
                }
                default { 
                    $hostResult.Errors += "Host discovery failed for unknown reason"
                }
            }
        }
        
        $stopwatch.Stop()
        $hostResult.ScanTime = $stopwatch.ElapsedMilliseconds
        $Global:ScriptConfig.ScannedHosts++
        
        $scanSummary = if ($hostResult.IsAlive) {
            "Alive: YES, Ports: $($hostResult.OpenPorts.Count), Vulnerabilities: $($hostResult.Vulnerabilities.Count)"
        } else {
            "Alive: NO (Status: $($hostResult.Status))"
        }
        
        Write-Log "Host scan completed for $IPAddress - $scanSummary, Time: $($hostResult.ScanTime)ms" -Level ([LogLevel]::DEBUG)
    }
    catch {
        Invoke-ErrorHandler -Operation "Host Scan for $IPAddress" -ErrorRecord $_
        $hostResult.Errors += $_.Exception.Message
        $hostResult.Status = [HostStatus]::Unknown
    }
    
    return $hostResult
}

#endregion

#region 4. VULNERABILITY ASSESSMENT

function Test-HostVulnerabilities {
    <#
    .SYNOPSIS
        Comprehensive vulnerability assessment for discovered services
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [array]$OpenPorts,
        
        [Parameter(Mandatory = $true)]
        [array]$Services
    )
    
    $vulnerabilities = @()
    
    try {
        # Check for insecure services
        foreach ($service in $Services) {
            switch ($service.Service) {
                "Telnet" {
                    $vulnerabilities += @{
                        Type           = "Insecure Protocol"
                        Service        = "Telnet"
                        Port           = $service.Port
                        Severity       = [VulnerabilitySeverity]::High
                        Description    = "Telnet transmits credentials in clear text"
                        Recommendation = "Replace with SSH (port 22)"
                        CVE            = "N/A"
                        CVSS           = 7.5
                    }
                }
                
                "FTP" {
                    if ($service.Banner -notmatch "FTPS|SFTP") {
                        $vulnerabilities += @{
                            Type           = "Insecure Protocol"
                            Service        = "FTP"
                            Port           = $service.Port
                            Severity       = [VulnerabilitySeverity]::Medium
                            Description    = "Plain FTP transmits credentials in clear text"
                            Recommendation = "Use FTPS (port 990) or SFTP (port 22) instead"
                            CVE            = "N/A"
                            CVSS           = 5.3
                        }
                    }
                }
                
                "HTTP" {
                    if ($service.Port -eq 80 -and (443 -in $OpenPorts)) {
                        $vulnerabilities += @{
                            Type           = "Configuration Issue"
                            Service        = "HTTP"
                            Port           = $service.Port
                            Severity       = [VulnerabilitySeverity]::Medium
                            Description    = "HTTP service running alongside HTTPS - potential for downgrade attacks"
                            Recommendation = "Redirect all HTTP traffic to HTTPS and implement HSTS"
                            CVE            = "N/A"
                            CVSS           = 4.3
                        }
                    }
                }
                
                "SMB" {
                    if ($service.Port -in @(139, 445)) {
                        $vulnerabilities += @{
                            Type           = "Network Exposure"
                            Service        = "SMB"
                            Port           = $service.Port
                            Severity       = [VulnerabilitySeverity]::Medium
                            Description    = "SMB service exposed to network - potential for lateral movement"
                            Recommendation = "Restrict SMB access to trusted networks or disable if not needed"
                            CVE            = "Various"
                            CVSS           = 6.5
                        }
                    }
                }
                
                "RDP" {
                    if ($service.Port -eq 3389) {
                        $vulnerabilities += @{
                            Type           = "Network Exposure"
                            Service        = "RDP"
                            Port           = $service.Port
                            Severity       = [VulnerabilitySeverity]::High
                            Description    = "RDP service exposed - high risk for brute force attacks"
                            Recommendation = "Use VPN access, enable NLA, implement account lockout policies"
                            CVE            = "CVE-2019-0708"
                            CVSS           = 9.8
                        }
                    }
                }
                
                "SNMP" {
                    if ($service.Port -eq 161) {
                        $vulnerabilities += @{
                            Type           = "Information Disclosure"
                            Service        = "SNMP"
                            Port           = $service.Port
                            Severity       = [VulnerabilitySeverity]::Medium
                            Description    = "SNMP service exposed - may reveal system information"
                            Recommendation = "Use SNMPv3 with authentication, restrict community strings"
                            CVE            = "N/A"
                            CVSS           = 5.3
                        }
                    }
                }
            }
        }
        
        # Check for excessive open ports
        if ($OpenPorts.Count -gt 10) {
            $vulnerabilities += @{
                Type           = "Configuration Issue"
                Service        = "Multiple"
                Port           = "Various"
                Severity       = [VulnerabilitySeverity]::Low
                Description    = "Large number of open ports ($($OpenPorts.Count)) detected - increased attack surface"
                Recommendation = "Review and close unnecessary ports, implement port-based access controls"
                CVE            = "N/A"
                CVSS           = 3.1
            }
        }
        
        # Check for common vulnerable port combinations
        if (21 -in $OpenPorts -and 22 -notin $OpenPorts) {
            $vulnerabilities += @{
                Type           = "Missing Security Control"
                Service        = "File Transfer"
                Port           = "21"
                Severity       = [VulnerabilitySeverity]::Medium
                Description    = "FTP available but no SSH - missing secure file transfer option"
                Recommendation = "Enable SSH/SFTP for secure file transfers"
                CVE            = "N/A"
                CVSS           = 4.3
            }
        }
        
        Write-Log "Vulnerability assessment completed for $IPAddress - Found $($vulnerabilities.Count) potential issues" -Level ([LogLevel]::DEBUG)
    }
    catch {
        Invoke-ErrorHandler -Operation "Vulnerability Assessment for $IPAddress" -ErrorRecord $_
    }
    
    return $vulnerabilities
}

#endregion

#region 5. THREAD MANAGEMENT

function Get-OptimalThreadCount {
    <#
    .SYNOPSIS
        Calculate optimal thread count based on system resources
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$DefaultThreads = 500,  # Conservative baseline for all systems
        
        [Parameter()]
        [int]$TotalTargets = 1000
    )
    
    try {
        Write-Log "Analyzing system resources for thread optimization..." -Level ([LogLevel]::DEBUG)
        
        # Initialize fallback values
        $logicalProcessors = 4  # Fallback value
        $freeMemoryMB = 4096   # Fallback value
        
        # Try multiple methods to get system information
        try {
            # Method 1: Try CIM first
            $cpu = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            
            $logicalProcessors = $cpu.NumberOfLogicalProcessors
            $freeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024)
            
            Write-Log "CIM method successful - CPU cores: $logicalProcessors, Free memory: ${freeMemoryMB}MB" -Level ([LogLevel]::DEBUG)
        }
        catch {
            Write-Log "CIM method failed, trying WMI..." -Level ([LogLevel]::DEBUG)
            
            try {
                # Method 2: Try WMI as fallback
                $cpu = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
                $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                
                $logicalProcessors = $cpu.NumberOfLogicalProcessors
                $freeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024)
                
                Write-Log "WMI method successful - CPU cores: $logicalProcessors, Free memory: ${freeMemoryMB}MB" -Level ([LogLevel]::DEBUG)
            }
            catch {
                Write-Log "WMI method failed, trying environment variables..." -Level ([LogLevel]::DEBUG)
                
                try {
                    # Method 3: Try environment variables and .NET memory estimation
                    $logicalProcessors = [int]$env:NUMBER_OF_PROCESSORS
                    
                    # Get total physical memory from system info if available
                    try {
                        $computerInfo = Get-ComputerInfo -Property TotalPhysicalMemory -ErrorAction Stop
                        $totalMemoryMB = [math]::Round($computerInfo.TotalPhysicalMemory / 1MB)
                        $freeMemoryMB = [math]::Round($totalMemoryMB * 0.6)  # Estimate 60% available
                    }
                    catch {
                        # Fallback to GC memory estimation
                        $currentMemoryMB = [math]::Round([System.GC]::GetTotalMemory($false) / 1MB)
                        $freeMemoryMB = [math]::Max(2048, $currentMemoryMB * 2)  # Conservative estimate
                    }
                    
                    Write-Log "Environment method successful - CPU cores: $logicalProcessors, Estimated free memory: ${freeMemoryMB}MB" -Level ([LogLevel]::DEBUG)
                }
                catch {
                    Write-Log "All methods failed, using fallback values - CPU cores: $logicalProcessors, Free memory: ${freeMemoryMB}MB" -Level ([LogLevel]::WARNING)
                }
            }
        }
        
        # Validate values
        if ($logicalProcessors -le 0) { $logicalProcessors = 4 }
        if ($freeMemoryMB -le 0) { $freeMemoryMB = 4096 }
        
        # Calculate optimal thread counts based on different factors - FULLY DYNAMIC APPROACH
        
        # 1. CPU-based calculation - Dynamic scaling based on actual core count
        # Network I/O bound operations can handle more threads than CPU bound tasks
        # Use logarithmic scaling to prevent excessive thread creation on very high-core systems
        $coreMultiplier = if ($logicalProcessors -le 2) { 4 }      # 2-core: conservative
                         elseif ($logicalProcessors -le 4) { 6 }   # 4-core: moderate
                         elseif ($logicalProcessors -le 8) { 8 }   # 8-core: aggressive
                         elseif ($logicalProcessors -le 16) { 10 } # 16-core: very aggressive
                         elseif ($logicalProcessors -le 32) { 12 } # 32-core: maximum aggressive
                         else { 15 }                               # 32+ core: ultra aggressive
        
        $cpuBasedThreads = $logicalProcessors * $coreMultiplier
        
        # 2. Memory-based calculation - Dynamic based on available memory
        # Estimate 2MB per thread for network scanning (conservative estimate including overhead)
        $memoryPerThreadMB = 2
        $memoryBasedThreads = [math]::Floor($freeMemoryMB * 0.7 / $memoryPerThreadMB)  # Use 70% of free memory
        
        # 3. Target-based calculation - Adaptive scaling based on scan size
        # Ensure we don't create more threads than targets, but scale appropriately
        $targetRatio = if ($TotalTargets -le 50) { 0.5 }      # Small scans: 50% thread-to-target ratio
                      elseif ($TotalTargets -le 200) { 0.6 }  # Medium scans: 60% ratio
                      elseif ($TotalTargets -le 1000) { 0.4 } # Large scans: 40% ratio (more efficient batching)
                      else { 0.3 }                            # Massive scans: 30% ratio (maximum efficiency)
        
        $targetBasedThreads = [math]::Min($TotalTargets, [math]::Floor($TotalTargets * $targetRatio))
        
        # 4. Dynamic system capacity limit - Based on actual system resources
        # Calculate maximum threads based on system tier (determined by CPU+Memory combination)
        $systemTier = Get-SystemPerformanceTier -LogicalProcessors $logicalProcessors -FreeMemoryMB $freeMemoryMB
        
        switch ($systemTier) {
            "Ultra"    { $maxThreadLimit = [math]::Min(2000, $logicalProcessors * 20) }  # No hardcoded limits
            "High"     { $maxThreadLimit = [math]::Min(1500, $logicalProcessors * 15) }  # Scale with actual cores
            "Medium"   { $maxThreadLimit = [math]::Min(1000, $logicalProcessors * 12) }  # Proportional scaling
            "Low"      { $maxThreadLimit = [math]::Min(500, $logicalProcessors * 8) }    # Conservative scaling
            "Minimal"  { $maxThreadLimit = [math]::Min(200, $logicalProcessors * 4) }    # Very conservative
            default    { $maxThreadLimit = [math]::Min(300, $logicalProcessors * 6) }    # Safe fallback
        }
        
        # INTELLIGENT ADAPTIVE CALCULATION - No hardcoded system assumptions
        # Use weighted approach based on system capability tier
        
        # Calculate base threads using the most restrictive of the three factors
        $baseThreads = [math]::Min([math]::Min($cpuBasedThreads, $memoryBasedThreads), $targetBasedThreads)
        
        # Apply system tier optimization
        $tierMultiplier = switch ($systemTier) {
            "Ultra"   { 1.5 }  # Boost maximum performance systems
            "High"    { 1.3 }  # Moderate boost
            "Medium"  { 1.1 }  # Slight boost
            "Low"     { 0.9 }  # Slight reduction for stability
            "Minimal" { 0.7 }  # Conservative reduction
            default   { 1.0 }  # No change
        }
        
        $optimalThreads = [math]::Floor($baseThreads * $tierMultiplier)
        
        # Apply system capacity limit
        $optimalThreads = [math]::Min($optimalThreads, $maxThreadLimit)
        
        # Apply intelligent minimum based on scan size and system capability
        $intelligentMinimum = [math]::Min(
            [math]::Max(25, [math]::Min($logicalProcessors * 2, $TotalTargets)), 
            200
        )
        $optimalThreads = [math]::Max($optimalThreads, $intelligentMinimum)
        
        Write-Log "Dynamic thread calculation:" -Level ([LogLevel]::INFO)
        Write-Log "  - System Tier: $systemTier (CPU: $logicalProcessors cores, Memory: ${freeMemoryMB}MB)" -Level ([LogLevel]::INFO)
        Write-Log "  - CPU-based threads: $cpuBasedThreads (multiplier: $coreMultiplier)" -Level ([LogLevel]::INFO)
        Write-Log "  - Memory-based threads: $memoryBasedThreads" -Level ([LogLevel]::INFO)
        Write-Log "  - Target-based threads: $targetBasedThreads (ratio: $targetRatio for $TotalTargets targets)" -Level ([LogLevel]::INFO)
        Write-Log "  - System capacity limit: $maxThreadLimit" -Level ([LogLevel]::INFO)
        Write-Log "  - Tier multiplier: $tierMultiplier" -Level ([LogLevel]::INFO)
        Write-Log "  - Final optimized threads: $optimalThreads" -Level ([LogLevel]::INFO)
        
        # Performance prediction
        $estimatedTimePerHost = if ($optimalThreads -gt 100) { 2 } elseif ($optimalThreads -gt 50) { 3 } else { 5 }
        $estimatedTotalMinutes = [math]::Round(($TotalTargets * $estimatedTimePerHost) / ($optimalThreads * 60), 1)
        Write-Log "  - Estimated scan time: $estimatedTotalMinutes minutes" -Level ([LogLevel]::INFO)
        
        return $optimalThreads
    }
    catch {
        $errorMsg = "Thread optimization failed completely: $($_.Exception.Message)"
        Write-Log $errorMsg -Level ([LogLevel]::WARNING)
        Write-Log "Using default thread count: $DefaultThreads" -Level ([LogLevel]::WARNING)
        return $DefaultThreads
    }
}

function Get-AdaptiveThreadCount {
    <#
    .SYNOPSIS
        Dynamically adjust thread count based on runtime performance with 30% safety margins
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$CurrentThreads,
        
        [Parameter(Mandatory = $true)]
        [int]$CompletedHosts,
        
        [Parameter(Mandatory = $true)]
        [int]$TotalHosts,
        
        [Parameter(Mandatory = $true)]
        [timespan]$ElapsedTime,
        
        [Parameter()]
        [int]$MaxAllowedThreads = 0,  # 0 = Auto-calculate based on system
        
        [Parameter()]
        [double]$TargetCPUUtilization = 70,  # Keep 30% CPU free
        
        [Parameter()]
        [double]$TargetMemoryUtilization = 70  # Keep 30% memory free
    )
    
    try {
        # Get current system performance metrics
        $currentCPUUtilization = 0
        $totalMemoryMB = 0
        $currentFreeMemoryMB = 0
        
        try {
            # Quick CPU utilization check
            $cpuCounter = Get-Counter "\Processor(_Total)\% Processor Time" -MaxSamples 1 -ErrorAction Stop
            $currentCPUUtilization = $cpuCounter.CounterSamples.CookedValue
            
            # Get system memory information
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $totalMemoryMB = [math]::Round($os.TotalPhysicalMemory / 1MB)
            $currentFreeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024)
            $systemMemoryUtilization = [math]::Round((($totalMemoryMB - $currentFreeMemoryMB) / $totalMemoryMB) * 100, 1)
        }
        catch {
            Write-Log "Unable to get performance metrics, maintaining current threads" -Level ([LogLevel]::DEBUG)
            return $CurrentThreads
        }
        
        # Dynamically determine maximum allowed threads based on current system state
        $systemTier = Get-SystemPerformanceTier -LogicalProcessors ([int]$env:NUMBER_OF_PROCESSORS) -FreeMemoryMB $currentFreeMemoryMB
        $dynamicMaxThreads = switch ($systemTier) {
            "Ultra"   { [math]::Min(5000, ([int]$env:NUMBER_OF_PROCESSORS) * 25) }
            "High"    { [math]::Min(3000, ([int]$env:NUMBER_OF_PROCESSORS) * 20) }
            "Medium"  { [math]::Min(2000, ([int]$env:NUMBER_OF_PROCESSORS) * 15) }
            "Low"     { [math]::Min(1000, ([int]$env:NUMBER_OF_PROCESSORS) * 10) }
            "Minimal" { [math]::Min(500, ([int]$env:NUMBER_OF_PROCESSORS) * 5) }
            default   { 1000 }
        }
        
        # Use the more restrictive of user-specified max or dynamic calculation
        $effectiveMaxThreads = if ($MaxAllowedThreads -gt 0) { 
            [math]::Min($MaxAllowedThreads, $dynamicMaxThreads) 
        } else { 
            $dynamicMaxThreads 
        }
        
        Write-Log "Adaptive metrics: CPU: $([math]::Round($currentCPUUtilization, 1))% (target: ≤$TargetCPUUtilization%), System Memory: $systemMemoryUtilization% (target: ≤$TargetMemoryUtilization%), Free: ${currentFreeMemoryMB}MB, Threads: $CurrentThreads" -Level ([LogLevel]::DEBUG)
        
        $newThreadCount = $CurrentThreads
        
        # Calculate safety margins
        $cpuMargin = $TargetCPUUtilization - $currentCPUUtilization  # Positive = under target, negative = over target
        $memoryMargin = $TargetMemoryUtilization - $systemMemoryUtilization  # Positive = under target, negative = over target
        
        # PRIORITY 1: If we're exceeding safety margins, reduce threads immediately
        if ($currentCPUUtilization -gt $TargetCPUUtilization -or $systemMemoryUtilization -gt $TargetMemoryUtilization) {
            $cpuOverage = [math]::Max(0, $currentCPUUtilization - $TargetCPUUtilization)
            $memoryOverage = [math]::Max(0, $systemMemoryUtilization - $TargetMemoryUtilization)
            
            # Calculate reduction based on how much we're over the target
            if ($cpuOverage -gt 20 -or $memoryOverage -gt 20) {
                # Severely over target - aggressive reduction
                $reduction = [math]::Max(100, [math]::Round($CurrentThreads * 0.4))  # 40% reduction or at least 100 threads
                $newThreadCount = [math]::Max($CurrentThreads - $reduction, 50)  # Never go below 50
                Write-Log "CRITICAL: Severely over safety margins (CPU: +$([math]::Round($cpuOverage, 1))%, Memory: +$([math]::Round($memoryOverage, 1))%), aggressively reducing threads by $reduction to $newThreadCount" -Level ([LogLevel]::ERROR)
            }
            elseif ($cpuOverage -gt 10 -or $memoryOverage -gt 10) {
                # Moderately over target - significant reduction
                $reduction = [math]::Max(50, [math]::Round($CurrentThreads * 0.25))  # 25% reduction or at least 50 threads
                $newThreadCount = [math]::Max($CurrentThreads - $reduction, 75)  # Never go below 75
                Write-Log "WARNING: Over safety margins (CPU: +$([math]::Round($cpuOverage, 1))%, Memory: +$([math]::Round($memoryOverage, 1))%), reducing threads by $reduction to $newThreadCount" -Level ([LogLevel]::WARNING)
            }
            else {
                # Slightly over target - moderate reduction
                $reduction = [math]::Max(25, [math]::Round($CurrentThreads * 0.15))  # 15% reduction or at least 25 threads
                $newThreadCount = [math]::Max($CurrentThreads - $reduction, 100)  # Maintain reasonable minimum threads
                Write-Log "Over safety margins (CPU: +$([math]::Round($cpuOverage, 1))%, Memory: +$([math]::Round($memoryOverage, 1))%), moderately reducing threads by $reduction to $newThreadCount" -Level ([LogLevel]::INFO)
            }
        }
        # PRIORITY 2: If we're well under safety margins, increase threads aggressively
        elseif ($cpuMargin -gt 10 -and $memoryMargin -gt 10 -and $currentFreeMemoryMB -gt 4096) {
            # Both CPU and memory are well under target with plenty of free memory
            if ($cpuMargin -gt 40 -and $memoryMargin -gt 40) {
                # Severely underutilized - massive increase
                $increment = [math]::Max(200, [math]::Round($CurrentThreads * 1.5))  # 150% increase or at least 200 threads
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System severely underutilized (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), massively increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
            elseif ($cpuMargin -gt 25 -and $memoryMargin -gt 25) {
                # Very underutilized - large increase
                $increment = [math]::Max(150, [math]::Round($CurrentThreads * 1.0))  # 100% increase or at least 150 threads
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System very underutilized (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), significantly increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
            elseif ($cpuMargin -gt 15 -and $memoryMargin -gt 15) {
                # Moderately underutilized - good increase
                $increment = [math]::Max(100, [math]::Round($CurrentThreads * 0.75))  # 75% increase or at least 100 threads
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System underutilized (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
            else {
                # Mildly underutilized - moderate increase
                $increment = [math]::Max(50, [math]::Round($CurrentThreads * 0.5))  # 50% increase or at least 50 threads
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System has capacity (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), moderately increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
        }
        
        # PRIORITY 3: Fine-tune if we're close to targets but still have some room
        elseif ($cpuMargin -gt 5 -and $memoryMargin -gt 5 -and $currentFreeMemoryMB -gt 2048) {
            # Small increase if we have some headroom
            $increment = [math]::Max(25, [math]::Round($CurrentThreads * 0.25))  # 25% increase or at least 25 threads
            $newThreadCount = [math]::Min($CurrentThreads + $increment, $MaxAllowedThreads)
            Write-Log "Fine-tuning: Small headroom available (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), small thread increase by $increment to $newThreadCount" -Level ([LogLevel]::DEBUG)
        }
        else {
            Write-Log "Resource usage optimal: CPU: $([math]::Round($currentCPUUtilization, 1))%, Memory: $systemMemoryUtilization%, maintaining $CurrentThreads threads" -Level ([LogLevel]::DEBUG)
        }
        
        return $newThreadCount
    }
    catch {
        Write-Log "Failed to calculate adaptive thread count: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
        return $CurrentThreads
    }
}

function Get-RealTimeThreadAdjustment {
    <#
    .SYNOPSIS
        Real-time thread adjustment optimized for 30-second intervals
        Maintains 30% CPU and 30% memory safety margins
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$CurrentThreads,
        
        [Parameter()]
        [int]$MaxAllowedThreads = 0,  # 0 = Auto-calculate based on system
        
        [Parameter()]
        [double]$TargetCPUUtilization = 70,  # Keep 30% CPU free
        
        [Parameter()]
        [double]$TargetMemoryUtilization = 70  # Keep 30% memory free
    )
    
    try {
        # Get current system performance metrics
        $currentCPUUtilization = 0
        $totalMemoryMB = 0
        $currentFreeMemoryMB = 0
        
        try {
            # Quick CPU utilization check
            $cpuCounter = Get-Counter "\Processor(_Total)\% Processor Time" -MaxSamples 1 -ErrorAction Stop
            $currentCPUUtilization = $cpuCounter.CounterSamples.CookedValue
            
            # Get system memory information
            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            $totalMemoryMB = [math]::Round($os.TotalPhysicalMemory / 1MB)
            $currentFreeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024)
            $systemMemoryUtilization = [math]::Round((($totalMemoryMB - $currentFreeMemoryMB) / $totalMemoryMB) * 100, 1)
        }
        catch {
            Write-Log "Real-time monitoring: Unable to get performance metrics, maintaining current threads" -Level ([LogLevel]::DEBUG)
            return $CurrentThreads
        }
        
        # Dynamically determine maximum allowed threads based on current system state
        $systemTier = Get-SystemPerformanceTier -LogicalProcessors ([int]$env:NUMBER_OF_PROCESSORS) -FreeMemoryMB $currentFreeMemoryMB
        $dynamicMaxThreads = switch ($systemTier) {
            "Ultra"   { [math]::Min(5000, ([int]$env:NUMBER_OF_PROCESSORS) * 25) }
            "High"    { [math]::Min(3000, ([int]$env:NUMBER_OF_PROCESSORS) * 20) }
            "Medium"  { [math]::Min(2000, ([int]$env:NUMBER_OF_PROCESSORS) * 15) }
            "Low"     { [math]::Min(1000, ([int]$env:NUMBER_OF_PROCESSORS) * 10) }
            "Minimal" { [math]::Min(500, ([int]$env:NUMBER_OF_PROCESSORS) * 5) }
            default   { 1000 }
        }
        
        # Use the more restrictive of user-specified max or dynamic calculation
        $effectiveMaxThreads = if ($MaxAllowedThreads -gt 0) { 
            [math]::Min($MaxAllowedThreads, $dynamicMaxThreads) 
        } else { 
            $dynamicMaxThreads 
        }
        
        Write-Log "Real-time metrics: CPU: $([math]::Round($currentCPUUtilization, 1))% (target: ≤$TargetCPUUtilization%), System Memory: $systemMemoryUtilization% (target: ≤$TargetMemoryUtilization%), Free: ${currentFreeMemoryMB}MB, Threads: $CurrentThreads, Max: $effectiveMaxThreads" -Level ([LogLevel]::DEBUG)
        
        $newThreadCount = $CurrentThreads
        
        # Calculate safety margins
        $cpuMargin = $TargetCPUUtilization - $currentCPUUtilization  # Positive = under target, negative = over target
        $memoryMargin = $TargetMemoryUtilization - $systemMemoryUtilization  # Positive = under target, negative = over target
        
        # PRIORITY 1: If we're exceeding safety margins, reduce threads immediately
        if ($currentCPUUtilization -gt $TargetCPUUtilization -or $systemMemoryUtilization -gt $TargetMemoryUtilization) {
            $cpuOverage = [math]::Max(0, $currentCPUUtilization - $TargetCPUUtilization)
            $memoryOverage = [math]::Max(0, $systemMemoryUtilization - $TargetMemoryUtilization)
            
            # Calculate reduction based on how much we're over the target
            if ($cpuOverage -gt 15 -or $memoryOverage -gt 15) {
                # Critical overutilization - immediate aggressive reduction
                $reduction = [math]::Max(200, [math]::Round($CurrentThreads * 0.6))  # 60% reduction or at least 200
                $newThreadCount = [math]::Max($CurrentThreads - $reduction, 50)
                Write-Log "CRITICAL: Severely over safety margins (CPU: +$([math]::Round($cpuOverage, 1))%, Memory: +$([math]::Round($memoryOverage, 1))%), aggressively reducing threads by $reduction to $newThreadCount" -Level ([LogLevel]::ERROR)
            }
            elseif ($cpuOverage -gt 10 -or $memoryOverage -gt 10) {
                # Moderately over target - significant reduction
                $reduction = [math]::Max(100, [math]::Round($CurrentThreads * 0.4))  # 40% reduction or at least 100
                $newThreadCount = [math]::Max($CurrentThreads - $reduction, 75)
                Write-Log "WARNING: Over safety margins (CPU: +$([math]::Round($cpuOverage, 1))%, Memory: +$([math]::Round($memoryOverage, 1))%), reducing threads by $reduction to $newThreadCount" -Level ([LogLevel]::WARNING)
            }
            else {
                # Slightly over target - moderate reduction
                $reduction = [math]::Max(75, [math]::Round($CurrentThreads * 0.25))  # 25% reduction or at least 75
                $newThreadCount = [math]::Max($CurrentThreads - $reduction, 100)  # Maintain reasonable minimum threads
                Write-Log "Over safety margins (CPU: +$([math]::Round($cpuOverage, 1))%, Memory: +$([math]::Round($memoryOverage, 1))%), moderately reducing threads by $reduction to $newThreadCount" -Level ([LogLevel]::INFO)
            }
        }
        # PRIORITY 2: If we're well under safety margins, increase threads aggressively
        elseif ($cpuMargin -gt 10 -and $memoryMargin -gt 10 -and $currentFreeMemoryMB -gt 4096) {
            # Both CPU and memory are well under target with plenty of free memory
            if ($cpuMargin -gt 40 -and $memoryMargin -gt 40 -and $currentFreeMemoryMB -gt 12288) {
                # Severely underutilized - massive increase
                $increment = [math]::Max(300, [math]::Round($CurrentThreads * 1.0))  # 100% increase or at least 300
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System severely underutilized (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), massively increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
            elseif ($cpuMargin -gt 25 -and $memoryMargin -gt 25 -and $currentFreeMemoryMB -gt 8192) {
                # Very underutilized - large increase
                $increment = [math]::Max(200, [math]::Round($CurrentThreads * 0.8))  # 80% increase or at least 200
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System very underutilized (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), significantly increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
            elseif ($cpuMargin -gt 15 -and $memoryMargin -gt 15) {
                # Moderately underutilized - good increase
                $increment = [math]::Max(100, [math]::Round($CurrentThreads * 0.75))  # 75% increase or at least 100 threads
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System underutilized (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
            else {
                # Mildly underutilized - moderate increase
                $increment = [math]::Max(50, [math]::Round($CurrentThreads * 0.5))  # 50% increase or at least 50 threads
                $newThreadCount = [math]::Min($CurrentThreads + $increment, $effectiveMaxThreads)
                Write-Log "System has capacity (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), moderately increasing threads by $increment to $newThreadCount" -Level ([LogLevel]::INFO)
            }
        }
        
        # PRIORITY 3: Fine-tune if we're close to targets but still have some room
        elseif ($cpuMargin -gt 5 -and $memoryMargin -gt 5 -and $currentFreeMemoryMB -gt 2048) {
            # Small increase if we have some headroom
            $increment = [math]::Max(25, [math]::Round($CurrentThreads * 0.25))  # 25% increase or at least 25 threads
            $newThreadCount = [math]::Min($CurrentThreads + $increment, $MaxAllowedThreads)
            Write-Log "Fine-tuning: Small headroom available (CPU: -$([math]::Round($cpuMargin, 1))%, Memory: -$([math]::Round($memoryMargin, 1))%), small thread increase by $increment to $newThreadCount" -Level ([LogLevel]::DEBUG)
        }
        else {
            Write-Log "Resource usage optimal: CPU: $([math]::Round($currentCPUUtilization, 1))%, Memory: $systemMemoryUtilization%, maintaining $CurrentThreads threads" -Level ([LogLevel]::DEBUG)
        }
        
        return $newThreadCount
    }
    catch {
        Write-Log "Real-time thread adjustment failed: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
        return $CurrentThreads
    }
}

function Start-ResourceMonitor {
    <#
    .SYNOPSIS
        Start continuous resource monitoring with 20-second intervals after initial 30-second wait
        Adjusts threads by 10% when any free resource is less than 30%
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$IntervalSeconds = 20,
        
        [Parameter()]
        [int]$InitialWaitSeconds = 30,
        
        [Parameter()]
        [double]$FreeResourceThreshold = 30.0,  # 30% free resource threshold
        
        [Parameter()]
        [scriptblock]$OnThreadAdjustment = $null
    )
    
    Write-Log "Starting resource monitor: ${InitialWaitSeconds}s initial wait, then ${IntervalSeconds}s intervals, ${FreeResourceThreshold}% free resource threshold" -Level ([LogLevel]::INFO)
    
    # Store initial thread count
    if (-not $script:currentScanThreads) {
        $script:currentScanThreads = 1000  # Start with 1000 threads
    }
    
    # Initial wait flag
    $script:initialWaitCompleted = $false
    
    # Main monitoring action with 10% adjustment logic - DEFINED FIRST
    $monitoringAction = {
        try {
            if (-not $script:resourceMonitoringActive -or -not $script:initialWaitCompleted) { return }
            
            # Get current resource metrics
            $cpuUtilization = 0
            $memoryUtilization = 0
            $freeCPU = 0
            $freeMemory = 0
            
            try {
                # CPU utilization (average over 2 samples for accuracy)
                $cpuCounter = Get-Counter "\Processor(_Total)\% Processor Time" -MaxSamples 2 -ErrorAction Stop
                $cpuUtilization = [math]::Round(($cpuCounter.CounterSamples | Measure-Object CookedValue -Average).Average, 1)
                $freeCPU = [math]::Round(100 - $cpuUtilization, 1)
                
                # Memory utilization
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                $totalMemoryMB = [math]::Round($os.TotalPhysicalMemory / 1MB)
                $freeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024)
                $memoryUtilization = [math]::Round((($totalMemoryMB - $freeMemoryMB) / $totalMemoryMB) * 100, 1)
                $freeMemory = [math]::Round(100 - $memoryUtilization, 1)
            }
            catch {
                Write-Log "Resource monitor: Failed to get metrics - $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
                return
            }
            
            # Get current thread count
            $oldThreads = $script:currentScanThreads
            $newThreads = $oldThreads
            $adjustmentReason = ""
            
            # Check if ANY free resource is less than 30%
            $needDecrease = ($freeCPU -lt $FreeResourceThreshold) -or ($freeMemory -lt $FreeResourceThreshold)
            $canIncrease = ($freeCPU -gt $FreeResourceThreshold) -and ($freeMemory -gt $FreeResourceThreshold)
            
            if ($needDecrease) {
                # Decrease threads by 10%
                $reduction = [math]::Max(1, [math]::Round($oldThreads * 0.1))
                $newThreads = [math]::Max($oldThreads - $reduction, 10)  # Minimum 10 threads
                $adjustmentReason = "Free resources below threshold (CPU: ${freeCPU}%, Memory: ${freeMemory}%) - reducing by 10%"
            }
            elseif ($canIncrease) {
                # Increase threads by 10%
                $increment = [math]::Max(1, [math]::Round($oldThreads * 0.1))
                $maxThreads = [math]::Min(5000, [int]$env:NUMBER_OF_PROCESSORS * 50)  # Reasonable maximum
                $newThreads = [math]::Min($oldThreads + $increment, $maxThreads)
                $adjustmentReason = "Free resources above threshold (CPU: ${freeCPU}%, Memory: ${freeMemory}%) - increasing by 10%"
            }
            
            # Apply adjustment if needed
            if ($newThreads -ne $oldThreads) {
                $script:currentScanThreads = $newThreads
                $direction = if ($newThreads -gt $oldThreads) { "INCREASED" } else { "DECREASED" }
                $change = [math]::Abs($newThreads - $oldThreads)
                
                $message = "Resource monitor: Thread count $direction by $change (from $oldThreads -> $newThreads) - $adjustmentReason"
                Write-Log $message -Level ([LogLevel]::INFO)
                
                # Call adjustment callback if provided
                if ($OnThreadAdjustment) {
                    try {
                        & $OnThreadAdjustment $newThreads $oldThreads $adjustmentReason
                    }
                    catch {
                        Write-Log "Thread adjustment callback error: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
                    }
                }
            }
            else {
                # Log current status every few checks (to avoid spam)
                if ((Get-Random -Minimum 1 -Maximum 10) -eq 1) {
                    Write-Log "Resource monitor: Stable at $oldThreads threads (CPU: ${freeCPU}% free, Memory: ${freeMemory}% free)" -Level ([LogLevel]::DEBUG)
                }
            }
        }
        catch {
            Write-Log "Resource monitoring error: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
        }
    }
    
    # Create initial wait timer
    $script:initialWaitTimer = New-Object System.Timers.Timer
    $script:initialWaitTimer.Interval = $InitialWaitSeconds * 1000
    $script:initialWaitTimer.AutoReset = $false
    
    # Initial wait completion action
    $initialWaitAction = {
        Write-Log "Resource monitor: Initial ${InitialWaitSeconds}s wait completed, starting periodic monitoring" -Level ([LogLevel]::INFO)
        $script:initialWaitCompleted = $true
        
        # Start the main monitoring timer
        $script:resourceTimer = New-Object System.Timers.Timer
        $script:resourceTimer.Interval = $IntervalSeconds * 1000
        $script:resourceTimer.AutoReset = $true
        
        # Register the main monitoring action
        Register-ObjectEvent -InputObject $script:resourceTimer -EventName Elapsed -Action $monitoringAction | Out-Null
        $script:resourceTimer.Start()
    }
    
    # Register and start the initial wait timer
    Register-ObjectEvent -InputObject $script:initialWaitTimer -EventName Elapsed -Action $initialWaitAction | Out-Null
    $script:initialWaitTimer.Start()
    
    Write-Log "Resource monitor started successfully - monitoring every ${IntervalSeconds} seconds after ${InitialWaitSeconds}s initial wait" -Level ([LogLevel]::INFO)
}

function Stop-ResourceMonitor {
    <#
    .SYNOPSIS
        Stop the resource monitoring system
    #>
    [CmdletBinding()]
    param()
    
    try {
        $script:resourceMonitoringActive = $false
        $script:initialWaitCompleted = $false
        
        # Stop and cleanup main resource timer
        if ($script:resourceTimer) {
            $script:resourceTimer.Stop()
            $script:resourceTimer.Dispose()
            $script:resourceTimer = $null
        }
        
        # Stop and cleanup initial wait timer
        if ($script:initialWaitTimer) {
            $script:initialWaitTimer.Stop()
            $script:initialWaitTimer.Dispose()
            $script:initialWaitTimer = $null
        }
        
        # Cleanup any registered events
        Get-EventSubscriber | Where-Object { $_.SourceObject -is [System.Timers.Timer] } | Unregister-Event -ErrorAction SilentlyContinue
        
        Write-Log "Resource monitor stopped" -Level ([LogLevel]::INFO)
    }
    catch {
        Write-Log "Error stopping resource monitor: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
    }
}

function Start-AdaptiveNetworkScan {
    <#
    .SYNOPSIS
        Adaptive network scanning with real-time resource monitoring and thread adjustment
        Features 20-second interval monitoring with 30% resource threshold management
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$HostList,
        
        [Parameter(Mandatory = $true)]
        [int[]]$PortList,
        
        [Parameter(Mandatory = $true)]
        [int]$InitialThreadCount,
        
        [Parameter()]
        [int]$TimeoutMs = 2000,
        
        [Parameter()]
        [DiscoveryMethod]$DiscoveryMethod = [DiscoveryMethod]::Both,
        
        [Parameter()]
        [bool]$EnablePortScanning = $true,
        
        [Parameter()]
        [bool]$EnableServiceDetection = $true,
        
        [Parameter()]
        [bool]$EnableVulnerabilityAssessment = $true
    )
    
    $allResults = @()
    $currentThreads = 1000  # Start with 1000 threads regardless of input
    $scanStartTime = Get-Date
    $initialWaitCompleted = $false
    
    try {
        Write-Log "Starting adaptive network scan with initial thread count: $currentThreads" -Level ([LogLevel]::INFO)
        Write-Log "Scan parameters: $($HostList.Count) hosts, $($PortList.Count) ports, discovery method: $DiscoveryMethod" -Level ([LogLevel]::INFO)
        
        # Initialize script-level variables for resource monitoring
        $script:resourceMonitoringActive = $true
        $script:currentScanThreads = $currentThreads
        $script:initialWaitCompleted = $false
        
        # Start resource monitoring with new logic
        Start-ResourceMonitor -IntervalSeconds 20 -InitialWaitSeconds 30 -OnThreadAdjustment {
            param($NewThreadCount, $OldThreadCount, $Reason)
            Write-Log "Resource monitor adjusted thread count: $OldThreadCount -> $NewThreadCount ($Reason)" -Level ([LogLevel]::INFO)
            $script:currentScanThreads = $NewThreadCount
        }
        
        # Create single runspace pool for all hosts (no batching)
        Write-Log "Processing all $($HostList.Count) hosts simultaneously with dynamic thread management" -Level ([LogLevel]::INFO)
        
        # Note: PowerShell runspace pools cannot be dynamically resized after creation.
        # The dynamic thread management works by tracking the $script:currentScanThreads variable
        # which represents the logical thread limit, while the actual runspace pool uses the initial thread count.
        # This provides resource monitoring and logging without the complexity of recreating pools mid-scan.
        
        # Create runspace pool with initial thread count
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $currentThreads)
        $runspacePool.Open()
        
        # Define the script block for scanning with self-contained functions
        $scriptBlock = {
            param($IPAddress, $PortList, $TimeoutMs, $DiscoveryMethod, $ServicePorts, $EnablePortScanning, $EnableServiceDetection, $EnableVulnerabilityAssessment)
            
            # Simple host connectivity test with response time capture
            function Test-SimpleConnectivity {
                param($IP, $Timeout)
                
                try {
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    $reply = $ping.Send($IP, $Timeout)
                    $ping.Dispose()
                    
                    if ($reply.Status -eq "Success") {
                        return @{
                            IsAlive = $true
                            ResponseTime = $reply.RoundtripTime
                        }
                    }
                    else {
                        return @{
                            IsAlive = $false
                            ResponseTime = 0
                        }
                    }
                }
                catch {
                    return @{
                        IsAlive = $false
                        ResponseTime = 0
                    }
                }
            }
            
            # Simple port scan
            function Test-PortOpen {
                param($IP, $Port, $Timeout)
                
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connection = $tcpClient.BeginConnect($IP, $Port, $null, $null)
                    $wait = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
                    
                    if ($wait) {
                        $tcpClient.EndConnect($connection)
                        $tcpClient.Close()
                        return $true
                    }
                    else {
                        $tcpClient.Close()
                        return $false
                    }
                }
                catch {
                    return $false
                }
                finally {
                    if ($tcpClient) { $tcpClient.Dispose() }
                }
            }
            
            try {
                $result = @{
                    IPAddress = $IPAddress
                    MACAddress = $null
                    IsAlive = $false
                    ResponseTime = 0
                    OpenPorts = @()
                    Services = @()
                    Vulnerabilities = @()
                    ScanTime = 0
                    Errors = @()
                    Status = "Unknown"
                }
                
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                
                # Test connectivity first and capture response time
                $connectivityResult = Test-SimpleConnectivity -IP $IPAddress -Timeout $TimeoutMs
                $result.IsAlive = $connectivityResult.IsAlive
                $result.ResponseTime = $connectivityResult.ResponseTime
                # Retrieve MAC address for this IP
                try {
                    $mac = (arp -a | Select-String "\b$IPAddress\b")
                    if ($mac) {
                        $macParts = $mac -split '\s+'
                        foreach ($part in $macParts) {
                            if ($part -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                                $result.MACAddress = $part.ToUpper()
                                break
                            }
                        }
                    }
                    if (-not $result.MACAddress) {
                        Test-Connection -ComputerName $IPAddress -Count 1 -Quiet | Out-Null
                        $mac = (arp -a | Select-String "\b$IPAddress\b")
                        if ($mac) {
                            $macParts = $mac -split '\s+'
                            foreach ($part in $macParts) {
                                if ($part -match '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})') {
                                    $result.MACAddress = $part.ToUpper()
                                    break
                                }
                            }
                        }
                    }
                } catch { $result.MACAddress = $null }
                
                if ($result.IsAlive) {
                    $result.Status = "Alive"
                    
                    # Perform port scanning only if enabled
                    if ($EnablePortScanning) {
                        foreach ($port in $PortList) {
                            if (Test-PortOpen -IP $IPAddress -Port $port -Timeout $TimeoutMs) {
                                $result.OpenPorts += $port
                                
                                # Perform service detection only if enabled
                                if ($EnableServiceDetection) {
                                    $serviceInfo = @{
                                        Port = $port
                                        Service = if ($ServicePorts.ContainsKey($port)) { $ServicePorts[$port] } else { "Unknown" }
                                        IsOpen = $true
                                        Banner = "N/A"
                                    }
                                    
                                    # Add basic banner grabbing for common services
                                    try {
                                        if ($port -eq 80 -or $port -eq 8080) {
                                            $serviceInfo.Banner = "HTTP Service"
                                        }
                                        elseif ($port -eq 443) {
                                            $serviceInfo.Banner = "HTTPS Service"
                                        }
                                        elseif ($port -eq 22) {
                                            $serviceInfo.Banner = "SSH Service"
                                        }
                                        elseif ($port -eq 21) {
                                            $serviceInfo.Banner = "FTP Service"
                                        }
                                    }
                                    catch {
                                        $serviceInfo.Banner = "Detection Failed"
                                    }
                                    
                                    $result.Services += $serviceInfo
                                }
                                else {
                                    # Just record the open port without service details
                                    $serviceInfo = @{
                                        Port = $port
                                        Service = "Port Open"
                                        IsOpen = $true
                                    }
                                    $result.Services += $serviceInfo
                                }
                            }
                        }
                        
                        # Perform vulnerability assessment only if enabled AND ports are open
                        if ($EnableVulnScan -and $result.OpenPorts.Count -gt 0) {
                            # Basic vulnerability checks
                            if (21 -in $result.OpenPorts) {
                                $result.Vulnerabilities += "FTP service detected - potential security risk"
                            }
                            if (23 -in $result.OpenPorts) {
                                $result.Vulnerabilities += "Telnet service detected - unencrypted protocol"
                            }
                            if ($result.OpenPorts.Count -gt 10) {
                                $result.Vulnerabilities += "Many open ports detected - potential attack surface"
                            }
                        }
                    }
                }
                else {
                    $result.Status = "Not Responding"
                }
                
                $stopwatch.Stop()
                $result.ScanTime = $stopwatch.ElapsedMilliseconds
                
                return $result
            }
            catch {
                return @{
                    IPAddress = $IPAddress
                    MACAddress = $null
                    IsAlive = $false
                    Error = $_.Exception.Message
                    Status = "Error"
                }
            }
        }
        
        # Create and start jobs for all hosts at once
        $jobs = @()
        Write-Log "Creating $($HostList.Count) scanning jobs..." -Level ([LogLevel]::INFO)
        
        foreach ($hostIP in $HostList) {
            $powerShell = [powershell]::Create()
            $powerShell.RunspacePool = $runspacePool
            $powerShell.AddScript($scriptBlock).AddParameter("IPAddress", $hostIP).AddParameter("PortList", $PortList).AddParameter("TimeoutMs", $TimeoutMs).AddParameter("DiscoveryMethod", $DiscoveryMethod).AddParameter("ServicePorts", $Global:ServicePorts).AddParameter("EnablePortScanning", $EnablePortScanning).AddParameter("EnableServiceDetection", $EnableServiceDetection).AddParameter("EnableVulnerabilityAssessment", $EnableVulnerabilityAssessment) | Out-Null
            
            $jobs += @{
                PowerShell = $powerShell
                Handle = $powerShell.BeginInvoke()
                HostIP = $hostIP
            }
        }
        
        Write-Log "All jobs created. Monitoring completion with dynamic thread management..." -Level ([LogLevel]::INFO)
        
        # Wait for jobs to complete with progress monitoring and dynamic thread adjustment
        $completedJobs = 0
        $lastProgressReport = Get-Date
        
        while ($completedJobs -lt $jobs.Count) {
            Start-Sleep -Milliseconds 100
            
            # Check for completed jobs
            for ($i = 0; $i -lt $jobs.Count; $i++) {
                if ($jobs[$i].Handle.IsCompleted -and $jobs[$i].PowerShell) {
                    try {
                        $result = $jobs[$i].PowerShell.EndInvoke($jobs[$i].Handle)
                        $allResults += $result
                        
                        if ($result.IsAlive) {
                            $Global:ScriptConfig.TotalOpenPorts += $result.OpenPorts.Count
                        }
                    }
                    catch {
                        Write-Log "Job completion error for $($jobs[$i].HostIP): $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
                        $allResults += @{
                            IPAddress = $jobs[$i].HostIP
                            MACAddress = $null
                            IsAlive = $false
                            Error = $_.Exception.Message
                            Status = "JobError"
                        }
                    }
                    finally {
                        $jobs[$i].PowerShell.Dispose()
                        $jobs[$i].PowerShell = $null
                        $completedJobs++
                    }
                }
            }
            
            # Progress reporting every 30 seconds
            $now = Get-Date
            if (($now - $lastProgressReport).TotalSeconds -ge 30) {
                $percentComplete = [math]::Round(($completedJobs / $HostList.Count) * 100, 1)
                $message = "Progress: $completedJobs/$($HostList.Count) hosts completed " + $percentComplete + "%, running $($script:currentScanThreads) threads"
                Write-Log $message -Level ([LogLevel]::INFO)
                $lastProgressReport = $now
            }
        }
        
        # Cleanup runspace pool
        $runspacePool.Close()
        $runspacePool.Dispose()
        
        # Final statistics
        $totalElapsed = (Get-Date) - $scanStartTime
        $liveHosts = ($allResults | Where-Object { $_.IsAlive }).Count
        $totalOpenPorts = ($allResults | Where-Object { $_.OpenPorts } | ForEach-Object { $_.OpenPorts.Count } | Measure-Object -Sum).Sum
        
        # Update global configuration counters
        $Global:ScriptConfig.ScannedHosts = $HostList.Count
        $Global:ScriptConfig.LiveHosts = $liveHosts
        $Global:ScriptConfig.TotalOpenPorts = $totalOpenPorts
        
        Write-Log "Adaptive scan completed successfully!" -Level ([LogLevel]::INFO)
        Write-Log "  - Total time: $([math]::Round($totalElapsed.TotalMinutes, 1)) minutes" -Level ([LogLevel]::INFO)
        Write-Log "  - Hosts scanned: $($HostList.Count)" -Level ([LogLevel]::INFO)
        Write-Log "  - Live hosts found: $liveHosts" -Level ([LogLevel]::INFO)
        Write-Log "  - Total open ports: $totalOpenPorts" -Level ([LogLevel]::INFO)
        Write-Log "  - Final thread count: $($script:currentScanThreads)" -Level ([LogLevel]::INFO)
        
        return $allResults
    }
    catch {
        Write-Log "Adaptive network scan failed: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
        throw
    }
    finally {
        # Stop resource monitoring
        Stop-ResourceMonitor
        $script:resourceMonitoringActive = $false
        
        Write-Log "Resource monitoring stopped and cleanup completed" -Level ([LogLevel]::INFO)
    }
}

function Update-ActiveScanThreads {
    <#
    .SYNOPSIS
        Placeholder function for dynamic thread pool resizing
        Can be extended for actual runspace pool resizing if supported by the platform
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$NewThreadCount,
        
        [Parameter()]
        [string]$Reason = "Resource optimization"
    )
    
    try {
        # Update the global thread count variable
        $script:currentScanThreads = $NewThreadCount
        
        Write-Log "Thread count updated to $NewThreadCount threads ($Reason)" -Level ([LogLevel]::INFO)
        
        # Future enhancement: Implement actual runspace pool resizing
        # This would require more complex runspace management
        # For now, this serves as a placeholder and logging mechanism
        
        return $NewThreadCount
    }
    catch {
        Write-Log "Failed to update thread count: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
        return $script:currentScanThreads
    }
}

function Get-SystemPerformanceTier {
    <#
    .SYNOPSIS
        Dynamically determine system performance tier based on actual hardware resources
        No hardcoded assumptions - works on any system configuration
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$LogicalProcessors,
        
        [Parameter(Mandatory = $true)]
        [double]$FreeMemoryMB
    )
    
    try {
        # Calculate system performance score based on CPU and Memory
        # CPU component (0-50 points) - logarithmic scaling to handle extreme systems
        $cpuScore = if ($LogicalProcessors -le 1) { 5 }
                   elseif ($LogicalProcessors -le 2) { 10 }
                   elseif ($LogicalProcessors -le 4) { 20 }
                   elseif ($LogicalProcessors -le 8) { 30 }
                   elseif ($LogicalProcessors -le 16) { 40 }
                   elseif ($LogicalProcessors -le 32) { 45 }
                   else { 50 }  # 32+ cores = maximum CPU score
        
        # Memory component (0-50 points) - progressive scaling
        $memoryScore = if ($FreeMemoryMB -lt 1024) { 5 }        # <1GB free
                      elseif ($FreeMemoryMB -lt 2048) { 10 }     # 1-2GB free
                      elseif ($FreeMemoryMB -lt 4096) { 20 }     # 2-4GB free
                      elseif ($FreeMemoryMB -lt 8192) { 30 }     # 4-8GB free
                      elseif ($FreeMemoryMB -lt 16384) { 40 }    # 8-16GB free
                      elseif ($FreeMemoryMB -lt 32768) { 45 }    # 16-32GB free
                      else { 50 }                                # 32GB+ free = maximum memory score
        
        # Calculate total performance score (0-100)
        $totalScore = $cpuScore + $memoryScore
        
        # Determine tier based on total score
        $tier = if ($totalScore -ge 90) { "Ultra" }        # 90-100: Maximum performance systems
               elseif ($totalScore -ge 70) { "High" }      # 70-89: High performance systems
               elseif ($totalScore -ge 50) { "Medium" }    # 50-69: Medium-range systems
               elseif ($totalScore -ge 30) { "Low" }       # 30-49: Low-end systems
               else { "Minimal" }                          # 0-29: Minimal/embedded systems
        
        Write-Log "System Performance Analysis:" -Level ([LogLevel]::DEBUG)
        Write-Log "  - CPU Score: $cpuScore/50" -Level ([LogLevel]::DEBUG)
        Write-Log "  - RAM Score: $memoryScore/50" -Level ([LogLevel]::DEBUG)
        Write-Log "  - Total Score: $totalScore/100" -Level ([LogLevel]::DEBUG)
        Write-Log "  - Performance Tier: $tier" -Level ([LogLevel]::DEBUG)
        
        return $tier
    }
    catch {
        Write-Log "Error determining system performance tier: $($_.Exception.Message)" -Level ([LogLevel]::WARNING)
        return "Medium"  # Safe fallback
    }
}

#endregion

#region 6. REPORTING & OUTPUT

function Export-ScanResults {
    <#
    .SYNOPSIS
        Export scan results to HTML and CSV formats
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Results
    )
    
    try {
        # Sort results by IP address in ascending order
        Write-Log "Sorting $($Results.Count) scan results by IP address..." -Level ([LogLevel]::INFO)
        $sortedResults = $Results | Sort-Object { 
            # Convert IP address to sortable format
            $parts = $_.IPAddress.Split('.')
            [int]$parts[0] * 16777216 + [int]$parts[1] * 65536 + [int]$parts[2] * 256 + [int]$parts[3]
        }
        
        # HTML report
        $htmlFile = $Global:ScriptConfig.ReportFile
        $csvFile = [System.IO.Path]::ChangeExtension($htmlFile, ".csv")
        
        Write-Log "Generating HTML report: $htmlFile" -Level ([LogLevel]::INFO)
        
        # Prepare dynamic values for HTML template
        $totalHosts = if ($Global:ScriptConfig.TotalHosts) { $Global:ScriptConfig.TotalHosts } else { $Results.Count }
        $liveHosts = if ($Global:ScriptConfig.LiveHosts) { $Global:ScriptConfig.LiveHosts } else { ($Results | Where-Object { $_.IsAlive }).Count }
        $totalOpenPorts = if ($Global:ScriptConfig.TotalOpenPorts) { $Global:ScriptConfig.TotalOpenPorts } else { ($Results | Where-Object { $_.OpenPorts } | ForEach-Object { $_.OpenPorts.Count } | Measure-Object -Sum).Sum }
        $vulnerabilitiesFound = if ($Global:ScriptConfig.VulnerabilitiesFound) { $Global:ScriptConfig.VulnerabilitiesFound } else { ($Results | Where-Object { $_.Vulnerabilities } | ForEach-Object { $_.Vulnerabilities.Count } | Measure-Object -Sum).Sum }
        
        # Generate HTML report using proper PowerShell string building techniques
        $scanRange = if ($script:NetworkRange) { $script:NetworkRange } else { "Interactive Scan" }
        $currentDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        
        # Build HTML content using proper PowerShell here-string syntax
        $htmlTemplate = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced Network Scan Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background: #f5f5f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header { 
            text-align: center; 
            background: #2c3e50; 
            color: white; 
            padding: 20px; 
            margin: -20px -20px 20px -20px; 
            border-radius: 8px 8px 0 0;
        }
        .stats { 
            display: flex; 
            justify-content: space-around; 
            margin: 20px 0; 
            flex-wrap: wrap;
        }
        .stat-card { 
            text-align: center; 
            padding: 15px; 
            background: #ecf0f1; 
            border-radius: 5px; 
            min-width: 120px;
            margin: 5px;
        }
        .stat-number { 
            font-size: 24px; 
            font-weight: bold; 
            color: #2c3e50; 
        }
        .stat-label { 
            color: #666; 
            margin-top: 5px; 
            font-size: 12px;
        }
        .controls { 
            margin: 20px 0; 
            text-align: center;
        }
        .control-btn { 
            background: #3498db; 
            color: white; 
            border: none; 
            padding: 10px 15px; 
            margin: 5px; 
            border-radius: 4px; 
            cursor: pointer; 
            font-size: 14px;
        }
        .control-btn:hover { 
            background: #2980b9; 
        }
        .table-container {
            margin-top: 20px;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .table-header-box {
            background: #34495e;
            border-radius: 8px;
            padding: 0;
            margin: 0 0 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .table-body-box {
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            max-height: 600px;
            overflow-y: auto;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 0;
        }
        .header-table {
            margin: 0;
            background: #34495e;
        }
        .body-table {
            margin: 0;
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border: none;
        }
        .header-table th:nth-child(1), .body-table td:nth-child(1) { width: 15%; }
        .header-table th:nth-child(2), .body-table td:nth-child(2) { width: 15%; }
        .header-table th:nth-child(3), .body-table td:nth-child(3) { width: 20%; }
        .header-table th:nth-child(4), .body-table td:nth-child(4) { width: 25%; }
        .header-table th:nth-child(5), .body-table td:nth-child(5) { width: 20%; }
        .header-table th:nth-child(6), .body-table td:nth-child(6) { width: 8%; }
        th { 
            background: #34495e; 
            color: white; 
            font-weight: bold;
            border-bottom: 2px solid #2c3e50;
        }
        td {
            border-bottom: 1px solid #eee;
        }
        tbody tr:hover { 
            background: #f8f9fa; 
        }
        tbody tr:nth-child(even) {
            background: #fafafa;
        }
        tbody tr:nth-child(even):hover {
            background: #f0f0f0;
        }
        .status-alive { 
            background: #d4edda; 
            color: #155724; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 12px;
            font-weight: bold;
        }
        .status-notresponding { 
            background: #f8d7da; 
            color: #721c24; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 12px;
            font-weight: bold;
        }
        .status-unknown { 
            background: #fff3cd; 
            color: #856404; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 12px;
            font-weight: bold;
        }
        .footer { 
            text-align: center; 
            margin-top: 30px; 
            padding: 20px; 
            background: #34495e; 
            color: white; 
            border-radius: 5px;
        }
        @media (max-width: 768px) {
            .stats { flex-direction: column; }
            .stat-card { margin: 5px 0; }
            .table-container { font-size: 12px; }
            .table-body-box { max-height: 400px; }
            th, td { padding: 8px 4px; }
            .header-table th:nth-child(1), .body-table td:nth-child(1) { width: 20%; }
            .header-table th:nth-child(2), .body-table td:nth-child(2) { width: 15%; }
            .header-table th:nth-child(3), .body-table td:nth-child(3) { width: 20%; }
            .header-table th:nth-child(4), .body-table td:nth-child(4) { width: 20%; }
            .header-table th:nth-child(5), .body-table td:nth-child(5) { width: 15%; }
            .header-table th:nth-child(6), .body-table td:nth-child(6) { width: 10%; }
        }

        /* Print styles: ensure the entire table is visible and not clipped */
        @media print {
            body, .container {
                background: white !important;
                box-shadow: none !important;
            }
            .table-container, .table-body-box {
                max-height: none !important;
                overflow: visible !important;
                box-shadow: none !important;
            }
            .table-header-box {
                box-shadow: none !important;
            }
            .controls, .footer {
                display: none !important;
            }
            .container {
                margin: 0 !important;
                padding: 0 !important;
                width: 100% !important;
                max-width: 100% !important;
            }
            table {
                page-break-inside: auto;
            }
            tr {
                page-break-inside: avoid;
                page-break-after: auto;
            }
            thead { display: table-header-group; }
            tfoot { display: table-footer-group; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Enhanced Network Scan Report</h1>
            <p>Comprehensive network analysis and security assessment</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">$scanRange</div>
                <div class="stat-label">Scan Range</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalHosts</div>
                <div class="stat-label">Total Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$liveHosts</div>
                <div class="stat-label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalOpenPorts</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$vulnerabilitiesFound</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>
        
        <div class="controls">
            <button class="control-btn" onclick="exportToCSV()">📄 Export to CSV</button>
            <button class="control-btn" onclick="filterLiveHosts()">🔍 Show Live Hosts</button>
            <button class="control-btn" onclick="showAllHosts()">📋 Show All Hosts</button>
            <button class="control-btn" onclick="window.print()">🖨️ Print Report</button>
        </div>
        
        <div class="table-container">
            <!-- Table Header Box -->
            <div class="table-header-box">
                <table class="header-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>MAC Address</th>
                            <th>Status</th>
                            <th>Open Ports</th>
                            <th>Services</th>
                            <th>Vulnerabilities</th>
                            <th>Response Time</th>
                        </tr>
                    </thead>
                </table>
            </div>
            
            <!-- Table Body Box -->
            <div class="table-body-box">
                <table class="body-table" id="resultsTable">
                    <tbody>
"@

        # Initialize StringBuilder for building the HTML content
        $html = New-Object System.Text.StringBuilder
        [void]$html.AppendLine($htmlTemplate)
        
        # Generate table rows from results
        foreach ($result in $sortedResults) {
            $openPortsList = if ($result.OpenPorts) { ($result.OpenPorts -join ', ') } else { '' }
            $servicesList = if ($result.Services) {
                $serviceArray = @()
                foreach ($service in $result.Services) {
                    $serviceArray += "$($service.Port):$($service.Service)"
                }
                $serviceArray -join ', '
            } else {
                ''
            }
            $vulnerabilitiesList = if ($result.Vulnerabilities -and $result.Vulnerabilities.Count -gt 0) {
                ($result.Vulnerabilities -join ', ')
            } else {
                ''
            }
            $statusClass = switch ($result.Status) {
                'Alive' { 'status-alive' }
                'NotResponding' { 'status-notresponding' }
                default { 'status-unknown' }
            }
            $latency = if ($null -ne $result.ResponseTime -and $result.ResponseTime -gt 0) {
                "$($result.ResponseTime) ms"
            } else {
                ''
            }
            # Only add rows with a valid IP and at least one other non-empty field
            $hasData = $result.IPAddress -and (
                $openPortsList -or $servicesList -or $vulnerabilitiesList -or $latency -or $result.Status -or $result.MACAddress
            )
            if ($hasData) {
                # Safely encode HTML entities to prevent issues
                $safeIPAddress = [System.Web.HttpUtility]::HtmlEncode($result.IPAddress)
                $safeMAC = if ($result.MACAddress) { [System.Web.HttpUtility]::HtmlEncode($result.MACAddress) } else { 'N/A' }
                $safeOpenPorts = if ($openPortsList) { [System.Web.HttpUtility]::HtmlEncode($openPortsList) } else { 'None' }
                $safeServices = if ($servicesList) { [System.Web.HttpUtility]::HtmlEncode($servicesList) } else { 'None' }
                $safeVulnerabilities = if ($vulnerabilitiesList) { [System.Web.HttpUtility]::HtmlEncode($vulnerabilitiesList) } else { 'None' }
                $safeLatency = if ($latency) { [System.Web.HttpUtility]::HtmlEncode($latency) } else { 'N/A' }
                $safeStatus = if ($result.Status) { [System.Web.HttpUtility]::HtmlEncode($result.Status) } else { 'Unknown' }
                # Build table row using proper string concatenation
                $tableRow = @"
                        <tr>
                            <td>$safeIPAddress</td>
                            <td>$safeMAC</td>
                            <td><span class="$statusClass">$safeStatus</span></td>
                            <td>$safeOpenPorts</td>
                            <td>$safeServices</td>
                            <td>$safeVulnerabilities</td>
                            <td>$safeLatency</td>
                        </tr>
"@
                [void]$html.AppendLine($tableRow)
            }
        }
        
        # Close HTML structure and add JavaScript functionality
        $htmlClosing = @"
                    </tbody>
                </table>
            </div>
        </div>
    </div>
        
    <div class="footer">
        <p>Report generated on: $currentDate</p>
        <p>Powered by Enhanced Network Scanner v2.0</p>
    </div>
</div>
    <style>
        @media print {
            .table-body-box {
                max-height: none !important;
                overflow: visible !important;
                box-shadow: none !important;
                border: none !important;
            }
            .container {
                box-shadow: none !important;
                background: white !important;
            }
        }
    </style>

    <script>
        function exportToCSV() {
            // Get header from header table
            const headerTable = document.querySelector('.header-table');
            const headerRow = headerTable.querySelector('thead tr');
            const headerCells = headerRow.querySelectorAll('th');
            
            // Get body rows from body table
            const bodyTable = document.getElementById('resultsTable');
            const bodyRows = bodyTable.querySelectorAll('tbody tr');
            
            let csvContent = '';
            
            // Add header row
            const headerData = Array.from(headerCells).map(cell => {
                let text = cell.textContent || '';
                return '"' + text.replace(/"/g, '""') + '"';
            }).join(',');
            csvContent += headerData + '\n';
            
            // Add body rows
            bodyRows.forEach(row => {
                const cells = row.querySelectorAll('td');
                const rowData = Array.from(cells).map(cell => {
                    let text = cell.textContent || '';
                    return '"' + text.replace(/"/g, '""') + '"';
                }).join(',');
                csvContent += rowData + '\n';
            });
            
            const blob = new Blob([csvContent], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'network_scan_' + new Date().toISOString().slice(0, 10) + '.csv';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }

        function filterLiveHosts() {
            const bodyTable = document.getElementById('resultsTable');
            const rows = bodyTable.querySelectorAll('tbody tr');
            rows.forEach(row => {
                const statusCell = row.querySelector('td:nth-child(2)');
                const isAlive = statusCell && statusCell.textContent.includes('Alive');
                row.style.display = isAlive ? '' : 'none';
            });
        }

        function showAllHosts() {
            const bodyTable = document.getElementById('resultsTable');
            const rows = bodyTable.querySelectorAll('tbody tr');
            rows.forEach(row => {
                row.style.display = '';
            });
        }

        function toggleVulnDetails() {
            const details = document.querySelectorAll('.vuln-details');
            details.forEach(detail => {
                detail.style.display = detail.style.display === 'none' ? 'block' : 'none';
            });
        }

        // Initialize page
        document.addEventListener('DOMContentLoaded', function() {
            console.log('Enhanced Network Scanner Report loaded');
        });
    </script>
</body>
</html>
"@
        
        # Append closing HTML and convert StringBuilder to string
        [void]$html.AppendLine($htmlClosing)
        $finalHtml = $html.ToString()
        # Write HTML file
        Set-Content -Path $htmlFile -Value $finalHtml -Encoding UTF8
        
        Write-Log "HTML report generated: $htmlFile" -Level ([LogLevel]::INFO)
        
        # CSV export
        Write-Log "Exporting results to CSV: $csvFile" -Level ([LogLevel]::INFO)
        
        $csvData = @()
        foreach ($result in $sortedResults) {
            $openPortsList = if ($result.OpenPorts) { $result.OpenPorts -join ', ' } else { 'None' }
            $servicesList = if ($result.Services) { 
                ($result.Services | ForEach-Object { "$($_.Port):$($_.Service)" }) -join ', ' 
            } else { 
                'None' 
            }
            $vulnerabilitiesList = if ($result.Vulnerabilities) { $result.Vulnerabilities -join ', ' } else { 'None' }
            
            $csvData += [PSCustomObject]@{
                IPAddress       = $result.IPAddress
                MACAddress      = if ($result.MACAddress) { $result.MACAddress } else { 'N/A' }
                Status          = $result.Status
                OpenPorts       = $openPortsList
                Services        = $servicesList
                Vulnerabilities = $vulnerabilitiesList
                Latency         = if ($null -ne $result.ResponseTime -and $result.ResponseTime -gt 0) { "$($result.ResponseTime) ms" } else { 'N/A' }
            }
        }
        
        # Export to CSV
        $csvData | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        
        Write-Log "CSV export completed: $csvFile" -Level ([LogLevel]::INFO)
    }
    catch {
        Write-Log "Failed to export scan results: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
    }
}

function Send-EmailNotification {
    <#
    .SYNOPSIS
        Send email notifications with scan results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToEmail,
        
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        
        [Parameter(Mandatory = $true)]
        [string]$Body,
        
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $true)]
        [securestring]$SecurePassword,
        
        [Parameter()]
        [string]$SMTPServer = "smtp.gmail.com"
    )
    
    try {
        # Create the email message
        $emailMessage = New-Object System.Net.Mail.MailMessage
        $emailMessage.From = $Username
        $emailMessage.To.Add($ToEmail)
        $emailMessage.Subject = $Subject
        $emailMessage.Body = $Body
        $emailMessage.IsBodyHtml = $true
        
        # SMTP client configuration
        $smtpClient = New-Object Net.Mail.SmtpClient($SMTPServer, 587)
        $smtpClient.EnableSsl = $true
        $smtpClient.Credentials = New-Object Net.NetworkCredential($Username, $SecurePassword)
        
        # Send the email
        $smtpClient.Send($emailMessage)
        
        Write-Log "Email notification sent to $ToEmail" -Level ([LogLevel]::INFO)
    }
    catch {
        Write-Log "Failed to send email notification: $($_.Exception.Message)" -Level ([LogLevel]::ERROR)
    }
}

#endregion

#region 7. MAIN EXECUTION FLOW

function Initialize-ScanEnvironment {
    <#
    .SYNOPSIS
        Initialize the scanning environment and validate parameters
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "`n" -NoNewline
        Write-Host "================================================================================================" -ForegroundColor Cyan
        Write-Host "                            Enhanced Network Scanner v2.0" -ForegroundColor White
        Write-Host "================================================================================================" -ForegroundColor Cyan
        Write-Host ""
        
        # Initialize logging
        Initialize-LoggingSystem
        
        # Start performance monitoring with user-specified memory limit
        Start-PerformanceMonitoring -MemoryLimitMB $MemoryLimitMB
        
        # Run system diagnostic if verbose output is enabled
        if ($VerboseOutput) {
            Test-SystemInformation
        }
        
        # Validate email parameters if email is enabled
        if ($EnableEmail) {
            if ([string]::IsNullOrEmpty($EmailTo) -or [string]::IsNullOrEmpty($SMTPUsername)) {
                Write-Log "Email notifications enabled but missing required parameters" -Level ([LogLevel]::ERROR)
                throw "Email notifications require -EmailTo and -SMTPUsername parameters"
            }
        }
        
        # Log scan parameters
        Write-Log "=== Scan Configuration ===" -Level ([LogLevel]::INFO)
        Write-Log "Network Range: $script:NetworkRange" -Level ([LogLevel]::INFO)
        Write-Log "Ports to scan: $($Ports -join ', ')" -Level ([LogLevel]::INFO)
        Write-Log "Timeout: $Timeout ms" -Level ([LogLevel]::INFO)
        Write-Log "Output Path: $OutputPath" -Level ([LogLevel]::INFO)
        Write-Log "Port Scanning: $script:EnablePortScanning" -Level ([LogLevel]::INFO)
        Write-Log "Service Detection: $script:EnableServiceDetection" -Level ([LogLevel]::INFO)
        Write-Log "Vulnerability Scanning: $script:EnableVulnScan" -Level ([LogLevel]::INFO)
        Write-Log "Discovery Method: $Discovery" -Level ([LogLevel]::INFO)
        Write-Log "Email Notifications: $EnableEmail" -Level ([LogLevel]::INFO)
        Write-Log "Memory Limit: $MemoryLimitMB MB" -Level ([LogLevel]::INFO)
        
    }
    catch {
        Invoke-ErrorHandler -Operation "Initialize Scan Environment" -ErrorRecord $_ -Fatal
    }
}

function Start-NetworkScan {
    <#
    .SYNOPSIS
        Main scanning orchestration function
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Starting network scan for range: $script:NetworkRange" -Level ([LogLevel]::INFO)
        
        # Use pre-generated host list if available, otherwise generate new one
        if ($Global:GeneratedHostList) {
            $hostList = $Global:GeneratedHostList
            Write-Log "Using pre-generated host list: $($hostList.Count) hosts" -Level ([LogLevel]::INFO)
        }
        else {
            $hostList = Get-NetworkHosts -NetworkRange $script:NetworkRange
        }
        
        # Determine optimal thread count
        if (-not $MaxThreads) {
            Write-Log "Auto-calculating optimal thread count based on system resources..." -Level ([LogLevel]::INFO)
            $MaxThreads = Get-OptimalThreadCount -DefaultThreads 500 -TotalTargets $hostList.Count
            
            # Dynamic validation based on system performance tier
            $systemTier = Get-SystemPerformanceTier -LogicalProcessors ([int]$env:NUMBER_OF_PROCESSORS) -FreeMemoryMB 0
            $minimumThreads = switch ($systemTier) {
                "Ultra"   { 500 }
                "High"    { 300 }
                "Medium"  { 200 }
                "Low"     { 100 }
                "Minimal" { 50 }
                default   { 100 }
            }
            $maximumThreads = switch ($systemTier) {
                "Ultra"   { 5000 }
                "High"    { 3000 }
                "Medium"  { 2000 }
                "Low"     { 1000 }
                "Minimal" { 500 }
                default   { 1000 }
            }
            
            if ($MaxThreads -lt $minimumThreads) {
                Write-Log "Calculated thread count too low ($MaxThreads), using minimum of $minimumThreads for $systemTier-tier system" -Level ([LogLevel]::WARNING)
                $MaxThreads = $minimumThreads
            }
            elseif ($MaxThreads -gt $maximumThreads) {
                Write-Log "Calculated thread count extremely high ($MaxThreads), capping at $maximumThreads for $systemTier-tier system stability" -Level ([LogLevel]::WARNING)
                $MaxThreads = $maximumThreads
            }
            
            Write-Log "Using optimized thread count: $MaxThreads (based on $($hostList.Count) targets, $systemTier-tier system)" -Level ([LogLevel]::INFO)
        }
        else {
            Write-Log "Using user-specified thread count: $MaxThreads" -Level ([LogLevel]::INFO)
        }
        
        Write-Log "Using $MaxThreads threads for scanning $($hostList.Count) hosts" -Level ([LogLevel]::INFO)
        
        # Use adaptive scanning for better performance and resource utilization
        $discoveryMethod = [DiscoveryMethod]::$Discovery
        $allResults = Start-AdaptiveNetworkScan -HostList $hostList -PortList $Ports -InitialThreadCount $MaxThreads -TimeoutMs $Timeout -DiscoveryMethod $discoveryMethod -EnablePortScanning $script:EnablePortScanning -EnableServiceDetection $script:EnableServiceDetection -EnableVulnerabilityAssessment $script:EnableVulnScan
        
        Write-Log "Network scan completed. Processing results..." -Level ([LogLevel]::INFO)
        
        return $allResults
    }
    catch {
        Invoke-ErrorHandler -Operation "Network Scan" -ErrorRecord $_ -Fatal
    }
}

function Complete-ScanProcess {
    <#
    .SYNOPSIS
        Finalize the scanning process and generate reports
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$ScanResults
    )
    
    try {
        # Generate and export reports
        Export-ScanResults -Results $ScanResults
        
        # Send email notification if enabled
        if ($EnableEmail -and $EmailTo -and $SMTPUsername) {
            $securePassword = Read-Host "Enter SMTP password" -AsSecureString
            
            $emailSubject = "Network Scan Report - $script:NetworkRange"
            $emailBody = @"
<html>
<body>
<h2>Network Scan Completed</h2>
<p><strong>Scan Range:</strong> $script:NetworkRange</p>
<p><strong>Total Hosts:</strong> $($Global:ScriptConfig.TotalHosts)</p>
<p><strong>Live Hosts:</strong> $($Global:ScriptConfig.LiveHosts)</p>
<p><strong>Open Ports Found:</strong> $($Global:ScriptConfig.TotalOpenPorts)</p>
<p><strong>Vulnerabilities Found:</strong> $($Global:ScriptConfig.VulnerabilitiesFound)</p>
<p><strong>Report File:</strong> $($Global:ScriptConfig.ReportFile)</p>
<p>Please open the attached HTML report for complete scan details including service information, banners, and vulnerability assessments.</p>
</body>
</html>
"@
            
            Send-EmailNotification -ToEmail $EmailTo -Subject $emailSubject -Body $emailBody -Username $SMTPUsername -SecurePassword $securePassword -SMTPServer $SMTPServer
        }
        
        # Final summary
        $endTime = Get-Date
        $totalDuration = $endTime - $Global:ScriptConfig.StartTime
        
        Write-Host "`n" -NoNewline
        Write-Host "================================================================================================" -ForegroundColor Green
        Write-Host "                                    SCAN COMPLETED" -ForegroundColor White
        Write-Host "================================================================================================" -ForegroundColor Green
        Write-Host "Total Duration: $($totalDuration.ToString('hh\:mm\:ss'))" -ForegroundColor Yellow
        Write-Host "Hosts Scanned: $($Global:ScriptConfig.ScannedHosts) / $($Global:ScriptConfig.TotalHosts)" -ForegroundColor Yellow
        Write-Host "Live Hosts: $($Global:ScriptConfig.LiveHosts)" -ForegroundColor Yellow
        Write-Host "Open Ports: $($Global:ScriptConfig.TotalOpenPorts)" -ForegroundColor Yellow
        Write-Host "Vulnerabilities: $($Global:ScriptConfig.VulnerabilitiesFound)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Report File:" -ForegroundColor Cyan
        Write-Host "  HTML: $($Global:ScriptConfig.ReportFile)" -ForegroundColor White
        Write-Host "  Log:  $($Global:ScriptConfig.LogFile)" -ForegroundColor White
        Write-Host "================================================================================================" -ForegroundColor Green
        
        Write-Log "=== Scan Summary ===" -Level ([LogLevel]::INFO)
        Write-Log "Total Duration: $($totalDuration.ToString('hh\:mm\:ss'))" -Level ([LogLevel]::INFO)
        Write-Log "Hosts Scanned: $($Global:ScriptConfig.ScannedHosts)" -Level ([LogLevel]::INFO)
        Write-Log "Live Hosts: $($Global:ScriptConfig.LiveHosts)" -Level ([LogLevel]::INFO)
        Write-Log "Open Ports: $($Global:ScriptConfig.TotalOpenPorts)" -Level ([LogLevel]::INFO)
        Write-Log "Vulnerabilities: $($Global:ScriptConfig.VulnerabilitiesFound)" -Level ([LogLevel]::INFO)
        
    }
    catch {
        Invoke-ErrorHandler -Operation "Complete Scan Process" -ErrorRecord $_
    }
    finally {
        # Cleanup
        Stop-PerformanceMonitoring
        
        # Final garbage collection
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
        [System.GC]::Collect()
    }
}

# Main execution block
try {
    # Handle interactive session if network range is not provided or interactive mode is explicitly enabled
    if ([string]::IsNullOrWhiteSpace($NetworkRange) -or $Interactive.IsPresent) {
        $hostList = Initialize-InteractiveSession
        # Store the generated host list for later use
        $Global:GeneratedHostList = $hostList
    }
    
    # Initialize environment
    Initialize-ScanEnvironment
    
    # Execute scan
    $scanResults = Start-NetworkScan
    
    # Complete and finalize
    Complete-ScanProcess -ScanResults $scanResults
}
catch {
    Invoke-ErrorHandler -Operation "Main Execution" -ErrorRecord $_ -Fatal
}
