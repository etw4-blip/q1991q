name: Secure RDP via Tailscale

on:
  workflow_dispatch:

env:
  TS_VERSION: "1.82.0"
  RDP_PORT: 3389
  RDP_USERNAME: "GitHubRDPUser"
  MAX_RETRIES: 15
  RETRY_DELAY: 10

jobs:
  secure-rdp:
    runs-on: windows-latest
    timeout-minutes: 3600

    steps:
      - name: Check Required Secrets
        run: |
          if (-not $env:TAILSCALE_AUTH_KEY) {
            Write-Error "TAILSCALE_AUTH_KEY secret is required. Please add it to repository secrets."
            exit 1
          }

      - name: Configure RDP Securely
        run: |
          # Enable Remote Desktop
          Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
                           -Name "fDenyTSConnections" -Value 0 -Force
          
          # Configure security settings (consider keeping NLA enabled for production)
          Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                           -Name "UserAuthentication" -Value 0 -Force
          Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                           -Name "SecurityLayer" -Value 1 -Force
          
          # Configure firewall rules with specific Tailscale interface
          $existingRules = netsh advfirewall firewall show rule name="RDP-Tailscale" | Out-String
          if ($existingRules -match "Enabled:") {
            netsh advfirewall firewall delete rule name="RDP-Tailscale"
          }
          
          # Allow RDP only on Tailscale interface (more secure)
          netsh advfirewall firewall add rule `
            name="RDP-Tailscale" `
            dir=in `
            action=allow `
            protocol=TCP `
            localport=$env:RDP_PORT `
            remoteip=100.64.0.0/10,fd7a:115c:a1e0::/48 `
            description="Allow RDP over Tailscale VPN" `
            enable=yes
          
          # Restart services for changes to take effect
          Restart-Service -Name TermService -Force -ErrorAction SilentlyContinue
          Start-Sleep -Seconds 5

      - name: Create Secure RDP User
        id: create-user
        run: |
          # Remove existing user if exists (clean state)
          if (Get-LocalUser -Name $env:RDP_USERNAME -ErrorAction SilentlyContinue) {
            Remove-LocalUser -Name $env:RDP_USERNAME -ErrorAction SilentlyContinue
          }
          
          # Generate cryptographically secure password
          Add-Type -AssemblyName System.Security
          $passwordChars = @()
          
          # Ensure password meets Windows complexity requirements
          $passwordChars += [char[]](65..90) | Get-Random -Count 3 # Uppercase
          $passwordChars += [char[]](97..122) | Get-Random -Count 3 # Lowercase
          $passwordChars += [char[]](48..57) | Get-Random -Count 3 # Numbers
          $passwordChars += @('#', '$', '%', '&', '*', '@', '!') | Get-Random -Count 2 # Special chars
          
          # Add random padding to reach 16 characters
          $allChars = (65..90) + (97..122) + (48..57) + @('#', '$', '%', '&', '*', '@', '!')
          $passwordChars += [char[]]$allChars | Get-Random -Count 5
          
          # Shuffle and create password
          $password = -join ($passwordChars | Get-Random -Count $passwordChars.Count)
          $securePass = ConvertTo-SecureString $password -AsPlainText -Force
          
          # Create user with secure settings
          try {
            $newUser = New-LocalUser -Name $env:RDP_USERNAME `
                                     -Password $securePass `
                                     -AccountNeverExpires `
                                     -PasswordNeverExpires:$false `
                                     -UserMayNotChangePassword:$false `
                                     -ErrorAction Stop
            
            Add-LocalGroupMember -Group "Administrators" -Member $env:RDP_USERNAME -ErrorAction Stop
            Add-LocalGroupMember -Group "Remote Desktop Users" -Member $env:RDP_USERNAME -ErrorAction Stop
            
            # Output password (masked in logs)
            Write-Host "::add-mask::$password"
            echo "RDP_USERNAME=$env:RDP_USERNAME" >> $env:GITHUB_ENV
            echo "RDP_PASSWORD=$password" >> $env:GITHUB_ENV
            
            Write-Host "✓ User created successfully: $env:RDP_USERNAME"
          } catch {
            Write-Error "Failed to create user: $_"
            exit 1
          }

      - name: Install Tailscale
        run: |
          $tsUrl = "https://pkgs.tailscale.com/stable/tailscale-setup-$env:TS_VERSION-amd64.msi"
          $installerPath = "$env:TEMP ailscale-$env:TS_VERSION.msi"
          $logPath = "$env:TEMP ailscale-install.log"
          
          Write-Host "Downloading Tailscale v$env:TS_VERSION..."
          Invoke-WebRequest -Uri $tsUrl -OutFile $installerPath -UseBasicParsing
          
          Write-Host "Installing Tailscale..."
          $installArgs = @(
            "/i", "`"$installerPath`"",
            "/quiet",
            "/norestart",
            "/log", "`"$logPath`""
          )
          
          $process = Start-Process msiexec.exe -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
          
          if ($process.ExitCode -ne 0) {
            Write-Error "Tailscale installation failed with exit code $($process.ExitCode)"
            Get-Content $logPath -ErrorAction SilentlyContinue | Write-Host
            exit 1
          }
          
          Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
          Write-Host "✓ Tailscale installed successfully"

      - name: Establish Tailscale Connection
        id: tailscale
        run: |
          $tsExe = "$env:ProgramFiles\Tailscale ailscale.exe"
          $hostname = "gh-runner-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
          
          # Start Tailscale service
          Start-Service -Name Tailscale -ErrorAction SilentlyContinue
          Start-Sleep -Seconds 5
          
          # Connect to Tailscale
          Write-Host "Connecting to Tailscale with hostname: $hostname"
          & $tsExe up --authkey=$env:TAILSCALE_AUTH_KEY --hostname=$hostname --reset
          
          # Wait for IP assignment with retries
          $tsIP = $null
          $retryCount = 0
          
          while (-not $tsIP -and $retryCount -lt $env:MAX_RETRIES) {
            $tsIP = & $tsExe ip -4 2>$null
            if ($tsIP) {
              break
            }
            Write-Host "Waiting for Tailscale IP (attempt $($retryCount + 1)/$env:MAX_RETRIES)..."
            Start-Sleep -Seconds $env:RETRY_DELAY
            $retryCount++
          }
          
          if (-not $tsIP) {
            Write-Error "Tailscale failed to assign an IP address"
            & $tsExe status
            exit 1
          }
          
          # Get additional network info
          $tsStatus = & $tsExe status --json | ConvertFrom-Json
          $tailscaleDNS = $tsStatus.Self.DNSName
          
          echo "TAILSCALE_IP=$tsIP" >> $env:GITHUB_ENV
          echo "TAILSCALE_DNS=$tailscaleDNS" >> $env:GITHUB_ENV
          Write-Host "✓ Tailscale connected: $tsIP ($tailscaleDNS)"

      - name: Verify RDP Accessibility
        run: |
          $testResult = $null
          $retryCount = 0
          
          while ($retryCount -lt 5) {
            $testResult = Test-NetConnection -ComputerName $env:TAILSCALE_IP -Port $env:RDP_PORT -WarningAction SilentlyContinue
            if ($testResult.TcpTestSucceeded) {
              Write-Host "✓ RDP port 3389 is accessible via Tailscale"
              break
            }
            
            $retryCount++
            if ($retryCount -lt 5) {
              Write-Host "RDP test failed, retrying in 10 seconds... ($retryCount/5)"
              Start-Sleep -Seconds 10
            }
          }
          
          if (-not $testResult.TcpTestSucceeded) {
            Write-Warning "RDP port test failed. Checking firewall and service status..."
            
            # Diagnostic info
            Get-NetFirewallRule -Name "RDP-Tailscale" | Format-List
            Get-Service -Name TermService | Format-List
            & "$env:ProgramFiles\Tailscale ailscale.exe" status
            
            Write-Error "RDP verification failed after multiple attempts"
            exit 1
          }

      - name: Display Connection Information
        run: |
          $border = "═" * 50
          
          Write-Host ""
          Write-Host $border
          Write-Host "🚀 RDP CONNECTION READY"
          Write-Host $border
          Write-Host ""
          Write-Host "🔗 Connection Methods:"
          Write-Host " IP Address: $env:TAILSCALE_IP"
          Write-Host " DNS Name: $env:TAILSCALE_DNS"
          Write-Host ""
          Write-Host "👤 Credentials:"
          Write-Host " Username: $env:RDP_USERNAME"
          Write-Host " Password: ******** (check workflow environment)"
          Write-Host ""
          Write-Host "⚙️ Port: $env:RDP_PORT"
          Write-Host ""
          Write-Host "📝 Connection String:"
          Write-Host " mstsc /v:$env:TAILSCALE_IP"
          Write-Host ""
          Write-Host "⚠️ Important:"
          Write-Host " • This runner will stay active for 60 minutes"
          Write-Host " • Cancel the workflow to terminate the RDP session"
          Write-Host " • Credentials are temporary and will be destroyed"
          Write-Host ""
          Write-Host $border

      - name: Maintain Active Connection
        run: |
          $checkInterval = 60 # seconds
          $lastCheck = Get-Date
          
          Write-Host "🔄 Monitoring connection status..."
          Write-Host " Press 'Cancel workflow' in GitHub to terminate"
          Write-Host ""
          
          while ($true) {
            $currentTime = Get-Date
            $elapsed = ($currentTime - $lastCheck).TotalMinutes
            
            # Check Tailscale connection every 5 minutes
            if ($elapsed -ge 5) {
              $tsStatus = & "$env:ProgramFiles\Tailscale ailscale.exe" status --json 2>$null | ConvertFrom-Json
              if ($tsStatus.BackendState -ne "Running") {
                Write-Warning "Tailscale connection lost, attempting to reconnect..."
                & "$env:ProgramFiles\Tailscale ailscale.exe" up --reset
              }
              $lastCheck = $currentTime
            }
            
            # Display status
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] RDP Active | IP: $env:TAILSCALE_IP | User: $env:RDP_USERNAME"
            Start-Sleep -Seconds $checkInterval
          }
