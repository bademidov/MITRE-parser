[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    $platform = @('windows', 'linux'),
    [switch]$includechanges,
    [switch]$protection
)

$version = "0.3"
$detection_results_xlsx = './2021_Detection_Detailed_Results_By_Vendor.xlsx'
$detection_results_summary_xlsx = './2021_Detection_Summary.xlsx'
$protection_results_xlsx = './2021_Protection_Detailed_Results_By_Vendor.xlsx'
$protection_results_summary_xlsx = './2021_Protection_Summary.xlsx'
$files = Get-ChildItem -Filter "./JSON/*.json"
$summary_results = @()
$summary_results_protection = @()
$conf_changes_summary =@()
Remove-Item -Path $detection_results_xlsx -Force -ErrorAction SilentlyContinue
Remove-Item -Path $detection_results_summary_xlsx -Force -ErrorAction SilentlyContinue
Remove-Item -Path $protection_results_xlsx -Force -ErrorAction SilentlyContinue
Remove-Item -Path $protection_results_summary_xlsx -Force -ErrorAction SilentlyContinue


# Validate platform parameter
$os_list = @()
if (-Not $platform) {
    $os_list = @("Windows", "Linux")
}
else {
    $os_list = $platform.Split(",")
    $os_list = $os_list | Where-Object {$_ -eq 'windows' -Or $_ -eq 'linux'}
    if (-Not $os_list) {
        write-host "Provided wrong platform type. Allowed values: Windows, Linux."
        exit
    }
}

foreach ($file in $files) {
    $wkst_detection = @()
    $wkst_protection = @()
    $analytic_steps = 0
    $visibility_steps = 0
    $technique_steps = 0
    $analytic_discount = 0
    $visibility_discount = 0
    $technique_discount = 0
    $delayed = 0
    $detection_logic_changes = 0
    $ux_changes = 0
    $config_changes_general = 0
    $data_sources_changes = 0
    $config_changes_total = 0
    $json = Get-Content $file.FullName -Raw | ConvertFrom-Json
    $vendor_name = $file.name.split("_")[0]
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "----------------------------------" -ForegroundColor Green
    Write-Host "Parsing $vendor_name..." -ForegroundColor Green
    Write-Host "----------------------------------" -ForegroundColor Green
    $summary = $json.adversaries.Aggregate_Data.aggregates
    if ($json.adversaries.participant_capabilities -contains "Linux Capability") { $Linux = "Yes" } else { $Linux = "No" }

    if (-Not $protection) {
        #
        # Parse detection test results
        #

        # Filter substeps based on the desired platform (Windows, Linux, or both)
        $total_substeps = 0
        $substeps = @()
        foreach ($day in @("Scenario_1", "Scenario_2")) {
            $scenario = $json.adversaries.detections_by_step.$day
            # Handle -platform switch
            if ("windows" -eq $os_list) {
                # Exclude Linux steps
                $substeps += $scenario.steps.substeps | Where-object {"Linux Capability" -ne $_.capability_requirements }
            }
            elseif ("linux" -eq $os_list) {
                # Exclude Windows steps
                $substeps += $scenario.steps.substeps | Where-object {"Linux Capability" -eq $_.capability_requirements }
            }
            else {
                $substeps += $scenario.steps.substeps
            }
        }

        $total_substeps = $substeps.count

        foreach ($substep in $substeps) {
            if ($null -eq $substep.Subtechnique.Subtechnique_ID) {
                $Subtechnique = ""
                $Subtechnique_ID = ""
            } else {
                $Subtechnique_ID = $substep.Subtechnique.Subtechnique_ID
                $Subtechnique = $substep.Subtechnique.Subtechnique_Name
            }

            # If only one detection per substep
            if ($substep.Detections.count -eq 1) {
                #write-host $substep.Detections.Detection_Type -ForegroundColor Green
                if ($substep.Detections.Detection_Type -ne "None" -And $substep.Detections.Detection_Type -ne "N/A") {
                    # Count visibility and analytic steps
                    if ("Technique","General","Tactic" -contains $substep.Detections.Detection_Type) {
                        $analytic_steps +=1
                        $visibility_steps +=1
                    } 
                    elseif ("Telemetry" -eq $substep.Detections.Detection_Type) {
                        $visibility_steps +=1
                    }

                    if ($includechanges) {
                        # Check for configuration changes
                        if ($substep.Detections.Modifiers.count -eq 1) {
                            write-host " "
                            write-host " "
                            write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                            if ("Technique","General","Tactic" -contains $substep.Detections.Detection_Type) {
                                switch ($substep.Detections.Modifiers) {
                                    "Delayed" { 
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Delayed detection. Discounting Visibility and Analytics" -ForegroundColor Yellow
                                        $visibility_discount +=1 
                                        $analytic_discount +=1
                                    }
                                    "Configuration Change (Data Sources)" { 
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change (Data Sources). Discounting Visibility and Analytics" -ForegroundColor Yellow 
                                        $visibility_discount +=1
                                        $analytic_discount +=1
                                    }
                                    "Configuration Change (Detection Logic)" {
                                        if ($substep.Detections.Detection_Type -eq "Technique") {
                                            Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                            write-host "Configuration Change (Detection Logic) found. Discounting Analytic Coverage" -ForegroundColor Yellow
                                            $analytic_discount +=1
                                        }
                                    }
                                    "Configuration Change (UX)" { 
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change (UX). Discounting Analytics" -ForegroundColor Yellow
                                        $visibility_discount +=1
                                    }
                                    "Configuration Change" { 
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change found. Discounting Analytic Coverage" -ForegroundColor Yellow
                                        $analytic_discount +=1
                                    }
                                    "N/A" { 
                                        write-host "Detection: N/A" }
                                    Default {}
                                }
                            }
                            elseif ("Telemetry" -contains $substep.Detections.Detection_Type) {
                                Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                write-host "This Telemetry detection has a config change. Discounting Visibility" -ForegroundColor Yellow 
                                $visibility_discount +=1
                            }
                        }
                        elseif ($substep.Detections.Modifiers.count -gt 1){
                            if ("Technique","General","Tactic" -contains $substep.Detections.Detection_Type) {
                                if ($substep.Detections.Modifiers -contains "Configuration Change (Data Sources)" -Or
                                    $substep.Detections.Modifiers -contains "Delayed") {
                                    write-host " "
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                    write-host "This detection is either Delayed or contains Configuration Change (Data Sources). Discounting both Analytic Coverage and Visibility" -ForegroundColor Yellow
                                    $analytic_discount +=1
                                    $visibility_discount +=1
                                }
                            }
                            elseif ("Telemetry" -contains $substep.Detections.Detection_Type) {
                                write-host " "
                                write-host " "
                                write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                write-host "This Telemetry detection has a config change. Discounting Visibility" -ForegroundColor Yellow
                                $visibility_discount +=1
                            }
                            else {
                                Write-Host "ERROR: Couldn't identify type of the detection" -ForegroundColor Red
                            }
                            # It means there is only one detection with multiple Modifiers
                            # switch ($substep.Detections.Detection_Type) {
                            #     "Technique" { 
                            #         write-host " "
                            #         write-host " "
                            #         write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                            #         Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                            #         write-host "Multiple configuration changes resulted to Technique detection. Discounting Analytic Coverage" -ForegroundColor Yellow
                            #         $analytic_discount +=1
                            #     }
                            #     "Telemetry" { 
                            #         write-host " "
                            #         write-host " "
                            #         write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                            #         Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                            #         write-host "Multiple configuration changes resulted to Telemetry detection. Discounting Visibility" -ForegroundColor Yellow
                            #         $visibility_discount +=1
                            #     }
                            #     Default {}
                            # }
                        }
                    }
                }
            }

            if ($substep.Detections.count -gt 1) {
                # Check for highest detection regardless of a config change
                if ($substep.Detections.Detection_Type -contains "Technique" -Or
                    $substep.Detections.Detection_Type -contains "General" -Or
                    $substep.Detections.Detection_Type -contains "Tactic") {
                        $visibility_steps +=1
                        $analytic_steps +=1
                    }
                elseif ($substep.Detections.Detection_Type -contains "Telemetry"){
                    $visibility_steps +=1
                }

                if ($includechanges) {
                    # Process config changes
                    # What was the original detection without modifiers?
                    write-host " "
                    write-host " "
                    write-host "$vendor_name - Substep $($substep.Substep). Found $($substep.Detections.count) detections:" -ForegroundColor Cyan
                    Write-output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
        
                    # If at least one detection has a config change
                    if ($substep.Detections.modifiers.count -ne 0) {
                        $original_detection = ($substep.Detections | where-object {$_.modifiers.count -eq 0}).Detection_Type
                        if ($null -ne $original_detection) {
                            write-host "The original detection was: $original_detection"
                        }
                        switch ($original_detection) {
                            "Technique" {
                                write-host " "
                                write-host "Verdict: No change"
                            } 
                            "General" {
                                write-host " "
                                write-host "Discounting Technique Coverage (no changes to Analytic or Visibility score)" -ForegroundColor Yellow
                                $technique_discount +=1
                            } 
                            "Tactic" {
                                write-host " "
                                write-host "Discounting Technique Coverage (no changes to Analytic or Visibility score)" -ForegroundColor Yellow
                                $technique_discount +=1
                            }
                            "Telemetry" {
                                write-host " "
                                write-host "Discounting Analytic" -ForegroundColor Yellow
                                $analytic_discount +=1 
                            }
                            "None" { 
                                write-host " "
                                write-host "Discounting Visibility" -ForegroundColor Yellow 
                                $visibility_discount +=1 
                                if ($substep.Detections.Detection_Type -contains "Technique" -or
                                    $substep.Detections.Detection_Type -contains "General" -or
                                    $substep.Detections.Detection_Type -contains "Tactic" ) {
                                    write-host " "
                                    write-host "Discounting also Analytic because the original detection was None" -ForegroundColor Yellow
                                    $analytic_discount +=1 
                                }
                            }
                            "N/A" {
                                write-host " "
                                write-host "Detection: N/A" 
                            }
                            Default {
                                write-host " "
                                write-host "All detections have configuration changes in this substep."
                                if ($substep.Detections.Detection_Type -contains "Technique" -or
                                    $substep.Detections.Detection_Type -contains "General" -or
                                    $substep.Detections.Detection_Type -contains "Tactic" ) {
                                    write-host " "
                                    write-host "Discounting Analytic because there is no Analytic detection found without a config change." -ForegroundColor Yellow
                                    $analytic_discount +=1 
                                }
                                if ($substep.Detections.Detection_Type -contains "Telemetry") {
                                    write-host "Discounting Visibility because there is no Telemetry detection found without a config change." -ForegroundColor Yellow
                                    $visibility_discount +=1 
                                }
                            }
                        }
                    }

                    if ($substep.Detections.count -gt 3) {
                        write-host "ERROR: Too many detections. Cannot process."
                    }
                }
            }

            $Detection = ($substep.Detections | Select-Object -ExpandProperty Detection_Type) -join ", "
            $Modifiers = ($substep.Detections | Select-Object -ExpandProperty Modifiers) -join ", "
            $row = [PSCustomObject]@{
                Substep = $substep.Substep
                #Step = $step.Step_Num
                #Step_Name = $step.Step_Name
                Criteria = $substep.Criteria
                Tactic = $substep.Tactic.Tactic_Name
                Technique_ID = $substep.Technique.Technique_ID
                Technique = $substep.Technique.Technique_Name
                Subtechnique_ID = $Subtechnique_ID
                Subtechnique = $Subtechnique
                Detection = $Detection
                Modifiers = $Modifiers
            }
            $wkst_detection += $row
        }

        #
        # Parse and calculate summary results
        #

        $total_substeps_summary = $summary.Total_Substeps

        foreach ($scenario in @("Scenario_1","Scenario_2")) {
            $json.adversaries.detections_by_step.$scenario.steps.substeps | foreach-object {
                if ($_.detections.Detection_Type -contains "Technique") {
                    $technique_steps +=1
                }
                if ($_.detections.modifiers -gt 0) {
                    $config_changes_total +=1
                }
                if ($_.detections.modifiers -contains "Delayed") {
                    $delayed +=1
                }
                if ($_.detections.modifiers -contains "Configuration Change (Detection Logic)") {
                    $detection_logic_changes +=1
                }
                if ($_.detections.modifiers -contains "Configuration Change (UX)") {
                    $ux_changes +=1
                }
                if ($_.detections.modifiers -contains "Configuration Change (Data Sources)") {
                    $data_sources_changes +=1
                }
                if ($_.detections.modifiers -contains "Configuration Change") {
                    $config_changes_general +=1
                }
            }
        }

        if ($os_list.count -eq 2 -and $Linux -eq "yes") {
            $total_substeps = 109
        }
        elseif ($os_list.count -eq 2 -and $Linux -eq "no") {
            $total_substeps = 90
        }
        elseif ($os_list -eq "Linux") {
            $total_substeps = 19
        }
        elseif ($os_list -eq "Windows") {
            $total_substeps = 90
        }

        # Calculate final scores 
        if ($includechanges) {
            $Analytic_Score = ($analytic_steps - $analytic_discount) / $total_substeps
            $Visibility_Score = ($visibility_steps - $visibility_discount) / $total_substeps
            $Technique_Score = ($technique_steps - $technique_discount) / $total_substeps
        } else {
            $Analytic_Score = $analytic_steps / $total_substeps
            $Visibility_Score = $visibility_steps / $total_substeps
            $Technique_Score = $technique_steps / $total_substeps
        }

        if ($includechanges) {
            $result = [PSCustomObject]@{
                Vendor = $vendor_name
                Analytic_Coverage_without_Config_Changes = $Analytic_Score
                Analytic_Steps_without_Config_Changes = $analytic_steps - $analytic_discount
                Analytic_Steps_with_Config_Changes = $analytic_steps
                Analytic_Coverage_with_Config_Changes = $analytic_steps / $total_substeps
                Config_Changes_Impact_to_Analytic = $analytic_discount
                Visibility_without_Config_Changes = $Visibility_Score
                Visibility_Steps_without_Config_Changes = $visibility_steps - $visibility_discount
                Visibility_Steps_with_Config_Changes = $visibility_steps
                Visibility_with_Config_Changes = $visibility_steps / $total_substeps
                Config_Changes_Impact_to_Visibility = $visibility_discount
                Technique_Coverage_without_Config_Changes = $Technique_Score
                Technique_Steps_without_Config_Changes = $technique_steps - $technique_discount
                Technique_Steps_with_Config_Changes = $technique_steps
                Techniques_Coverage_with_Config_Changes  = $technique_steps / $total_substeps
                Config_Changes_Impact_to_Technique_Coverage = $technique_discount
                #Analytic_Coverage_Percentage = $summary.Analytic_Coverage.Split("/")[0] / $total_substeps_summary
                #Visibility_Percentage = $summary.Visibility.Split("/")[0] / $total_substeps_summary
                #Analytic_Coverage = $summary.Analytic_Coverage
                #Visibility_Coverage = $summary.Visibility
                #Telemetry_Coverage = $summary.Telemetry_Coverage
                #Analytic = $summary.Analytic_Coverage.Split("/")[0]
                #Visibility = $summary.Visibility.Split("/")[0]
                #Total_Steps_Summary = $total_substeps_summary
                Total_Steps = $total_substeps
                Linux = $Linux
                Config_Changes_Delayed_Detections = $delayed
                Config_Changes_Data_Sources = $data_sources_changes
                Config_Changes_Detection_Logic = $detection_logic_changes
                Config_Changes_General = $config_changes_general
                Config_Changes_UX = $ux_changes
                Config_Changes_Total = $config_changes_total
            }
        }
        else {
            $result = [PSCustomObject]@{
                Vendor = $vendor_name
                Analytic_Score = $Analytic_Score
                #Original_Analytic_Score = $summary.Analytic_Coverage.Split("/")[0] / $total_substeps_summary
                Analytic_Steps = $analytic_steps
                Visibility_Score = $Visibility_Score
                #Original_Visibility_Score = $summary.Visibility.Split("/")[0] / $total_substeps_summary
                Visibility_Steps = $visibility_steps
                #Analytic_Coverage = $summary.Analytic_Coverage
                #Visibility_Coverage = $summary.Visibility
                Total_Steps = $total_substeps
                Linux = $Linux
            }
        }

        $summary_results += $result
        $wkst_detection | Export-Excel -Path $detection_results_xlsx -AutoSize -TableName $vendor_name -WorksheetName $vendor_name -FreezeTopRowFirstColumn

        if ($includechanges) {
            Write-host " "
            Write-host "----------------------------------------" -ForegroundColor Green
            Write-Host "$vendor_name config changes summary" -ForegroundColor Green
            Write-host "----------------------------------------" -ForegroundColor Green
            Write-host "Analytic steps to deduct: " $analytic_discount -ForegroundColor Yellow
            Write-host "Visibility steps to deduct: " $visibility_discount -ForegroundColor Yellow
            Write-host "Technique steps to deduct (experimental): " $technique_discount -ForegroundColor Cyan
            $conf_changes_vendor = [PSCustomObject]@{
                Vendor = $vendor_name
                Analytic_To_Deduct = $analytic_discount
                Visibility_To_Deduct = $visibility_discount
                Technique_To_Deduct = $technique_discount
            }
            $conf_changes_summary += $conf_changes_vendor
        }
    }

    if (-Not $protection) { continue }
    #
    # Parse protection test results
    #
    $tests = $json.adversaries.protections.protection_tests
    #write-output $scenario.Steps
    foreach ($test in $tests) {
        foreach ($substep in $test.Substeps) {
            if ($substep.Protection_Type -eq "Blocked") {
                $row = [PSCustomObject]@{
                    Substep = $substep.Substep
                    Test = $test.Test_Num
                    Test_Name = $test.Test_Name
                    Criteria = $substep.Criteria
                    Tactic = $substep.Tactic.Tactic_Name
                    Technique_ID = $substep.Technique.Technique_ID
                    Technique = $substep.Technique.Technique_Name
                    Subtechnique_ID = $Subtechnique_ID
                    Subtechnique = $Subtechnique
                    Protection_Type = $substep.Protection_Type
                    Modifiers = $substep.Detections.Modifiers
                }
                $wkst_protection += $row
            }
        }
    }
    $wkst_protection | Export-Excel -Path $protection_results_xlsx -AutoSize -TableName $vendor_name -WorksheetName $vendor_name -FreezeTopRowFirstColumn


    # Summary protection results
    if ($Linux -eq "Yes") { $total_steps_protection = 9 } else { $total_steps_protection = 8}
    $blocked_steps = $wkst_protection.Protection_Type.count
    $results_protection = [PSCustomObject]@{
        Vendor = $vendor_name
        Score = $blocked_steps / $total_steps_protection
        Blocked_Steps = $blocked_steps
        Total_Steps = $total_steps_protection
        Linux = $Linux
    }

    $summary_results_protection += $results_protection
}

#$summary_results | Export-Csv 2021_results.csv -NoTypeInformation
$summary_results | Export-Excel -Path $detection_results_summary_xlsx -AutoSize -TableName Summary -WorksheetName "Summary" -FreezeTopRowFirstColumn -BoldTopRow
if ($protection) {
    $summary_results_protection | Export-Excel -Path $protection_results_summary_xlsx -AutoSize -TableName Summary -WorksheetName "Summary"
}

Write-Host "----------------------------------------------DONE----------------------------------------------" -ForegroundColor Green
if (-Not $protection) {
    if (Test-Path -path $detection_results_summary_xlsx) { write-host "Summary detection test results saved to $detection_results_summary_xlsx" -ForegroundColor Cyan } 
    else { write-host "Failed to export summary detection test results to $detection_results_summary_xlsx" -ForegroundColor Red}
    if (Test-Path -path $detection_results_xlsx) { write-host "Detaled detection test results saved to $detection_results_xlsx" -ForegroundColor Cyan } 
    else { write-host "Failed to export the detection test results to $detection_results_xlsx" -ForegroundColor Red }    
}

if ($protection) {
    if (Test-Path -path $protection_results_summary_xlsx) { write-host "Summary protection test results saved to $protection_results_summary_xlsx" -ForegroundColor Cyan }
    else { write-host "Failed to export summary protection test results to $protection_results_summary_xlsx" -ForegroundColor Red}
    if (Test-Path -path $protection_results_xlsx) { write-host "Protection test results saved to $protection_results_xlsx" -ForegroundColor Cyan }
    else { write-host "Failed to export the protection test results to $protection_results_xlsx" -ForegroundColor Red}
}
Write-Host "------------------------------------------------------------------------------------------------" -ForegroundColor Green


#$summary_results_protection | Export-Csv 2021_results_detection.csv -NoTypeInformation