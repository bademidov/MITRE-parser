
$detection_results_xlsx = './2021_Results_Detection.xlsx'
$protection_results_xlsx = './2021_Results_Protection.xlsx'
#$conf_changes_xlsx = './2021_Config_Changes_Summary.xlsx'
$files = Get-ChildItem -Filter "*.json"
$summary_results = @()
$summary_results_protection = @()
$conf_changes_summary =@()
Remove-Item -Path $detection_results_xlsx -Force -ErrorAction SilentlyContinue
Remove-Item -Path $protection_results_xlsx -Force -ErrorAction SilentlyContinue
Remove-Item -Path $conf_changes_xlsx -ErrorAction SilentlyContinue

foreach ($file in $files) {
    $wkst_detection = @()
    $wkst_protection = @()
    $analytic_discount = 0
    $visibility_discount = 0
    $technique_discount = 0
    $config_changes1 = 0
    $config_changes2 = 0
    $json = Get-Content $file -Raw | ConvertFrom-Json
    $vendor_name = $file.name.split("_")[0]
    Write-Host " "
    Write-Host " "
    Write-Host " "
    Write-Host "----------------------------------" -ForegroundColor Green
    Write-Host "Parsing $vendor_name..." -ForegroundColor Green
    Write-Host "----------------------------------" -ForegroundColor Green
    $summary = $json.adversaries.Aggregate_Data.aggregates

    # Calculate summary results
    $day1 = $json.adversaries.detections_by_step.Scenario_1.Steps.Substeps.Detections.Detection_Type | Where-Object {$_ -ne "N/A"}
    $day2 = $json.adversaries.detections_by_step.Scenario_2.Steps.Substeps.Detections.Detection_Type | Where-Object {$_ -ne "N/A"}
    #$total_steps = $day1.count + $day2.count
    
    #if ($total_steps -eq 10) { $Linux = "Yes" } else { $Linux = "No"}
    if ($json.adversaries.participant_capabilities -contains "Linux Capability") { $Linux = "Yes" } else { $Linux = "No" }
    #if ($Linux = "yes") { $total_steps = 109 } else { $total_steps = 90 }

    $total_steps = $summary.Total_Substeps
    #$config_changes1 = ($json.adversaries.detections_by_step.scenario_1.steps.substeps.detections  | Where-object {$_.detection_type -ne "None" -or $_.detection_type -ne "N/A"}).Modifiers.count
    #$config_changes2 = ($json.adversaries.detections_by_step.scenario_2.steps.substeps.detections  | Where-object {$_.detection_type -ne "None" -or $_.detection_type -ne "N/A"}).Modifiers.count

    $json.adversaries.detections_by_step.scenario_1.steps.substeps | foreach-object {
        if ($_.detections.modifiers -gt 0) {
            $config_changes1 +=1
        }
    }
    $json.adversaries.detections_by_step.scenario_2.steps.substeps | foreach-object {
        if ($_.detections.modifiers -gt 0) {
            $config_changes1 +=1
        }
    }
    $config_changes_total = $config_changes1 + $config_changes2
    $detection_logic_changed = ($json.adversaries.detections_by_step.scenario_1.steps.substeps.detections.modifiers | where-object {$_ -eq "Configuration Change (Detection Logic)" }).count
    $config_changes_ux = ($json.adversaries.detections_by_step.scenario_1.steps.substeps.detections.modifiers | where-object {$_ -eq "Configuration Change (UX)" }).count
    $delayed = ($json.adversaries.detections_by_step.scenario_1.steps.substeps.detections.modifiers | where-object {$_ -eq "delayed"}).count
    $data_sources_changed = ($json.adversaries.detections_by_step.scenario_1.steps.substeps.detections.modifiers | where-object {$_ -eq "Configuration Change (Data Sources)"}).count

    # Parse detection test results
    $days = @("Scenario_1", "Scenario_2")
    foreach ($day in $days) {
        $scenario = $json.adversaries.detections_by_step.$day
        #write-output $scenario.Steps
        foreach ($step in $scenario.Steps) {
            #write-output $step.Substeps
            foreach ($substep in $step.Substeps) {

                if ($null -eq $substep.Subtechnique.Subtechnique_ID) {
                    $Subtechnique = ""
                    $Subtechnique_ID = ""
                } else {
                    $Subtechnique_ID = $substep.Subtechnique.Subtechnique_ID
                    $Subtechnique = $substep.Subtechnique.Subtechnique_Name
                }

                if ($substep.Detections.count -eq 1) {
                    #write-host $substep.Detections.Detection_Type -ForegroundColor Green
                    if ($substep.Detections.Detection_Type -ne "None" -And $substep.Detections.Detection_Type -ne "N/A") {
                        if ($substep.Detections.Modifiers.count -eq 1) {
                            switch ($substep.Detections.Modifiers) {
                                "Delayed" { 
                                    write-host " "
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                    write-host "Delayed detection. Discounting Visibility." -ForegroundColor Red
                                    $visibility_discount +=1 
                                }
                                "Configuration Change (Data Sources)" { 
                                    write-host " " 
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                    write-host "Configuration Change (Data Sources). Discounting Visibility" -ForegroundColor Red 
                                    $visibility_discount +=1 
                                }
                                "Configuration Change (Detection Logic)" {
                                    if ($substep.Detections.Detection_Type -eq "Technique") {
                                        write-host " "
                                        write-host " "
                                        write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change (Detection Logic) found. Discounting Analytic Coverage" -ForegroundColor Yellow
                                        $analytic_discount +=1
                                    } elseif ($substep.Detections.Detection_Type -eq "Telemetry") {
                                        write-host " "
                                        write-host " "
                                        write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change (Detection Logic) found. Discounting Visibility" -ForegroundColor Red
                                        $visibility_discount +=1
                                    }
                                }
                                "Configuration Change (UX)" { 
                                    write-host " "
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                    write-host "Configuration Change (UX). Discounting Visibility" -ForegroundColor Red
                                    $visibility_discount +=1
                                }
                                "Configuration Change" {
                                    if ($substep.Detections.Detection_Type -eq "Technique") {
                                        write-host " "
                                        write-host " "
                                        write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan 
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change found. Discounting Analytic Coverage" -ForegroundColor Yellow
                                        $analytic_discount +=1
                                    } elseif ($substep.Detections.Detection_Type -eq "Telemetry") {
                                        write-host " "
                                        write-host " "
                                        write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan 
                                        Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                        write-host "Configuration Change found. Discounting Visibility" -ForegroundColor Red
                                        $visibility_discount +=1
                                    }
                                }
                                "N/A" { 
                                    write-host " "
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    write-host "Detection: N/A" }
                                Default {}
                            }
                        }
                        elseif ($substep.Detections.Modifiers.count -gt 1){
                            if ("Technique","General","Tactic" -contains $substep.Detections.Detection_Type) {
                                if ($substep.Detections.Modifiers -contains "Configuration Change (Data Sources)") {
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
                                write-host "This Telemetry detection has a config change. Discounting Visibility" -ForegroundColor Red
                                $visibility_discount +=1
                            }
                            else {
                                Write-Host "ERROR: Couldn't identify type of the detection" -ForegroundColor Red
                            }
                            # It means there is only one detection with multiple Modifiers
                            switch ($substep.Detections.Detection_Type) {
                                "Technique" { 
                                    write-host " "
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                    write-host "Multiple configuration changes resulted to Technique detection. Discounting Analytic Coverage" -ForegroundColor Yellow
                                    $analytic_discount +=1
                                }
                                "Telemetry" { 
                                    write-host " "
                                    write-host " "
                                    write-host "$vendor_name - Substep $($substep.Substep):" -ForegroundColor Cyan
                                    Write-Output $substep.Detections | Select-Object Detection_Type, Modifiers | ft
                                    write-host "Multiple configuration changes resulted to Telemetry detection. Discounting Visibility" -ForegroundColor Red
                                    $visibility_discount +=1
                                }
                                Default {}
                            }
                        }
                    }
                }

                if ($substep.Detections.count -gt 1) {
                    write-host " "
                    write-host " "
                    write-host "$vendor_name - Substep $($substep.Substep). Found $($substep.Detections.count) detections:" -ForegroundColor Cyan
                    Write-output $substep.Detections | Select-Object Detection_Type, Modifiers | ft

                    # What was the original detection without modifiers?
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
                            write-host "Discounting Technique Coverage (no changes to Analytic or Visibility score)"
                            $technique_discount +=1
                        } 
                        "Tactic" {
                            write-host " "
                            write-host "Discounting Technique Coverage (no changes to Analytic or Visibility score)"
                            $technique_discount +=1
                        }
                        "Telemetry" {
                            write-host " "
                            write-host "Discounting Analytic" -ForegroundColor Yellow
                            $analytic_discount +=1 
                        }
                        "None" { 
                            write-host " "
                            write-host "Discounting Visibility" -ForegroundColor Red 
                            $visibility_discount +=1 
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
                                write-host "Discounting Visibility because there is no Telemetry detection found without a config change." -ForegroundColor Red
                                $visibility_discount +=1 
                            }
                        }
                    }

                    if ($substep.Detections.count -gt 3) {
                        write-host "ERROR: Too many detections. Cannot process."
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
        }
    }

    # Parse detection summary results
    $result = [PSCustomObject]@{
        Vendor = $vendor_name
        Analytic_Coverage_Percentage = $summary.Analytic_Coverage.Split("/")[0] / $total_steps
        Visibility_Percentage = $summary.Visibility.Split("/")[0] / $total_steps
        Analytic_Coverage = $summary.Analytic_Coverage
        Visibility_Coverage = $summary.Visibility
        Telemetry_Coverage = $summary.Telemetry_Coverage
        Analytic = $summary.Analytic_Coverage.Split("/")[0]
        Visibility = $summary.Visibility.Split("/")[0]
        Total_Steps = $total_steps
        Linux = $Linux
        Analytic_To_Deduct = $analytic_discount
        Analytic_Without_CCs = $summary.Analytic_Coverage.Split("/")[0] - $analytic_discount
        Visibility_To_Deduct = $visibility_discount
        Visibility_Without_CCs = $summary.Visibility.Split("/")[0] - $visibility_discount
        New_Analytic = ($summary.Analytic_Coverage.Split("/")[0] - $analytic_discount) / $total_steps
        New_Visibility = ($summary.Visibility.Split("/")[0] - $visibility_discount) / $total_steps
        #Techniques_To_Deduct  = $technique_discount
        Config_Changes_Total = $config_changes_total
        #Detection_Logic_Changes = $detection_logic_changed
        #Data_Sources_Changes = $data_sources_changed
        #UX_Changes = $config_changes_ux
        #Delayed_Detections = $delayed
    }

    $summary_results += $result

    Write-host " "
    Write-host "----------------------------------------" -ForegroundColor Green
    Write-Host "$vendor_name config changes summary" -ForegroundColor Green
    Write-host "----------------------------------------" -ForegroundColor Green
    Write-host "Analytic steps to deduct: " $analytic_discount -ForegroundColor Yellow
    Write-host "Visibility steps to deduct: " $visibility_discount -ForegroundColor Red
    Write-host "Technique steps to deduct (experimental): " $technique_discount -ForegroundColor DarkCyan
    $conf_changes_vendor = [PSCustomObject]@{
        Vendor = $vendor_name
        Analytic_To_Deduct = $analytic_discount
        Visibility_To_Deduct = $visibility_discount
        #Technique_To_Deduct = $technique_discount
    }
    $conf_changes_summary += $conf_changes_vendor

    $wkst_detection | Export-Excel -Path $detection_results_xlsx -AutoSize -TableName $vendor_name -WorksheetName $vendor_name -FreezeTopRowFirstColumn

    # Parse protection test results
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
    if ($Linux -eq "Yes") { $total_steps = 9 } else { $total_steps = 8}
    $blocked_steps = $wkst_protection.Protection_Type.count
    $results_protection = [PSCustomObject]@{
        Vendor = $vendor_name
        Score = $blocked_steps / $total_steps
        Blocked_Steps = $blocked_steps
        Total_Steps = $total_steps
        Linux = $Linux
    }

    $summary_results_protection += $results_protection
}

#$summary_results | Export-Csv 2021_results.csv -NoTypeInformation
$summary_results | Export-Excel -Path $detection_results_xlsx -AutoSize -TableName Summary -WorksheetName "Summary"
$summary_results_protection | Export-Excel -Path $protection_results_xlsx -AutoSize -TableName Summary -WorksheetName "Summary"
#$conf_changes_summary | Export-Excel -Path $conf_changes_xlsx -AutoSize -TableName Summary -WorksheetName "Summary"

Write-Output $summary_results | Format-Table
Write-Output $conf_changes_summary | Format-Table

#$summary_results_protection | Export-Csv 2021_results_detection.csv -NoTypeInformation