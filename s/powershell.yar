rule powershell_artifacts
{   
     meta:
           Description = "Look for suspect powershell artificats."
           filetype = "MemoryDump"         
           Author = "Greg Carson"
           Date = "09-09-2015"
    
     strings:
           $s0 = "Invoke-" ascii
           $s1 = "-Enc" ascii

     condition:
           2 of them
}
