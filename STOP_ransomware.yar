 rule STOP_ransomware
{
    meta:
        description = "Detects Unpacked STOP Ransomware Samples"
        author = "Glyc3rius"
        date_created = "11/02/2024"
        sha256 = "236259fb27568c5b6ba0ed090909d2f1aeb70258673f3b561514350a65eba77a"
    strings:
         $s_launch_arg1 = "--Admin" wide
         $s_launch_arg2 = "IsNotAutoStart" wide
         $s_launch_arg3 = "IsNotTask" wide
         $s_launch_arg4 = "--AutoStart" wide 
         $s_launch_arg5 = "IsAutoStart" wide
         $s_launch_arg6 = "IsTask" wide
         $s_launch_arg7 = "--ForNetRes" wide
         $s_launch_arg8 = "--Task" wide
         $s_launch_arg9 = "--Service" wide

         $s_pdb = "encrypt_win_api.pdb"         
         $s_jpg = "5d2860c89d774.jpg" wide
         $s_scheduled_task = "Time Trigger Task" wide

         $mutex_1 = "{1D6FC66E-D1F3-422C-8A53-C0BBCF3D900D}"
         $mutex_2 = "{FBB4BCC6-05C7-4ADD-B67B-A98A697323C1}"
         $m_end_of_encrypted_file = "{36A698B9-D67C-4E07-BE82-0EC5B14B4DF5}"
        
   condition:
         uint16(0) == 0x5a4d
         and all of ($s*) 
         and (any of ($m*))
}

