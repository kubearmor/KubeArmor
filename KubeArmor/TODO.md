# Task List

- Security Policy Specification

    - 'fromSource' option
    
        \- Complete implementing this option using AppArmor's subprofiles

- Feature Extension

    - Indirect syscall restriction -> system-wide operations
    
        \- Develop system-wide operations from capabilities  
        \- Update 'supported_operation_list.md'
        
    - Resource restriction
    
        \- Develop policy specs based on rlimit features
        
    - PodPreset
    
        \- Currently need to add AppArmor annotations manually to use KubeArmor  
        \- See if we can use this to add AppArmor annotations into pod definitions

- Documentation

    - In documentation

        \- Update 'linux_security_modules.md'  
        \- Update 'comparison_with_existing_solutions.md'  
        \- Update 'integration_with_network_security_solutions.md'  

    - In KubeArmor

        \- Update comments in code to generate goDocs automatically

- Unittest

    - Add unittest functions in each module

- KRSI Implementation

    - Design and implementation of KRSI-based security policy enforcer
