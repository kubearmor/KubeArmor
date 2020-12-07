# Task List

- Feature Extension

    - Indirect syscall restriction -> system-wide operations
    
        \- Develop system-wide operations from capabilities  
        \- Update 'supported_operation_list.md'
        
    - Resource restriction
    
        \- Develop policy specs based on rlimit features
        
    - Fine-grained network access control
    
        \- Restrict network-related system calls  
        \- Provide security policy enfrocement at the IP/port level

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
