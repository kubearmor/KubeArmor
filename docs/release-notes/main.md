Release Title: fix missing labels

### Bug Fixes
- Added mapping for pod labels in the system monitor to ensure labels are correctly tracked and resolve missing label issues.
- Introduced locking mechanisms for owner information and container data to guarantee thread-safe access.

### Performance Improvements
- Refactored locking strategies to more reliably handle race conditions, especially around container map access.
- Added locks in the feeder enforcer to ensure thread-safe updates of enforcer types and retrieval of node information.