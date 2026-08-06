# kawin

## Build

### Prerequisites

- windows 10 or 11
- visual studio (recent version, min: 10.0.40219.1)
- [Windows Driver Kit](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

### Open & Build Proj in Visual Studio

- open the project folder in visual studio
- open  [solution file](./kubearmor.sln) in this folder.
- build the solution (`Build -> Build Solution`)
- the result should output the `.sys` and `.inf` file in `x64/Debug`.

### Install driver
- install the driver by right click the `.inf` file and click on install.

### Load and Run the driver
- open command prompt as Administrator
- check if driver got installed
    ```
    sc query kubearmor
    ```
- configure the driver to disable on boot
    ```
    sc config kubearmor start= demand
    ```
- start the driver
    ```
    sc start kubearmor
    ```