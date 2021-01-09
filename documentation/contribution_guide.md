# Contribution Guide

If you want to make a contribution, please follow the steps below.

1. Fork this repository (KubeArmor)

    First, fork this repository by clicking on the Fork button (top right).
    
    <center><img src=resources/images/fork_button.png></center>
    
    Then, click your ID on the pop-up screen.
    
    <center><img src=resources/images/fork_screen.png></center>

    This will create a copy of KubeArmor in your account.

    <center><img src=resources/images/forked_repo.png></center>

2. Clone the repository

    Now, it is time to get the code in your machine. In your machine, please run the following command.

    ```
    $ git clone https://github.com/[your GitHub ID]/KubeArmor
    ```

    Then, you will get the full code of KubeArmor in your machine.

3. Make changes

    First, go into the repository directory and make some changes.

    Please refer to [development guide](./development_guide.md) to set up your environment for KubeArmor contribution.

4. Commit the changes

    Please see your changes using "git status" and add them to the branch using "git add".

    ```
    $ cd KubeArmor
    (KubeArmor) $ git status
    (KubeArmor) $ git add [changed file]
    ```

    Then, commit the changes using the "git commit" command.

    ```
    (KubeArmor) $ git commit -m "Add a new feature by [your name]"
    ```

    Please make sure that your changes are properly tested in your machine.

5. Push changes to your forked repository

    Push your changes using the "git push" command.

    ```
    (KubeArmor) $ git push
    ```

6. Create a pull request with your changes

    First, go to your repository on GitHub. You will see something like the below screen.

    <center><img src=resources/images/commit_ahead.png></center>

    Then, please click "Pull request" button. You will see a screen like the below.

    <center><img src=resources/images/after_pull_request.png></center>

    After checking your changes, please click 'Create pull request'.

    <center><img src=resources/images/open_pull_request.png></center>

    As shown in the upper screenshot, a pull request should contain the details of all commits as specific as possible. Also, please make sure that you have "Fixes: #(issue number)".

    Finally, click the "Create pull request" button.

    Now, please let us review your code. We will merge all your changes into the master branch of KubeArmor. Once your changes are merged, you will get a notification, and the issue that you fixed will be closed as well.
