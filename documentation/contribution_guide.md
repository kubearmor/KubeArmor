# Contribution Guide

If you are interested in this project and want to make a contribution, please follow the steps below.

1. Fork this repository (KubeArmor)

    Fork this repository by clicking on the Fork button (top right). This will create a copy of this repository in your account.

2. Clone the repository

    Now, it is time to get the code in your machine. In your machine, please run the following command.

    ```
    $ git clone https://github.com/[your GitHub ID]/KubeArmor
    ```

    Then, you will get the full code of KubeArmor.

3. Create a branch

    First, go into the repository directory.

    ```
    $ cd KubeArmor
    ```

    Then, please create a branch using the "git checkout" command.

    ```
    (KubeArmor) $ git checkout -b [your branch name]
    ```

    For example:

    ```
    (KubeArmor) $ git checkout -b "add_a_new_feature"
    ```

    It would be good to have the specific purpose of your contribution in the branch name.

4. Make changes and commit the changes

    First, go into the repository directory and make some changes.

    Please refer to the development guide to set up your environment for KubeArmor contribution.

    Then, please see your changes and add them to the branch.

    ```
    $ cd KubeArmor
    (KubeArmor) $ git status
    (KubeArmor) $ git add [changed file]
    ```

    Now, commit the changes using the "git commit" command.

    ```
    (KubeArmor) $ git commit -m "Add a new feature by [your name]"
    ```

    Please make sure that your changes are properly tested in your machine.

5. Push changes to your forked repository

    Push your changes using the "git push" command.

    ```
    (KubeArmor) $ git push origin [your branch name]
    ```

6. Submit your changes for review

    If you go to your repository on GitHub, you can see the "Compare & pull request" button. Click on that button.

    Now, you see the "Open a pull request" screen. Please fill a title and a comment as specific as possible. You need to make sure that you include an issue number in the comment if you fix a certain issue.

    Finally, click the "Create pull request" button.

    Now, please let us review your code. We will merge all your changes into the master branch of KubeArmor. Once your changes have been merged, you will get a notification.
