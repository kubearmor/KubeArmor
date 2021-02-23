# Contribution Guide

If you want to make a contribution, please follow the steps below.

1. Fork this repository \(KubeArmor\)

   First, fork this repository by clicking on the Fork button \(top right\).

![Alt text](../resources/images/fork_button.png)

   Then, click your ID on the pop-up screen.

![Alt text](../resources/images/fork_screen.png)

   This will create a copy of KubeArmor in your account.

![Alt text](../resources/images/forked_repo.png)

2. Clone the repository

   Now, it is time to get the code in your machine. In your machine, please run the following command.

   ```text
    $ git clone https://github.com/[your GitHub ID]/KubeArmor
   ```

   Then, you will get the full code of KubeArmor in your machine.

3. Make changes

   First, go into the repository directory and make some changes.

   Please refer to [development guide](development_guide.md) to set up your environment for KubeArmor contribution.

4. Commit the changes

   Please see your changes using "git status" and add them to the branch using "git add".

   ```text
    $ cd KubeArmor
    (KubeArmor) $ git status
    (KubeArmor) $ git add [changed file]
   ```

   Then, commit the changes using the "git commit" command.

   ```text
    (KubeArmor) $ git commit -m "Add a new feature by [your name]"
   ```

   Please make sure that your changes are properly tested in your machine.

5. Push changes to your forked repository

   Push your changes using the "git push" command.

   ```text
    (KubeArmor) $ git push
   ```

6. Create a pull request with your changes

   First, go to your repository on GitHub.

![Alt text](../resources/images/commit_ahead.png)

   Then, click "Pull request" button.

![Alt text](../resources/images/after_pull_request.png)

   After checking your changes, click 'Create pull request'.

![Alt text](../resources/images/open_pull_request.png)

   A pull request should contain the details of all commits as specific as possible. Also, please make sure that you have "Fixes: \#\(issue number\)".

   Finally, click the "Create pull request" button.

   The changes would be merged post a review by the respective module owners. Once the changes are merged, you will get a notification, and the corresponding issue will be closed.
