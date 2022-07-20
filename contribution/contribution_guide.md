# Contribution Guide

KubeArmor maintainers welcome individuals and organizations from across the cloud security landscape (creators and implementers alike) to make contributions to the project. We equally value the addition of technical contributions and enhancements of documentation that helps us grow the community and strengthen the value of KubeArmor. We invite members of the community to contribute to the project!

To make a contribution, please follow the steps below.


1. Fork this repository \(KubeArmor\)

   First, fork this repository by clicking on the Fork button \(top right\).

   ![fork button](../.gitbook/assets/fork_button.png)  

   Then, click your ID on the pop-up screen.

   ![fork screen](../.gitbook/assets/fork_screen.png)  

   This will create a copy of KubeArmor in your account.

   ![fork repo](../.gitbook/assets/forked_repo.png)  

2. Clone the repository

   Now clone Kubearmor locally into your dev environment.

   ```text
    $ git clone https://github.com/[your GitHub ID]/KubeArmor
   ```

   This will clone a copy of Kubearmor installed in your dev environment.

3. Make changes

   First, go into the repository directory and make some changes.

   Please refer to [development guide](development_guide.md) to set up your environment for KubeArmor contribution.  

4. Check the changes

   Please run "test_kubearmor.sh" before committing the changes

   ```text
   cd KubeArmor/KubeArmor/build
   ~/KubeArmor/KubeArmor/build$ ./test_kubearmor.sh
   ```

   If you see any warnings or errors, please fix them first.

5. Commit changes

   Please see your changes using "git status" and add them to the branch using "git add".

   ```text
    $ cd KubeArmor
    ~/KubeArmor$ git status
    ~/KubeArmor$ git add [changed file]
   ```

   Then, commit the changes using the "git commit" command.

   ```text
    ~/KubeArmor$ git commit -s -m "Add a new feature by [your name]"
   ```

   Please make sure that your changes are properly tested on your machine.  

6. Push changes to your forked repository

   Push your changes using the "git push" command.

   ```text
    ~/KubeArmor$ git push
   ```

7. Create a pull request with your changes with the following steps

   First, go to your repository on GitHub.

   ![commit ahead](../.gitbook/assets/commit_ahead.png)  

   Then, click "Pull request" button.

   ![after pull request](../.gitbook/assets/after_pull_request.png)  

   After checking your changes, click 'Create pull request'.

   ![open pull request](../.gitbook/assets/open_pull_request.png)  

   A pull request should contain the details of all commits as specific as possible, including "Fixes: \#\(issue number\)".  

   Finally, click the "Create pull request" button.

   The changes would be merged post a review by the respective module owners. Once the changes are merged, you will get a notification, and the corresponding issue will be closed.

8. DCO Signoffs

   To ensure that contributors are only submitting work that they have rights to, we are requiring everyone to acknowledge this by signing their work. Any copyright notices in this repo should specify the authors as "KubeArmor authors".

   To sign your work, just add a line like this at the end of your commit message:

   ```
   Signed-off-by: FirstName LastName <email@address.com>
   ```

   This can easily be done with the `-s` or `--signoff` option to `git commit`.

   By doing this, you state that the source code being submitted originated from you (see https://developercertificate.org).
