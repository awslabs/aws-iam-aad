This code provides automated integration between AWS and Azure for SAML federation between Azure AD and multiple AWS accounts. You can read a detailed explanation about what it does and how it works in following  AWS blog post:

https://aws.amazon.com/blogs/security/how-to-automate-saml-federation-to-multiple-aws-accounts-from-microsoft-azure-active-directory/

The solution is designed to make it easy to manage any number of AWS accounts in a way that integration efforts are not increased with number of accounts.

This solution includes an PowerShell script to automate ongoing changes in AWS that need to be updated in Azure AD, as well as a solution to easily deploy changes in AWS accounts without having to manually login to each account. You can read about details in the blog post.