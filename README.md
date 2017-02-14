Setting up a phishing server is a very long and tedious process. It can take hours to setup, and can be compromised in minutes. The esteemed gentlemen [@cptjesus](https://twitter.com/cptjesus) and [@Killswitch_GUI](https://twitter.com/Killswitch_GUI) have already made leaps and bounds in this arena. I took everything that I learned from them on setting up a server, and applied it to a bash script to automate the process. Before we get to the script, let’s go over the basics to setting up a mail server.

First, let’s outline the process, then dive deeper into each step:

1. Obtain a VPS/Server/IP trusted by the target
2. Setup Secure Access to the Server
3. Disable IPv6 and Remove Exim
4. Install SSL Certs from Let's Encrypt
5. Install Dovecot and Postfix
6. Add Aliases
7. Configure DNS Entries
8. Test Mail Server Configuration

## 1) Obtain a VPS/Server/IP trusted by the target: ##

To use this script, you must have a Domain Name, and access to a server running Debian 8. You must have the ability to set the PTR record of the IP Address assigned to your server. There are many different options available to purchase a virtual private server(VPS). Some notable ones include [DigtalFyre](https://www.digitalfyre.com), [Linode](https://www.linode.com), and [DigitalOcean](https://www.digitalocean.com/)

## 2) Setup Secure Access to the Server ##

The industry standard for accessing a server remotely is through SSH. Ideally, SSH should only be accessible to a single account with low privileges. root login and password authentication should also be disabled. The Command “Setup SSH” will prompt you to create an account to be used for SSH Authentication. Once the account is setup the script uses that account to create an “.ssh” directory. It will also edit /etc/ssh/sshd_config to only allow that user to authenticate, and prevent remote root logins.

## 3) Disable ipv6 and remove Exim

Debian 8 comes with the Exim mail service by default. Exim can cause problems when installing Postfix and should be removed. On the same note, IPv6 can create additional problems and should be disabled. The command “Debian Prep” will remove Exim, and disable IPv6. The script will also prompt you for the Mail Server’s Domain Name. It will use this Domain name to change the Hostname of the System. After all of these changes, the system will reboot.

## 4) Install SSL Certs From Lets Encrypt ##

We will need a working SSL Certificate in order to use TLS with Postfix authentication. To create this, ensure that you have set the A record on your Domain Name to the IP address of the Server and run the “Install SSL” command. It will prompt you for the Domain Name again, and then begin the process of creating the SSL Certs.

## 5) Installing Postfix and Dovecot (MailServer): ##

Now that all of the prerequisites are complete, we can start installing the actual mail server. In order to make a mail server appear legitimate, it must have a reverse PTR record set up correctly and employ the following elements:

1. Sender Policy Framework (SPF)
2. DomainKeys Identified Mail (DKIM)
3. Domain Message Authentication, Reporting, and Conformance (DMARC)

This script will prompt you for the domain name you would like to use, and then setup all of the rest for you! Once the command has finished you should see a service status report for Postfix, Dovecot, OpenDKIM, and OpenDMARC. Each of these services should report “active (running)”

## 6) Add Aliases ##

Once the server is up and running, we need to tell it where to send mail to and from. Using the command “Add Aliases”, assign the user account you created earlier to receive mail for root, and then chose an alias to test from.

## 7) Configure DNS Entries ##

Finally we can add DNS entries to our domain to ensure that SPF, DKIM, and DMARC are working properly. Using the command “Get DNS Entries” will print the DNS entries to the console.

## 8) Testing your new mail server ##

To test your new mail server, send an email using the mail command! Simply run mail target@example.com on the command line, and then follow the prompts. Then check to see if the email was delivered. You can also use tools like
[DKIM Validator](http://dkimvalidator.com/) to check that DKIM is passing, and [MX Toolbox](http://mxtoolbox.com/) for pretty much everything else.

## In Conclusion ##

Phishing is a hard and painful process and this script is only part of the battle. Some organizations have hardened spam filters that can be incredibly difficult to get around. Things like domain categorization, and domain age can help but ultimately may still not be enough. In my testing, this script will get through to Gmail inboxes on DigitalFyre’s infrastructure. However, the story is different when used with Digital Ocean.  You can find the script on Github [here](https://github.com/jcatrambone94/Postfix-Server-Setup).
