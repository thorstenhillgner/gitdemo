# Test-EWS
#
# Dieses Script versucht den Posteingang und Kalender eines Postfach # über EWS Impersonation zu &ouml;ffnen # # Voraussettungen # - Exchange 2007 SP1+ # - NET 3.5 # - "Microsoft.Exchange.WebServices.dll
# Getting started with the EWS Managed API # http://msdn.microsoft.com/en-us/library/dd633626(v=exchg.80).aspx
#
# 1.0  Nov 2013  Initiale Version
#
# Impersonation braucht zwei Rechte:
#
# 1. Auf dem Server mit
# get-clientaccessserver  | Add-ADPermission -User svc-ews -ExtendedRights ms-Exch-EPI-Impersonation
#
# Ansonsten Fehler Exception calling "Bind" with "2" argument(s): "The server to which the application is connected cannot impersonate the # requested User due to insufficient permission."
#
# 2. Auf der Datenbank bzw dem Benutzer
# get-mailbox User | add-adpermission -User svc-ews -extendedRight ms-Exch-EPI-may-impersonate
#
#
param(
	[string]$MailboxSMTP = "User@msxfaq.local",	# must be primäry SMTP für impersonation
	[string]$Username    = "svc-ews",				# use default credentials, if empty
	[string]$Domain      = "msxfaq",				# Domain of the authentication User
	[string]$Password    = (read-host -Prompt "Password für $Domain\$Username"),  # password, if $Username is set
	[string]$ServiceURL  = "",						# use Autodiscover, if empty https://exchange.msxfaq.local/EWS/Exchange.asmx",
	[switch]$useImpersonation,						# forces impersonation 
	[string]$dllpath = "C:\Program Files (x86)\Microsoft\Exchange\Web Services\2.1\Microsoft.Exchange.WebServices.dll",
	#[string]$dllpath = "C:\Program Files\Microsoft\Exchange\Web Services\1.0\Microsoft.Exchange.WebServices.dll", # 
	#[string]$dllpath = "C:\Program Files\Microsoft\Exchange\Web Services\2.1\Microsoft.Exchange.WebServices.dll", # EWS DLL
	[switch]$EWSTrace,								# enable tracing of EWS to STDOUT
	[switch]$Verbose								# enable verbose output
)

if ($Verbose) {
	$VerbosePreference = "continue" 
}
Write-verbose "Test-EWS: Start"
Write-Verbose "Loading EWS DLL"

[void][Reflection.Assembly]::LoadFile($dllpath)
Write-Verbose "Creating EWS Service Class"
$service = new-object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2007_SP1)
#$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService('Exchange2007_SP1')
#$service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService
if ($ewsTrace) {
	Write-Verbose " Tracing: enabled"
	$service.TraceEnabled = $true
	#Tracing EWS requests http://msdn.microsoft.com/en-us/library/dd633676(v=exchg.80).aspx
}
# --------------------------- Credentials and Impersonation --------------------------- 
if ($Username -eq "") {  Write-Verbose "Credentials: useDefaultCredentials"
	$service.UseDefaultCredentials = $true
}
else  {
	Write-Verbose "Credentials: use alternate Credentials"
	$service.UseDefaultCredentials = $false  
	$service.Credentials = New-Object System.Net.NetworkCredential($Username, $password, $domain) 
} 
if ($useImpersonation) {
	Write-Verbose "Credentials: use impersonation"
	$service.ImpersonatedUserId = new-object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $mailboxSMTP);

	#Configuring Exchange Impersonation (Exchange Web Services)  #http://msdn.microsoft.com/en-us/library/bb204095(v=exchg.80).aspx
	#$service.impersonatedUserID = new impersonatedUserID(ConnectingIDType.SID,wert)
	#$service.impersonatedUserID = new impersonatedUserID(ConnectingIDType.PrincipalName,wert)
	#$service.impersonatedUserID = new impersonatedUserID(ConnectingIDType.SmtpAddress,wert)
}
# --------------------------- ServiceURI --------------------------- 
if ($serviceURL -eq "") {  
	Write-Verbose "ServiceURL: using Autodiscover für $mailboxSMTP"
	$service.AutodiscoverURL($mailboxSMTP)
}
else {
	Write-Verbose "ServiceURL: using specified $serviceURL"
	$service.URL = New-Object System.Uri($serviceURL) 
} 
write-verbose -Message ("ServiceURI="+$service.URL.AbsoluteUri)
# --------------------------- Connect --------------------------- 
$mbMailbox = new-object Microsoft.Exchange.WebServices.Data.Mailbox($mailboxSMTP)
Write-Verbose "Binding Inbox"
$inbox = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($service,[Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox)
write-host "Number or unread Messages : " $inbox.UnreadCount 
#$emails = $inbox.FindItems(5) 
#$emails | %{$_.load()}
#$emails 

#$view = New-Object Microsoft.Exchange.WebServices.Data.ItemView(1)
#$findResults = $ews.FindItems([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::Inbox,$view)
#""
#"Last Mail From : " + $findResults.Items[0].From.Name #"Subject : " + $findResults.Items[0].Subject #"Sent : " + $findResults.Items[0].DateTimeSent
Write-Verbose "test-ewsimpersonation: End"
#$windowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
#$sidbind = "LDAP://<SID=" + $windowsIdentity.User.Value.ToString() + ">"
#$aceUser = [ADSI]$sidbind
#$service.AutodiscoverURL($aceUser.mail.ToString())
#$service.ImpersonatedUserId = new-object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $mbtoDelegate);