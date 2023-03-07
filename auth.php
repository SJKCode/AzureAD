<?php

// Adapted from Sami Sipponen's Simple Azure Oauth2 Example with PHP
// https://www.sipponen.com/archives/4024

session_start();  

error_reporting(-1);  
ini_set("display_errors", "on");  

//Configuration

$client_id = "";  //Application (client) ID
$ad_tenant = "";  //Azure Active Directory Tenant ID
$client_secret = "";  //Client Secret
$redirect_uri = "";  //This needs to match what is set in Azure
$error_email = "";  //If your php.ini doesn't contain sendmail_from, use: ini_set("sendmail_from", "user@example.com");

function errorhandler($input, $email)
{
	$output = "PHP Session ID:    " . session_id() . PHP_EOL;
	$output .= "Client IP Address: " . getenv("REMOTE_ADDR") . PHP_EOL;
	$output .= "Client Browser:    " . $_SERVER["HTTP_USER_AGENT"] . PHP_EOL;
	$output .= PHP_EOL;

	ob_start(); 
	var_dump($input); 
	$output .= ob_get_contents(); 
	ob_end_clean();  
	mb_send_mail($email, "Your Azure AD Oauth2 script faced an error!", $output, "X-Priority: 1\nContent-Transfer-Encoding: 8bit\nX-Mailer: PHP/" . phpversion());
	exit;
  
}

if (isset($_GET["code"])) echo "<pre>";  // For debugging

if (!isset($_GET["code"]) and !isset($_GET["error"])) {  // Authentication part begins

	//First stage of the authentication process
	$url = "https://login.microsoftonline.com/" . $ad_tenant . "/oauth2/v2.0/authorize?";
	$url .= "state=" . session_id();  
	$url .= "&scope=User.Read";  
	$url .= "&response_type=code";
	$url .= "&approval_prompt=auto";
	$url .= "&client_id=" . $client_id;
	$url .= "&redirect_uri=" . urlencode($redirect_uri);
	header("Location: " . $url);  
  
} elseif (isset($_GET["error"])) {  //Second load of this page

	echo "Error handler activated:\n\n";

	var_dump($_GET);  //DUMP ERRORS

	errorhandler(array("Description" => "Error received at the beginning of second stage.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION), $error_email);
  
} elseif (strcmp(session_id(), $_GET["state"]) == 0) {  //Checking that the session_id matches to the state for security reasons

	echo "Stage2:\n\n";  

	var_dump($_GET);  

	//Verifying the received tokens with Azure and finalizing the authentication part

	$content = "grant_type=authorization_code";
	$content .= "&client_id=" . $client_id;
	$content .= "&redirect_uri=" . urlencode($redirect_uri);
	$content .= "&code=" . $_GET["code"];
	$content .= "&client_secret=" . urlencode($client_secret);
	$options = array(
		"http" => array(  //Use "http" even if you send the request with https
		"method"  => "POST",
		"header"  => "Content-Type: application/x-www-form-urlencoded\r\n" .
		"Content-Length: " . strlen($content) . "\r\n",
		"content" => $content
		)
	);
  
	$context  = stream_context_create($options);

	$json = file_get_contents("https://login.microsoftonline.com/" . $ad_tenant . "/oauth2/v2.0/token", false, $context);

	if ($json === false) errorhandler(array("Description" => "Error received during Bearer token fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);

	$authdata = json_decode($json, true);

	if (isset($authdata["error"])) errorhandler(array("Description" => "Bearer token fetch contained an error.", "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);

	var_dump($authdata);  //Debug print
  
	//Fetching the basic user information that is likely needed by your application

	$options = array(
	"http" => array(  //Use "http" even if you send the request with https
	  "method" => "GET",
	  "header" => "Accept: application/json\r\n" .
		"Authorization: Bearer " . $authdata["access_token"] . "\r\n"
	)
	);
  
	$context = stream_context_create($options);

	$json = file_get_contents("https://graph.microsoft.com/v1.0/me", false, $context);

	if ($json === false) errorhandler(array("Description" => "Error received during user data fetch.", "PHP_Error" => error_get_last(), "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);

	$userdata = json_decode($json, true);  // This should now contain your logged on user information

	if (isset($userdata["error"])) errorhandler(array("Description" => "User data fetch contained an error.", "\$userdata[]" => $userdata, "\$authdata[]" => $authdata, "\$_GET[]" => $_GET, "HTTP_msg" => $options), $error_email);


	var_dump($userdata);  // THE MAIN DUMP

	// Echo some data from the array
	
  	echo("Welcome, ");
	echo $userdata['givenName'];
	
	// Stash the Array Info
	
	$_SESSION['givenName'] = $userdata['givenName'];
	$_SESSION['surname'] = $userdata['surname'];
	$_SESSION['displayName'] = $userdata['displayName'];
	$_SESSION['email'] = $userdata['mail'];
	$_SESSION['uname'] = $userdata['userPrincipalName'];
	$_SESSION['id'] = $userdata['id'];
	
	// NOW DO SOMETHING
	
} else {
	
	// Something has gone wrong

	echo "Message\n\n";

	echo "PHP Session ID used as state: " . session_id() . "\n";  // Remove for production

	var_dump($_GET);  //var_dumps are useful

	errorhandler(array("Description" => "State mismatch.", "\$_GET[]" => $_GET, "\$_SESSION[]" => $_SESSION), $error_email);
}

echo "\n<a href=\"" . $redirect_uri . "\">Click here to redo the authentication</a>";  //Only to ease up your tests

echo "\n<a href=\"protected.php\">Protected Page</a>";  //Only to ease up your tests

echo "\n<a href=\"logout.php\">Logout</a>";  //Only to ease up your tests

?>