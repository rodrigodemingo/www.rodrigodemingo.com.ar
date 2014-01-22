<?php
ob_start();
//http://www.askapache.com/htaccess/apache-status-code-headers-errordocument.html
/*
array( floor($code / 100)
 1=>'INFO', 2=>'SUCCESS', 3=>'REDIRECT', 4|5=>'ERROR', 4=>'CLIENT_ERROR', 5=>'SERVER_ERROR', 'VALID_RESPONSE');
*/
$http_status_codes=array(
        100 => 'Continue',
        101 => 'Switching Protocols',
        102 => 'Processing',
        200 => 'OK',
        201 => 'Created',
        202 => 'Accepted',
        203 => 'Non-Authoritative Information',
        204 => 'No Content',
        205 => 'Reset Content',
        206 => 'Partial Content',
        207 => 'Multi-Status',
        300 => 'Multiple Choices',
        301 => 'Moved Permanently',
        302 => 'Found',
        303 => 'See Other',
        304 => 'Not Modified',
        305 => 'Use Proxy',
        306 => 'unused',
        307 => 'Temporary Redirect',
        400 => 'Bad Request',
        401 => 'Authorization Required',
        402 => 'Payment Required',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        406 => 'Not Acceptable',
        407 => 'Proxy Authentication Required',
        408 => 'Request Time-out',
        409 => 'Conflict',
        410 => 'Gone',
        411 => 'Length Required',
        412 => 'Precondition Failed',
        413 => 'Request Entity Too Large',
        414 => 'Request-URI Too Large',
        415 => 'Unsupported Media Type',
        416 => 'Requested Range Not Satisfiable',
        417 => 'Expectation Failed',
        418 => 'unused',
        419 => 'unused',
        420 => 'unused',
        421 => 'unused',
        422 => 'Unprocessable Entity',
        423 => 'Locked',
        424 => 'Failed Dependency',
        425 => 'No code',
        426 => 'Upgrade Required',
        500 => 'Internal Server Error',
        501 => 'Method Not Implemented',
        502 => 'Bad Gateway',
        503 => 'Service Temporarily Unavailable',
        504 => 'Gateway Time-out',
        505 => 'HTTP Version Not Supported',
        506 => 'Variant Also Negotiates',
        507 => 'Insufficient Storage',
        508 => 'unused',
        509 => 'unused',
        510 => 'Not Extended',
);

$err_status_codes = array(
'100'=>array('Continue',''),
'101'=>array('Switching Protocols', ''),
'102'=>array('Processing',  ''),
'200'=>array('OK', ''),
'201'=>array('Created',  ''),
'202'=>array('Accepted',  ''),
'203'=>array('Non-Authoritative Information', ''),
'204'=>array('No Content',  ''),
'205'=>array('Reset Content',  ''),
'206'=>array('Partial Content', ''),
'207'=>array('Multi-Status',  ''),
'300'=>array('Multiple Choices', ''),
'301'=>array('Moved Permanently', 'The document has moved <a href="THEREQUESTURI">here</a>.'),
'302'=>array('Found', 'The document has moved <a href="THEREQUESTURI">here</a>.'),
'303'=>array('See Other',  'The answer to your request is located <a href="THEREQUESTURI">here</a>.'),
'304'=>array('Not Modified',  ''),
'305'=>array('Use Proxy',  'This resource is only accessible through the proxy THEREQUESTURIYou will need to configure your client to use that proxy.'),
'307'=>array('Temporary Redirect', 'The document has moved <a href="THEREQUESTURI">here</a>.'),
'400' => array('Bad Request', 'Your browser sent a request that this server could not understand.'),
'401' => array('Authorization Required', 'This server could not verify that you are authorized to access the document requested. Either you supplied the wrong credentials (e.g., bad password), or your browser doesn\'t understand how to supply the credentials required.'),
'402' => array('Payment Required', 'INTERROR'),
'403' => array('Forbidden', 'You don\'t have permission to access THEREQUESTURI on this server.'),
'404' => array('Not Found', 'We couldn\'t find <acronym title="THEREQUESTURI">that uri</acronym> on our server, though it\'s most certainly not your fault.'),
'405' => array('Method Not Allowed', 'The requested method THEREQMETH is not allowed for the URL THEREQUESTURI.'),
'406' => array('Not Acceptable', 'An appropriate representation of the requested resource THEREQUESTURI could not be found on this server.'),
'407' => array('Proxy Authentication Required', 'This server could not verify that you are authorized to access the document requested. Either you supplied the wrong credentials (e.g., bad password), or your browser doesn\'t understand how to supply the credentials required.'),
'408' => array('Request Time-out', 'Server timeout waiting for the HTTP request from the client.'),
'409' => array('Conflict', 'INTERROR'),
'410' => array('Gone', 'The requested resourceTHEREQUESTURIis no longer available on this server and there is no forwarding address. Please remove all references to this resource.'),
'411' => array('Length Required', 'A request of the requested method GET requires a valid Content-length.'),
'412' => array('Precondition Failed', 'The precondition on the request for the URL THEREQUESTURI evaluated to false.'),
'413' => array('Request Entity Too Large', 'The requested resource THEREQUESTURI does not allow request data with GET requests, or the amount of data provided in the request exceeds the capacity limit.'),
'414' => array('Request-URI Too Large', 'The requested URL\'s length exceeds the capacity limit for this server.'),
'415' => array('Unsupported Media Type', 'The supplied request data is not in a format acceptable for processing by this resource.'),
'416' => array('Requested Range Not Satisfiable', ''),
'417' => array('Expectation Failed', 'The expectation given in the Expect request-header field could not be met by this server. The client sent <code>Expect:</code>'),
'422' => array('Unprocessable Entity', 'The server understands the media type of the request entity, but was unable to process the contained instructions.'),
'423' => array('Locked', 'The requested resource is currently locked. The lock must be released or proper identification given before the method can be applied.'),
'424' => array('Failed Dependency', 'The method could not be performed on the resource because the requested action depended on another action and that other action failed.'),
'425' => array('No code', 'INTERROR'),
'426' => array('Upgrade Required', 'The requested resource can only be retrieved using SSL. The server is willing to upgrade the current connection to SSL, but your client doesn\'t support it. Either upgrade your client, or try requesting the page using https://'),
'500' => array('Internal Server Error', 'INTERROR'),
'501' => array('Method Not Implemented', 'GET to THEREQUESTURI not supported.'),
'502' => array('Bad Gateway', 'The proxy server received an invalid response from an upstream server.'),
'503' => array('Service Temporarily Unavailable', 'The server is temporarily unable to service your request due to maintenance downtime or capacity problems. Please try again later.'),
'504' => array('Gateway Time-out', 'The proxy server did not receive a timely response from the upstream server.'),
'505' => array('HTTP Version Not Supported', 'INTERROR'),
'506' => array('Variant Also Negotiates', 'A variant for the requested resource <code>THEREQUESTURI</code> is itself a negotiable resource. This indicates a configuration error.'),
'507' => array('Insufficient Storage','The method could not be performed on the resource because the server is unable to store the representation needed to successfully complete the request. There is insufficient free space left in your storage allocation.'),
'510' => array('Not Extended', 'A mandatory extension policy in the request is not accepted by the server for this resource.')
);


    


if (isset($_SERVER['REDIRECT_STATUS'])) $err_code = $_SERVER['REDIRECT_STATUS'];

$err_req_meth = $_SERVER['REQUEST_METHOD'];
$err_req = htmlentities(strip_tags($_SERVER['REQUEST_URI']));
$err_phrase = $err_status_codes[$err_code][0];
$err_body = str_replace(
 array('INTERROR', 'THEREQUESTURI', 'THEREQMETH'),
 array('The server encountered an internal error or misconfiguration and was unable to complete your request.',$err_req, $err_req_meth),$err_status_codes[$err_code][1]);

@header("HTTP/1.1 $err_code $err_phrase", 1);
@header("Status: $err_code $err_phrase", 1);

//400 || 408 || 413 || 414 || 500 || 503 || 501
//@header("Connection: close", 1);

if ( $err_code=='400'||$err_code=='403'||$err_code=='405'||$err_code[0]=='5'){
 @header("Connection: close", 1);
 if ($err_code == '405') @header('Allow: GET,HEAD,POST,OPTIONS,TRACE');
 echo "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html>\n<head>\n<title>{$err_code} {$err_phrase}</title>\n<h1>{$err_phrase}</h1>\n<p>{$err_body}<br>\n</p>\n</body></html>";
} else echo '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
       "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xml:lang="en" lang="en">
<head>
  <title>'.$err_code.' '.$err_phrase.'</title>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8" />
</head>
<body>
<h1>'.$err_code.' '.$err_phrase.'</h1>
<hr />
<p>
'.$err_body.'<br />
</p>
  </body>
</html>';
?>
