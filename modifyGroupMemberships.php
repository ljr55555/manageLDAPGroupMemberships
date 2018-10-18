<?php
	////////////////////////////////////////////////////////////////////////////////
	// This page allows a developer to quickly modify their group memberships to test application error messages users will encounter when their
	// accounts have not been provisioned with the appropriate authorization groups. This is, obviously, a REALLY bad idea in production so please
	// do not re-target the strLDAPHost
	////////////////////////////////////////////////////////////////////////////////
	error_reporting(0);		// Disabling error reporting because err 16 and err 20 are expected
	////////////////////////////////////////////////////////////////////////////////
	// Site specific LDAP values
	////////////////////////////////////////////////////////////////////////////////
	$strLDAPProtocol = 'LDAPS';
	$strLDAPHost = 'ldap.dev.company.ccTLD';
	$iLDAPPort = '636';

	$strLDAPSystemUID = 'uid=LDAPGroupModifierAccount,ou=systemids,o=company';
	$strLDAPSystemPassword = 'MlVCd2pETks1L2d5OGdERDFXL3JqbEpCOW1lRjdoTjM4WnFWTGZKZnpDMD0=';	// Password crypted with encrypt_decrypt function
	$strKey = 'ksdjnlksjLKsdJLKDHELFKHNkjdsflksjfcbla';											// key used to openssl_encrypt password -- should come from external file
	$strInitializationVector = 'lkfalIOAJFKOI9jkfdjyqnzpQLAM';									// initialization vector used to openssl_encrypt password -- should come from external file

	$strBaseDN = "ou=groups,o=company";										// Base DN for group search
	$strObjectClassAttribute = 'groupOfUniqueNames';
	$strMemberAttribute = 'uniqueMember';
	$strMemberToFind = 'employeenumber=012345,ou=employees,o=company';		// Individual whose membership is modified through this form, or pull from logged on user

	// Hashed array containing all groups which should be managed through this form
	$strGroupMemberships = array("app_support"=>'0', "app_it"=>'0', "app_administrator"=>'0', "app_sales"=>'0', "app_custserv"=>'0', "app_repair"=>'0');

	////////////////////////////////////////////////////////////////////////////////
	// No more site specific settings
	////////////////////////////////////////////////////////////////////////////////


	////////////////////////////////////////////////////////////////////////////////
	// This function uses openssl_encrypt and openssl_decrypt to avoid storing
	// passwords in clear text. Key should be sourced from something outside of file
	// to prevent a single file from containing everything someone needs to obtain
	// the clear text password.
	// Input: $strAction:   'encrypt' or 'decrypt'
	//		  $strEncryptionMethod:	Encryption method
	//		  $strInput:    string to encrypt or decrypt
	//		  $strClearKey: key used to encrypt the string
	//		  $strClearInitializationVector: non-NULL initialization vector
	// Output: $strResult:  encrypted or decrypted string value
	////////////////////////////////////////////////////////////////////////////////
	function encrypt_decrypt($strAction, $strEncryptionMethod, $strInput, $strClearKey, $strClearInitializationVector) {
		$strResult = false;

		$strSecretKey = hash('sha256', $strClearKey);
		$strSecretInitializationVector = substr(hash('sha256', $strClearInitializationVector), 0, 16);

		if ( $strAction === 'encrypt' ) {
			$strResult = base64_encode(openssl_encrypt($strInput, $strEncryptionMethod, $strSecretKey, 0, $strSecretInitializationVector ));
		}
		else if( $strAction === 'decrypt' ) {
			$strResult = openssl_decrypt(base64_decode($strInput), $strEncryptionMethod, $strSecretKey, 0, $strSecretInitializationVector );
		}
		return $strResult;
	}
	////////////////////////////////////////////////////////////////////////////////

	$boolConnectFail = 0;
	putenv('LDAPTLS_REQCERT=never');
	$connLDAP = ldap_connect("$strLDAPProtocol://$strLDAPHost:$iLDAPPort") or $boolConnectFail = 1;
	if($boolConnectFail == 1){
		print "$strLDAPProtocol connection to $strLDAPHost on port $iLDAPPort failed\n";
	}
	else{
		$strLDAPSystemPassword = encrypt_decrypt("decrypt","AES-256-CBC",$strLDAPSystemPassword,$strKey,$strInitializationVector);
		ldap_set_option($connLDAP , LDAP_OPT_PROTOCOL_VERSION, 3);
		$boolLDAPBind = ldap_bind($connLDAP, $strLDAPSystemUID, $strLDAPSystemPassword);

		if(isset($_POST['Submit'])){
			// add user to groups and report
			print "<PRE>";
			foreach($strGroupMemberships as $strGroupName=>$iMemberValidation){
				$strNewState = $_POST[$strGroupName];
				$strGroupFQDN = "cn=$strGroupName,$strBaseDN";
				if( strcmp($strNewState,$strGroupName) == 0){
					print "I want $strMemberToFind to be a member of $strGroupFQDN\n";
					$ldapGroup = array();
					$ldapGroup[$strMemberAttribute] = $strMemberToFind;
					ldap_mod_add($connLDAP,$strGroupFQDN,$ldapGroup);
					$iModifyResult = ldap_errno($connLDAP);
					if( $iModifyResult == 0){
						print "\tI have successfully added $strMemberToFind to $strGroupFQDN\n\n";
					}
					elseif( $iModifyResult == 20){
						print "\t$strMemberToFind was already a member of $strGroupFQDN\n\n";
					}
					else{
						print "\tI got " . ldap_errno($connLDAP) . " attempting to add $strMemberToFind to $strGroupFQDN\n\n";
					}

				}
				else{
					print "I do not want $strMemberToFind to be a member of $strGroupFQDN\n";
					$ldapGroup = array();
					$ldapGroup[$strMemberAttribute] = $strMemberToFind;
					ldap_mod_del($connLDAP,$strGroupFQDN,$ldapGroup);
					$iModifyResult = ldap_errno($connLDAP);
					if( $iModifyResult == 0 ){
						print "\tI have successfully removed $strMemberToFind from $strGroupFQDN\n\n";
					}
					elseif( $iModifyResult == 16){
						print "\t$strMemberToFind was not a member of $strGroupFQDN\n\n";
					}
					else{
						print "\tI got " . ldap_errno($connLDAP) . " attempting to remove $strMemberToFind from $strGroupFQDN\n\n";
					}
				}
			}
			print "</PRE>\n";
		}
		else{
			$strFilter = "(&(objectClass=$strObjectClassAttribute)($strMemberAttribute=$strMemberToFind)(|";
			foreach($strGroupMemberships as $strGroupName=>$iMemberValidation){
					$strFilter = $strFilter . "(cn=" . $strGroupName . ")";
			}
			$strFilter = $strFilter . "))";


			print "<PRE>\n";
			$ldapSearchResults = ldap_search($connLDAP, $strBaseDN, $strFilter, array('cn'));
			$ldapEntries = ldap_get_entries($connLDAP, $ldapSearchResults);

			for($i=0; $i<$ldapEntries["count"]; $i++){
				$strGroup = strtolower($ldapEntries[$i]['cn'][0]);
				$strGroupMemberships[$strGroup] = 1;
			}

			print "<form action=" . $_SERVER["PHP_SELF"] ." method=\"post\">\n";
			print "<table border=0>\n";
			foreach($strGroupMemberships as $strGroupName=>$iMemberValidation){
				print "<tr><td><input type=\"checkbox\" name=\"$strGroupName\" value=\"$strGroupName\"";
				if($iMemberValidation == 1){
					print " checked";
				}
				print "></td><td>$strGroupName</td></tr>";
			}
			print "<tr><td colspan=2><input name=\"Submit\" value=\"Submit\" type=\"submit\"></td></tr></table>\n</form>\n";

			print "</PRE>\n";

		}
	}
	print "<a href=\"" . $_SERVER["PHP_SELF"] . "\">Home</a>\n";
?>
