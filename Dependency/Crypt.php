<?php
/* Skapat av Mikael Aspehed 2013-08-22 */
/* Användning: SaltedPassword(PasswordFromUser,SaltLength[,PasswordToVerifyAgainst,NumberOfTimes])*/
/* SaltLength kan vara antingen ett ord eller en siffra som anger längden.
/* Vidareutveckling kan vara att salta den slutliga SHA1 strängen med saltet på samma sätt som tidigare görs. */
/*
	v1: Använder Salt i form av siffror för att krydda lösenordet.
	v2: Salta även sha1 strängen
	v3: Array sparar saltet, för varje uppkomst av samma värde i saltet, plussa med 1 på antal. Detta ökar spridningen på saltet.
*/

//include_once($_SERVER['DOCUMENT_ROOT'] . "/modules/LogFunctionUsage.php");
function NumberInHexAlphabet($Letter) {
$Letter = strtolower($Letter);
$Alphabet = array("a"=>"1","b"=>"2","c"=>"3","d"=>"4","e"=>"5","f"=>"6","0"=>"7","1"=>"8","2"=>"9","3"=>"10","4"=>"11","5"=>"12","6"=>"13","7"=>"14","8"=>"15","9"=>"16");
return $Alphabet[$Letter];
}




function SaltedPassword($PasswordFromUser,$SaltLength,$PasswordFromDatabase = "",$NumberOfTimes = 2) {
	//echo "SaltLength: " . $SaltLength . "<br>";
	//LogFunctionUsage(dirname(__FILE__) . '/' . __FUNCTION__ . ".log");
	if(!is_numeric($SaltLength)) {
		$SaltLength=strlen($SaltLength);
	}
	//First, we generate the salt. The length of the salt is determined by $SaltLength. The salt is converted to a hexadecimal string but the length is preserved.
	//The salt is either generated through a randomizer or gathered from the supplied $PasswordFromDatabase.
	$Salt = "";
	$SaltCharacterArray = array();
	if($PasswordFromDatabase == "") {
		for ($i=0;$i<$SaltLength;$i++) {
			$Salt = $Salt . rand(0,9999);
		}
		$Salt = strtolower(substr(sha1($Salt),0,$SaltLength));
	//	echo "(Not From DB) Salt: {" . $Salt . "}<br>";
	} else {
		$Salt = substr($PasswordFromDatabase,0,$SaltLength);
	//	echo "(From DB) Salt: {" . $Salt . "}<br>";
	}

	
	//The salt is sprinkled on the $PasswordFromUser. Using the hexadecimals numerical position in the above array as markers for where to place the salt in the string.
	//This ensures that the salt is in different places on each unique password. Even if the password is the same.
	for($NumberOfTimesDone=0;$NumberOfTimesDone<$NumberOfTimes;$NumberOfTimesDone++) {

		for($i=0;$i<strlen($Salt);$i++) {
			if(array_key_exists($Salt[$i],$SaltCharacterArray)) {
				$SaltCharacterArray[$Salt[$i]]++;
			} else {
				$SaltCharacterArray[$Salt[$i]] = 1;
			}

			$GrainOfSalt = substr($Salt,$i,1);
			$EndPosition = NumberInHexAlphabet($GrainOfSalt)*$SaltCharacterArray[$Salt[$i]];
			if($EndPosition>strlen($PasswordFromUser)+1) {
				$EndPosition = $EndPosition/2;
			}
			$Password_Start = substr($PasswordFromUser,0,$EndPosition);
			$Password_End = substr($PasswordFromUser,strlen($Password_Start));
			$PasswordFromUser = $Password_Start . $GrainOfSalt . $Password_End;
		}

		if(($NumberOfTimesDone<($NumberOfTimes-1)) or ($NumberOfTimes<=1)) {
			$PasswordFromUser = sha1($PasswordFromUser);
		}

	}

	//Lastly we add the $salt to the beginning of the resulting crypted hash, so we can encrypt another string and reach the same result.
	$PasswordFromUser = $Salt . $PasswordFromUser;
	//If there was a $PasswordFromDatabase supplied we check if it matches our result. If none was provided, we return the encrypted string.
	if(!($PasswordFromDatabase == "")) {
		
		
		If($PasswordFromUser == $PasswordFromDatabase) {
			return true;
		} else {
			return false;
		}
	} else {
		return $PasswordFromUser;
	}
}
?>