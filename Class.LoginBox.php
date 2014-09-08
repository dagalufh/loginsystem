<?php
include_once("Class.Abstract.LoginSystem.php");
/**************************************************************************************************************************
 * 	Loginbox
 **************************************************************************************************************************/
 /**
 * Used to define the loginhandler
 * This class contains the functions that control the login.
 *
 * An example of smallest application:
 * <code>
 * <?php
 * $TestVar = New LoginBox($DatabaseConnection);
 *
 * if ($Testvar->Verification()) {
 *		echo "User is logged in.";
 * } else {
 *		$TestVar->ShowBox();
 * }
 * ?>
 * </code>
 *
 * @since Version 2.5
 */
class LoginBox extends LoginSystem {

	/**
	 * Indicates if the account is locked or not.
	 * @var boolean $AccountLocked
	 */
	protected $AccountLocked = false;

	/**
	 * Allowed number of failed logins before locking account.
	 * @var int $LoginThreshold
	 */
	protected $LoginThreshold = 3;

	/**
	 * Contains the question needed to unlock the account.
	 * @var string $UnlockQuestion
	 */
	protected $UnlockQuestion = "";

	/**
	 * This function builds the dialogbox that allows a user to login.
	 *
	 * Output can either be via return or via echo. Return allows the programmer to decide the output format.
	 * @param boolean $Output toggles how the output should be displayed.
	 * @return array
	 */
	public function ShowBox($Output = false) {
		
		// Build the LoginBox.
		$LoginBoxOutput['FormStart'] 	= '<form method="POST" name="LoginSystemLoginForm" action="">';
		$LoginBoxOutput['Username'] 	= '<input class="LoginSystemGeneral LoginSystemInputbox" type="text" name="Username">';
		$LoginBoxOutput['Password'] 	= '<input class="LoginSystemGeneral LoginSystemInputbox" type="password" name="Password">';
		$LoginBoxOutput['LoginButton'] 	= '<input class="LoginSystemGeneral LoginSystemButton" type="submit" value="'.$this->GetLanguageSpecificText('Button_Login').'" name="LoginBoxSubmit">';
		$LoginBoxOutput['FormEnd'] 		= '</form>';
		$LoginBoxOutput['Error']		= $this->GetUserFeedback(false);

		if ($this->AccountLocked) {
			$LoginBoxOutput['UnlockSequenceQuestion'] 	= $this->GetLanguageSpecificText('UnlockSequenceQuestion') . ':' . $this->UnlockQuestion;
			$LoginBoxOutput['UnlockSequenceAnswer'] 	= $this->GetLanguageSpecificText('UnlockSequenceAnswer') . ': <input class="LoginSystemGeneral LoginSystemInputbox" type="text" name="UnlockSequenceAnswer">';
		}

		if($Output == false) {
			// Output it directly via Echo
			echo "<table>";
			if(isset($this->LoginSystemMessage[3])) {
				echo "<tr><td>" . $this->GetUserFeedback(true) . "</td></tr>";
				}
			echo $LoginBoxOutput['FormStart'];
				echo "<tr><td>" . $this->GetLanguageSpecificText("Input_Username") . "</td><td>" . $LoginBoxOutput['Username'] . "</td></tr>";
				echo "<tr><td>" . $this->GetLanguageSpecificText("Input_Password") . "</td><td>" . $LoginBoxOutput['Password'] . "</td></tr>";
				if ($this->AccountLocked) {
					echo "<br>";
					echo "<tr><td>" . $LoginBoxOutput['UnlockSequenceQuestion'] . "</td></tr>";
					echo "<tr><td>" . $LoginBoxOutput['UnlockSequenceAnswer'] . "</td></tr>";
				}
				echo "<tr><td>" . $LoginBoxOutput['LoginButton'] . "</td></tr>";
			echo $LoginBoxOutput['FormEnd'];
			echo "</table>";
		} else {
			// Return to caller as an array.

			return $LoginBoxOutput;
		}
		
	}

	/**
	 * This function controls if the user is logged in or is in the process of logging in.
	 *
	 * There is two separate functions actually depending on if the user is logging in or is logged in.
	 * Logging in checks username and password but the logged in checkes if the users username and securitysequence is correct.
	 *
	 * @param int $Level Optional variable that controls the allowed AccessLevel. Defaults to 0.
	 *
	 * @return boolean
	 */

	public function Verification ($Level = 0) {
		$ProvidedUsername = false;
		$ProvidedPassword = false;
		$ProvidedSecurity = false;
		$Login = false;

		// Check if the call is made after a loginattempt. Setup variables accordingly.
		if (isset($_POST['LoginBoxSubmit'])) {
			$ProvidedUsername = $_POST['Username'];
			$ProvidedPassword = $_POST['Password'];
			unset($_POST['LoginBoxSubmit']);
			$Login = true;
			$this->DebugMessage("Login_Verify_Against","POST");
		} else {
			if( (!isset($_SESSION['Username'])) or (!isset($_SESSION['Security'])) ) {
				return false;
			}
			$ProvidedUsername = $_SESSION['Username'];
			$ProvidedSecurity = $_SESSION['Security'];
			$this->DebugMessage("Login_Verify_Against","SESSION");
		}

		// If there is a empty username, falsly provided by an empty session, return false.
		if($ProvidedUsername == "") {
			$this->DebugMessage("ProvidedUsername","Empty");
			return false;
		}

		// Check that there is a valid mysqli database connection.
		if( (is_object($this->DatabaseHandle)) and (get_class($this->DatabaseHandle) == 'mysqli') ) {
			// Attempt to fetch userinformation.
			$this->BuildQuery = "";
			foreach ($this->AddedTables as $AddedTable) {
			$this->BuildQuery = $this->BuildQuery . "," . $AddedTable;
			}
			
			if( $QueryResult = mysqli_query($this->DatabaseHandle, "SELECT UserID, Username, Password, SecuritySequence, AccessLevel".$this->BuildQuery." from Users where Username='".mysqli_real_escape_string($this->DatabaseHandle,$ProvidedUsername)."'") ) {
				$QueryRow = mysqli_fetch_assoc($QueryResult);
			} else {
				$this->DebugMessage("Login","[AttemptedLogin] Failed to query database for username: " . mysqli_error($this->DatabaseHandle));
				$this->AddUserFeedback($this->GetLanguageSpecificText("Error_SystemError"));
			}
			// If a username does not exist, report back with loginissue.
			if(!isset($QueryRow['Username'])) {
				$this->DebugMessage("MySQL", "QueryRow is empty.");
				$this->DebugMessage("MySQL",'Mysqli error: '. mysqli_error($this->DatabaseHandle));
				$this->AddUserFeedback($this->GetLanguageSpecificText('LoginIssues'));
				return false;
			}

			// If the securitycode was not supplied and $ProvidedSecurity is still false, handle it as a loginattempt and match user password with database.
			if($ProvidedSecurity == false) {
				
				$this->VerifySaltLength($ProvidedPassword);
				
				//echo "DB: " . $QueryRow['Password'] . "<br>";
				//echo "Try:" . SaltedPassword($ProvidedPassword,$this->SaltLength,$QueryRow['Password']) . "<br>";
				if(!SaltedPassword($ProvidedPassword,$this->SaltLength,$QueryRow['Password'])) {
					$this->DebugMessage("Login","Passwords did not match");
					$this->AddUserFeedback($this->GetLanguageSpecificText('LoginIssues'));

					if($this->AddedSecurity) {
						if($QueryRow['AttemptedLogins'] < $this->LoginThreshold) {
							$this->LoginBoxRecordLogins($QueryRow['UserID'],$QueryRow['AttemptedLogins']);
						} else {
							$this->LoginBoxLockUserAccount($QueryRow['UserID']);
						}

						if ( ($QueryRow['Locked']) or ($this->AccountLocked) ) {
							$this->AccountLocked = true;
							$this->UnlockQuestion = $QueryRow['SecurityQuestion'];
						}
					}
					return false;
				} else {

					// if the passwords match, update database with new securitysequence.
					$this->DebugMessage("Login","Passwords match");
					$this->BuildQuery = "";
					if($this->AddedSecurity) {
						if ( ($QueryRow['Locked']) and (!isset($_POST['UnlockSequenceAnswer'])) ){
								$this->AccountLocked = true;
								$this->UnlockQuestion = $QueryRow['SecurityQuestion'];
								$this->AddUserFeedback($this->GetLanguageSpecificText('IncorrectSecurityAnswer'));
								return false;
						}
						if ( ($QueryRow['Locked']) and (isset($_POST['UnlockSequenceAnswer'])) ){
								if(!LoginBoxUnlockUserAccount($QueryRow['UserID'],$QueryRow['SecurityAnswer'],$_POST['UnlockSequenceAnswer'])) {
									$this->AccountLocked = true;
									$this->UnlockQuestion = $QueryRow['SecurityQuestion'];
									return false;
								}
						}
						$this->BuildQuery = $this->AddedTables[1] . "='0', ";						
					}
					$Sequence = date("ymdhis") . $_SERVER['REMOTE_ADDR'];
					$GeneratedSecuritySeq = SaltedPassword($Sequence,(strlen($_SERVER['REMOTE_ADDR'])/2));
					
					if( mysqli_query($this->DatabaseHandle, "UPDATE Users SET ".$this->BuildQuery." SecuritySequence='".$GeneratedSecuritySeq."' WHERE UserID='". $QueryRow['UserID']."'") ) {
						$_SESSION['Security'] = $Sequence;
						$_SESSION['Username'] = $QueryRow['Username'];
						$_SESSION[$this->Session_UserID] = $QueryRow['UserID'];
					}
				}
			} else {
				// If the securitysequence does not match the one in the database, treat it as not logged in.
				if(!SaltedPassword($ProvidedSecurity,(strlen($_SERVER['REMOTE_ADDR'])/2),$QueryRow['SecuritySequence'])) {
					$this->AddUserFeedback($this->GetLanguageSpecificText('NotLoggedIn'));
					$this->DebugMessage("Security","[ProvidedSecurity] ".$ProvidedSecurity);
					$this->DebugMessage("Security","[QueryRowSecurity] ".$QueryRow['SecuritySequence']);
					$this->DebugMessage("Security","[SaltLength] ".(strlen($_SERVER['REMOTE_ADDR'])/2));
					return false;
				}
			}

			// After verification of user login is achieved, verify that the user is allowed to view the content based on accesslevel.
			if ($QueryRow['AccessLevel'] < $Level) {
				$this->LoginSystemMessage[2] = $this->GetLanguageSpecificText('AccessLevel');
				$this->DebugMessage("Level", "[Query] ".$QueryRow['AccessLevel']);
				$this->DebugMessage("Level", "[Required] ".$level);
				return false;
			}

			
			// Redirect after all is completered and no errors occured... Perhaps move this to be redirected on login/verification false returns.
			// This part only executes if we have reached this point after a successfull login.
			if($Login) {
				$this->CustomLoginWork();
			}
			return true;
		} else {
			// if there was no active mysqli connection, throw an debug error and return false.
			$this->DebugMessage("MySQLi","Not a valid MySQLi connection (".get_resource_type($this->DatabaseHandle).")");
			return false;
		}
	}


	/**************************************************************************************************************************
	 * 	Private functions that are not accessable outside of the class.
	 **************************************************************************************************************************/

	/**
	 * This function records logins to the users row in the table.
	 *
	 * @param int $UserID The unique identifier of the current user in the database.
	 * @param int $AttemptedLogins the number of attempted logins so far.
	 *
	 * @return boolean
	 */
	private function LoginBoxRecordLogins($UserID,$AttemptedLogins) {
		if(!(mysqli_query($this->DatabaseHandle,"UPDATE Users SET AttemptedLogins='". ($AttemptedLogins+1) ."' WHERE UserID='".$UserID."'"))) {
			$this->DebugMessage("Login","[AttemptedLogin] Failed to record login: " . mysqli_error($this->DatabaseHandle));
			return false;
		}
		return true;
	}

	/**
	 * Locks the users account.
	 *
	 * @param int $UserID The unique identifier of the current user.
	 * @return boolean
	 */
	private function LoginBoxLockUserAccount($UserID) {
		if ( !(mysqli_query($this->DatabaseHandle,"UPDATE Users SET Locked='1' WHERE UserID='".$UserID."'")) ) {
			$this->DebugMessage("Login","[AttemptedLogin] Failed to lock account: " . mysqli_error($this->DatabaseHandle));
			return false;
		}
		$this->AddUserFeedback($this->GetLanguageSpecificText('AccountLocked'));
		$this->AccountLocked = true;
		return true;
	}

	/**
	 * Unlocks the users account.
	 *
	 * @param int $UserID The unique identifier of the current user.
	 * @param string $DatabaseSecurityAnswer the securityanswer fetched from the database to compare against.
	 * @param string $UserSecurityAnswer the supplied securityanswer from the user, to be encrypted for comparison.
	 *
	 * @return boolean
	 */

	private function LoginBoxUnlockUserAccount($UserID,$DatabaseSecurityAnswer,$UserSecurityAnswer) {
	# Check that the supplied answer is the correct one. The answers should be salted aswell.
		if(!SaltedPassword($UserSecurityAnswer,strlen($UserSecurityAnswer),$DatabaseSecurityAnswer)) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('IncorrectSecurityAnswer'));
			return false;
		} else {
			if ( !(mysqli_query($this->DatabaseHandle,"UPDATE Users SET Locked='0' WHERE UserID='".$UserID."'")) ) {
				$this->DebugMessage("Login","[AttemptedLogin] Failed to unlock account: " . mysqli_error($this->DatabaseHandle));
				return false;
			}
		}
	return true;
	}

	/**************************************************************************************************************************
	 * Placeholder functions
	 **************************************************************************************************************************/

	/**
	 * This function can be declared via en extension of this class to enable programmer to customize what is done after successfull login.
     * <code>
	 * <?php
	 * class MyClass extends LoginBox {
	 * 	function CustomLoginWork() {
	 * 		// Send user to another site after successfull login.
	 * 	}
	 * }
	 * $TestVar = New MyClass($DatabaseConnection);
	 * ?>
	 * </code>
	 */
	protected function CustomLoginWork() {}
}
?>