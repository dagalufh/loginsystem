<?php
include_once("Class.Abstract.LoginSystem.php");
/**************************************************************************************************************************
 * 	ResetPasswordBox
 **************************************************************************************************************************/
 /**
 * Used to define the ResetPasswordBox
 * This class contains the functions that control the reset of passwords.
 *
 * @since Version 4
 */
class ResetPasswordBox extends LoginSystem {
	/*
	What is needed!?
	*/
	
	/**
	 * This is used to define the path for the Requested Password reset link that is sent to the user.
	 * @since Version 3.43
	 */
	protected $ResetRequestPath = "";
	
	function __construct($dbhandle,$EnableLogOutput = false,$ParentClass = false) {
       parent::__construct($dbhandle,$EnableLogOutput,$ParentClass);
       $this->ResetRequestPath = $_SERVER["HTTP_HOST"] . $_SERVER['REQUEST_URI'];
   	}
	
	/**
	 * Set-function for the ResetRequestPath variable
	 * @var string $Path A valid HTTP link that can be sent to the user that does not require login to access.
	 * @since Version 3.43
	 */
	public function SetResetRequestPath($Path) {
		$this->ResetRequestPath = $Path;
	}
	
	
	public function ShowBox ($Output = false)
	{
		// Two-Part dialogbox!
		// First part:
		if ((isset($_GET['Resetkey'])) and (preg_match("/[0-2][0-9][0-5][0-9]/", $_GET['Resetkey']))) {
			// Format-Valid resetkey supplied. (Starts with 4 numbers, first 0 - 2, second 0-9, third 0-5, fourth 0-9)
			// Interface for resetting password based on link in email.
			// Ask for username and new password. Username and the ResetKey will be matched with database before new password is set.
			// ResetKey should contain a timestamp.	
			$PasswordRecoveryOutput['FormStart']				= '<form method="post" name="PasswordRecoveryForm" action="">';
			$PasswordRecoveryOutput['Username']					= '<input class="LoginSystemGeneral LoginSystemInputbox" type="text" name="Username">';
			$PasswordRecoveryOutput['NewPassword']				= '<input class="LoginSystemGeneral LoginSystemInputbox" type="password" name="NewPassword">';
			$PasswordRecoveryOutput['PasswordRepeat']			= '<input class="LoginSystemGeneral LoginSystemInputbox" type="password" name="PasswordRepeat">';
			$PasswordRecoveryOutput['PasswordRecoveryButton']	= '<input class="LoginSystemGeneral LoginSystemButton" type="submit" value="'.$this->GetLanguageSpecificText('Button_PasswordRecovery').'" name="PasswordRecoverySubmit">';
			$PasswordRecoveryOutput['FormEnd'] 					= '</form>';
			
			if (!$Output) {
				// Output it directly via Echo
				echo "<table>";
					echo $PasswordRecoveryOutput['FormStart'];
					if(isset($this->LoginSystemMessage[3])) {
						echo "<tr><td colspan='2'>".$this->GetUserFeedback(true). "</td></tr>";
					}
					echo "<tr><td>".$this->GetLanguageSpecificText('Input_Username')."</td><td>".$PasswordRecoveryOutput['Username'] . "</td></tr>";
					echo "<tr><td>".$this->GetLanguageSpecificText('Input_NewPassword') ."</td><td>". $PasswordRecoveryOutput['NewPassword'] . "</td></tr>";
					echo "<tr><td>".$this->GetLanguageSpecificText('Input_PasswordRepeat') ."</td><td>". $PasswordRecoveryOutput['PasswordRepeat'] . "</td></tr>";	
					echo "<tr><td colspan='2'>".$PasswordRecoveryOutput['PasswordRecoveryButton'] . "</td></tr>";
					echo $PasswordRecoveryOutput['FormEnd'];
				echo "</table>";
			} else {
				// Return to caller as an array.
				return $PasswordRecoveryOutput;
			}
		} else {
			// Second part:
			// Interface for requesting password reset
			// Ask for mail and username. Has to match database in order for the mail to be sent out.
			$PasswordRecoveryOutput['FormStart']				= '<form method="post" name="PasswordRecoveryForm" action="">';
			$PasswordRecoveryOutput['Username']					= '<input class="LoginSystemGeneral LoginSystemInputbox" type="text" name="Username">';
			$PasswordRecoveryOutput['Mail']						= '<input class="LoginSystemGeneral LoginSystemInputbox" type="text" name="Mail">';
			$PasswordRecoveryOutput['PasswordRecoveryButton']	= '<input class="LoginSystemGeneral LoginSystemButton" type="submit" value="'.$this->GetLanguageSpecificText('Button_PasswordRecovery').'" name="PasswordRecoverySubmit">';
			$PasswordRecoveryOutput['FormEnd'] 					= '</form>';	
	
			if (!$Output) {
				// Output it directly via Echo
				echo "<table>";
					echo $PasswordRecoveryOutput['FormStart'];
					echo "<tr><td>".$this->GetLanguageSpecificText('Input_Username')."</td><td>".$PasswordRecoveryOutput['Username'] . "</td></tr>";
					echo "<tr><td>".$this->GetLanguageSpecificText('Input_Mail') ."</td><td>". $PasswordRecoveryOutput['Mail'] . "</td></tr>";
					echo "<tr><td colspan='2'>".$PasswordRecoveryOutput['PasswordRecoveryButton'] . "</td></tr>";
					echo $PasswordRecoveryOutput['FormEnd'];
				echo "</table>";
			} else {
				// Return to caller as an array.
				return $PasswordRecoveryOutput;
			}			
		}
		

	}
	
	public function Verification () {
		try {
			// Check database
			$ResetRequestTime = new datetime();
			//$ResetRequestTimePastLimit = new datetime();
			//$ResetRequestTimePastLimit->sub(new DateInterval("PT20M"));
			//echo "WHERE ResetRequestedTime BETWEEN ".$ResetRequestTimePastLimit->format('Y-m-d H:i:s')." AND ".$ResetRequestTime->format('Y-m-d H:i:s');
			if ( isset($_POST['Mail'])) {
				// If Mail Post-variable exists, we come from RequestPasswordReset	
				echo "Received Mail Post";
				
				// Check that a valid mail was entered.
				if(! (preg_match("/\A[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}\z/i",$_POST['Mail'])) ) {
					$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidMailSymbol'));
					throw new exception("Incorrect Mail Symbols");
				}
				
				// Fetch from database based on username and mail.
				
				if($QueryResult = mysqli_query($this->DatabaseHandle, "SELECT Username, Mail FROM users WHERE Username='".mysqli_real_escape_string($this->DatabaseHandle,$_POST['Username'])."' AND Mail='".mysqli_real_escape_string($this->DatabaseHandle,$_POST['Mail'])."'")) {
					$QueryRow = mysqli_fetch_assoc($QueryResult);
				} else {
					throw new exception(mysqli_error($this->DatabaseHandle), 2);
				}
				
				
				if (isset($QueryRow['Username'])) {
					echo "A username was found!";
					$ResetKey = $this->GeneratePassword($ResetRequestTime->format("ymdhis") . $QueryRow['Username'] . rand(0,9999));
					echo "<br>".$ResetKey . "<br> and path: " . $this->ResetRequestPath . "<br>";
					if(count($_GET)>0) {
						$this->ResetRequestPath .= "&Resetkey=" . $ResetKey;
					} else {
						$this->ResetRequestPath .= "?Resetkey=" . $ResetKey;
					}
					
					$MailContent = $this->GetLanguageSpecificText('MailContent');
					$MailContent = preg_replace("/RESETKEYPATH/", $this->ResetRequestPath, $MailContent);
					
					// Replace inside $MailContent ResetKey with the resetkey, and path with the path.
					//mail($QueryRow['Mail'], $this->WebsiteTitle . "Password Recovery","Your password has been reset, either by request by you or systemadministrator.");
				}
	
				
			}
			
			if (isset($_POST['NewPassword'])) {
				// if NewPassword-Post is set, we come from SetNewPassword.
				echo "Received NewPassword Post";
			}
		} catch(exception $e) {
			// catch eventual errors
			
			if($e->getCode() == 2) {
				$this->DebugMessage("SQL","An SQL Error occured: " . $e->getMessage());
				$this->AddUserFeedback($this->GetLanguageSpecificText('Error_Database'));	
			}
		}		
	}
}

/*
 * You can customize what happends after successfull login by extending LoginBox and creating a function called: CustomLoginWork();
 * Example:
 * 	class MyLoginSystem extends LoginBox {
	 * function CustomLoginWork() {
		*  // Something to do after a login.
		* }
	 }*
 *	And then you use that class instead $LoginSystem = new MyLoginSystem($Databasehandle);
 *
 * See Docs/Example.php for a few examples.
 */
//require($_SERVER['DOCUMENT_ROOT']."modules/Crypt.php");
?>