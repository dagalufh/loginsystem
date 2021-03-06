<?php
include_once("Class.Abstract.LoginSystem.php");
/**************************************************************************************************************************
 * 	RegistrationBox
 **************************************************************************************************************************/
/**
 * Used to define the registrationhandler
 * This class contains the functions that controls the registration of a new user.
 *
 * Example of smallest application:
 * <code>
 * <?php
 * $TestVar = New RegistrationBox($databaseconnection);
 * if($TestVar->Register()) {
 * 	echo "Successful registration";
 * } else {
 * 	$TestVar->ShowBox();
 * }
 * ?>
 * </code>
 * @since Version 3.0
 *
 */
class RegistrationBox extends LoginSystem {
	/**
	 * Holds the new unique ID of the recently created user.
	 *
	 * @var int $NewUser
	 * @since Version 3.0
	 */
	protected $NewUser = "";

	/**
	 * This function builds the dialogbox that allows a user to register.
	 *
	 * Output can either be via return or via echo. Return allows the programmer to decide the output format.
	 * This can be called with:
	 * <code>
	 * $TestVar->ShowBox();
	 * </code>
	 * or:
	 * <code>
	 * $Buffert = $TestVar->ShowBox(true);
	 * echo $Buffert['FormStart'];
	 * echo $Buffert['Username'];
	 * echo $Buffert['Password'];
	 * echo $Buffert['RegistrationButton'];
	 * echo $Buffert['FormEnd'];
	 * echo $Buffert['Error']
	 * </code>
	 * @param boolean $Output toggles how the output should be displayed.
	 * @return array
	 * @since Version 3.0
	 */
	public function ShowBox($Output = false) {
		// Shows the registrationbox

		// Build the RegistrationBox.
		$RegistrationBoxOutput['FormStart']		 		= '<form method="POST" name="LoginSystemRegistrationForm" role="form" action="">';
		$RegistrationBoxOutput['Username'] 				= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="text" name="Username">';
		$RegistrationBoxOutput['Password'] 				= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="password" name="Password">';
		$RegistrationBoxOutput['PasswordRepeat'] 		= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="password" name="PasswordRepeat">';
		$RegistrationBoxOutput['RegistrationButton'] 	= '<input class="btn btn-default LoginSystemGeneral LoginSystemButton" type="submit" value="'.$this->GetLanguageSpecificText('Button_Registration').'" name="RegistrationBoxSubmit">';
		$RegistrationBoxOutput['FormEnd'] 				= '</form>';
		$RegistrationBoxOutput['Error']					= $this->GetUserFeedback(false);

		if ($this->AddedSecurity) {
			$RegistrationBoxOutput['UnlockSequenceQuestion'] 	= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="text" name="UnlockSequenceQuestion">';
			$RegistrationBoxOutput['UnlockSequenceAnswer'] 		= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="text" name="UnlockSequenceAnswer">';
		}

		if($Output == false) {
			// Output it directly via Echo

			
			echo $RegistrationBoxOutput['FormStart'];
			echo '<div class="panel panel-default">';
			echo '<div class="panel-body">';	
				echo "<div>";
					if(isset($this->LoginSystemMessage[3])) {
						echo "<span id='helpBlock' class='help-block bg-danger'>" . $this->GetUserFeedback(true) . "</span>";
					}
				echo "</div>";
				echo "<div class='form-group'>";
					echo "<label for='Username' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('Input_Username')."</label><div class='col-sm-10'>".$RegistrationBoxOutput['Username'] . "</div>";
				echo "</div>";
				echo "<div class='form-group'>";
					echo "<label for='Username' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('Input_Password') ."</label><div class='col-sm-10'>". $RegistrationBoxOutput['Password'] . "</div>";
				echo "</div>";
				echo "<div class='form-group'>";
					echo "<label for='Username' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('Input_PasswordRepeat') ."</label><div class='col-sm-10'>". $RegistrationBoxOutput['PasswordRepeat'] . "</div>";
				echo "</div>";
				if ($this->AddedSecurity) {
					echo "<div class='form-group'>";
						echo "<label for='Username' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('UnlockSequenceQuestion') ."</label><div class='col-sm-10'>". $RegistrationBoxOutput['UnlockSequenceQuestion'] . "</div>";
					echo "</div>";
					echo "<div class='form-group'>";
						echo "<label for='Username' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('UnlockSequenceAnswer') ."</label><div class='col-sm-10'>". $RegistrationBoxOutput['UnlockSequenceAnswer'] . "</div>";
					echo "</div>";
				}
				echo "<div class='form-group'>";
					echo "<div class='col-sm-offset-2 col-sm-10'>".$RegistrationBoxOutput['RegistrationButton'] . "</div>";
				echo "</div>";
			echo "</div>";
			echo $RegistrationBoxOutput['FormEnd'];
		
		} else {
			// Return to caller as an array.
			return $RegistrationBoxOutput;
		}
	}

	/**
	 * This function handles the registrationfunctions.
	 * @return boolean
	 */
	public function Register() {

		$EncryptedSecurityAnswer = "";
		$EncryptedPassword = "";

		if(!isset($_POST['RegistrationBoxSubmit'])) {
			return false;
		}

		unset($_POST['RegistrationBoxSubmit']);

		// Check if the provided username already exists
		$Usernames = mysqli_query($this->DatabaseHandle,"SELECT Username from Users");

		while($CurrentUsername=mysqli_fetch_array($Usernames)) {
			if( strtolower($CurrentUsername['Username']) == strtolower($_POST['Username']) ) {
				$this->DebugMessage("Registration","[UsernameVerification] Provided username already exists.");
				$this->AddUserFeedback($this->GetLanguageSpecificText('UsernameExsists'));
				return false;
			}
		}

		if( (!$this->CheckAllowedSymbols($_POST['Password'])) or (!$this->CheckAllowedSymbols($_POST['Username'])) ) {
			return false;
		}
		// Below commented out because of duplicate function of above.
		//if(! (preg_match("/\A".$this->AllowedSymbols."\z/",$_POST['Password'])) ) {
		//	$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidPasswordSymbol'));
		//	return false;
		//}

		//if(! (preg_match("/\A".$this->AllowedSymbols."\z/",$_POST['Username'])) ) {
		//	$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidUsernameSymbol'));
		//	return false;
		//}

		if (strlen($_POST['Password']) < $this->MinimumPasswordLength) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidPasswordLength'));
			return false;
		}

		if (strlen($_POST['Username']) < $this->MinimumInputFieldLength) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidUsernameLength'));
			return false;
		}

		foreach ($this->ArrayOfFields as $CurrentField) {
			if(isset($_POST[$CurrentField])) {
				$this->CustomValues .= ',"'. mysqli_real_escape_string($this->DatabaseHandle,$_POST[$CurrentField]).'"';
				$this->CustomTables .= ',' . $CurrentField;
			}
		}


		if($this->AddedSecurity) {
			if (strlen($_POST['UnlockSequenceQuestion']) < $this->MinimumInputFieldLength) {
				$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidQuestionLength'));
				return false;
			}
			if (strlen($_POST['UnlockSequenceAnswer']) < $this->MinimumInputFieldLength) {
				$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidAnswerLength'));
				return false;
			}
			$this->BuildQuery = "";
			foreach ($this->AddedTables as $AddedTable) {
				$this->BuildQuery = $this->BuildQuery . "," . $AddedTable;
			}
			$this->AppendTables = $this->BuildQuery;
			$EncryptedSecurityAnswer = SaltedPassword($_POST['UnlockSequenceAnswer'],strlen($_POST['UnlockSequenceAnswer']));
			$this->AppendValues = ',false,"0","' . mysqli_real_escape_string($this->DatabaseHandle,$_POST['UnlockSequenceQuestion']) . '","' . mysqli_real_escape_string($this->DatabaseHandle,$EncryptedSecurityAnswer).'"';
		}


		$EncryptedPassword = $this->GeneratePasswordFromForm($_POST['Password'], $_POST['PasswordRepeat']);
		if($EncryptedPassword !== false) {
			echo 'INSERT INTO Users(Username,Password'.$this->AppendTables.$this->CustomTables.') VALUES("'.mysqli_real_escape_string($this->DatabaseHandle,$_POST['Username']).'","'.$EncryptedPassword.'"'.$this->AppendValues . $this->CustomValues.')';
			if(mysqli_query($this->DatabaseHandle,'INSERT INTO Users(Username,Password'.$this->AppendTables.$this->CustomTables.') VALUES("'.mysqli_real_escape_string($this->DatabaseHandle,$_POST['Username']).'","'.$EncryptedPassword.'"'.$this->AppendValues . $this->CustomValues.')')) {
				$this->NewUser = mysqli_insert_id($this->DatabaseHandle);
				$this->DebugMessage("Registration", "[Success] Registration was successfull and a user has been created with ID: " . $this->NewUser);
			} else {
				$this->DebugMessage("MySQLi","An error has occured while creating user: " . mysqli_error($this->DatabaseHandle));
				return false;
			}

			$this->SuccessfullRegistration();
			return true;
		} else {
			return false;
		}
	}

	/**************************************************************************************************************************
	 * 	Placeholder functions
	 **************************************************************************************************************************/
	 /**
	  * This function can be declared in an extension of RegistrationBox class.
	  * <code>
	  * <?php
	  * class MyClass extends RegistrationBox {
	  * 	function SuccessfullRegistration() {
	  * 		// Send user to another site after successfull registration.
	  * 	}
	  * }
	  * $TestVar = New MyClass($DatabaseConnection);
	  * ?>
	  * </code>
	  */
	protected function SuccessfullRegistration() {}
}
?>