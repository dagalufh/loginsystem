<?php
include_once("Class.Abstract.LoginSystem.php");
/**************************************************************************************************************************
 * 	ChangePasswordBox
 **************************************************************************************************************************/
/**
 * Used to define the password changer
 * This class contains the functions that can change a users password.
 *
 * Example of smallest application:
 * <code>
 * <?php
 * $TestVar = New ChangePasswordBox($databaseconnection);
 * if($TestVar->ChangePassword()) {
 * 	echo "Successfully changed password.";
 * } else {
 * 	$TestVar->ShowBox();
 * }
 * ?>
 * </code>
 * @since Version 3.3
 *
 */
class ChangePasswordBox extends LoginSystem {
	
	/**
	 * This function builds the dialogbox that allows the user to change password.
	 * @param boolean $Output controls if the function should output directly or return via array.
	 * @return array
	 */ 
	public function ShowBox($Output = false) {
		// Shows the registrationbox

		// Build the RegistrationBox.
		$ChangePasswordBoxOutput['FormStart']		 			= '<form method="POST" name="LoginSystemChangePasswordForm" class="form-horizontal" role="form" action="">';
		$ChangePasswordBoxOutput['OldPassword'] 				= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="password" name="OldPassword">';
		$ChangePasswordBoxOutput['NewPassword'] 				= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="password" name="NewPassword">';
		$ChangePasswordBoxOutput['PasswordRepeat'] 				= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="password" name="PasswordRepeat">';
		$ChangePasswordBoxOutput['ChangePasswordButton'] 		= '<input class="btn btn-default LoginSystemGeneral LoginSystemButton" type="submit" value="'.$this->GetLanguageSpecificText('Button_ChangePassword').'" name="ChangePasswordBoxSubmit">';
		$ChangePasswordBoxOutput['FormEnd'] 					= '</form>';
		$ChangePasswordBoxOutput['Error']						= $this->GetUserFeedback(false);

		if ($this->AddedSecurity) {
			$ChangePasswordBoxOutput['UnlockSequenceQuestion'] 	= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="text" name="UnlockSequenceQuestion">';
			$ChangePasswordBoxOutput['UnlockSequenceAnswer'] 	= '<input class="form-control LoginSystemGeneral LoginSystemInputbox" type="text" name="UnlockSequenceAnswer">';
		}

		if(!$Output) {
			// Output it directly via Echo
			echo $ChangePasswordBoxOutput['FormStart'];
			echo '<div class="panel panel-default">';
				echo '<div class="panel-body">';
					echo "<div>";
						if(isset($this->LoginSystemMessage[3])) {
							echo "<span id='helpBlock' class='help-block bg-danger'>" . $this->GetUserFeedback(true) . "</span>";
						}
					echo "</div>";
					echo "<div class='form-group'>";
						echo "<label for='OldPassword' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('Input_OldPassword')."</label><div class='col-sm-10'>".$ChangePasswordBoxOutput['OldPassword'] . "</div>";
					echo "</div>";
					echo "<div class='form-group'>";
						echo "<label for='NewPassword' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('Input_NewPassword') ."</label><div class='col-sm-10'>". $ChangePasswordBoxOutput['NewPassword'] . "</div>";
					echo "</div>";
					echo "<div class='form-group'>";	
						echo "<label for='PasswordRepeat' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('Input_PasswordRepeat') ."</label><div class='col-sm-10'>". $ChangePasswordBoxOutput['PasswordRepeat'] . "</div>";
					echo "</div>";
						if ($this->AddedSecurity) {
							echo "<div class='form-group'>";
								echo "<label for='UnlockSequenceQuestion' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('UnlockSequenceQuestion') ."</label><div class='col-sm-10'>". $ChangePasswordBoxOutput['UnlockSequenceQuestion'] . "</div>";
							echo "</div>";
							echo "<div class='form-group'>";
								echo "<label for='UnlockSequenceAnswer' class='col-sm-2 control-label'>".$this->GetLanguageSpecificText('UnlockSequenceAnswer') ."</label><div class='col-sm-10'>". $ChangePasswordBoxOutput['UnlockSequenceAnswer'] . "</div>";
							echo "</div>";
						}
					echo "<div class='form-group'>";
						echo "<div class='col-sm-offset-2 col-sm-10'>".$ChangePasswordBoxOutput['ChangePasswordButton'] . "</div>";
					echo "</div>";
				echo "</div>";
			echo "</div>";
			echo $ChangePasswordBoxOutput['FormEnd'];
		} else {
			// Return to caller as an array.
			return $ChangePasswordBoxOutput;
		}
	}
		
	/**
	 * This function performs the actual password change given that the conditions are met first.
	 */
	public function ChangePassword() {
		if(!isset($_POST['ChangePasswordBoxSubmit'])) {
			return false;
		} else {
			/**
			 * 
			 * Verify correct/valid new password supplied.
			 * run it through the salting and update database.
			 * Also, have a custom function at the end on success and also on fail.
			 * 
			 *  How will this work? Think it through!
			 *  
			 *  Build the SQL-query if there is any CustomTables added to the ArrayOfFields.
			 *  Check if user has also entered an old password. If that is not included, ignore passwordchange?
			 *  	Perhaps check if user has entered old or new password first, then check if they match and
			 * 		continue with the password reset.
			 * 	Continue with the SQL-Query and add the new password.
			 *  Build a function that handles the new password (Verify entered password is valid, generate new password, return new password. Allows for same usage of Change Password and Register.)
			 *  Execute the SQL-Query and return true.
			 */ 
			
			if(strlen($_POST['OldPassword'])<1) {
				$this->AddUserFeedback($this->GetLanguageSpecificText('OldPasswordNotSupplied'));
				return false;
			}
			
			// Check that there is a valid mysqli database connection.
			if( (is_object($this->DatabaseHandle)) and (get_class($this->DatabaseHandle) == 'mysqli') ) {
				// Attempt to fetch userinformation.
				if( $QueryResult = mysqli_query($this->DatabaseHandle, "SELECT Password FROM Users WHERE Username='".mysqli_real_escape_string($this->DatabaseHandle,$_SESSION['Username'])."'") ) {
					$QueryRow = mysqli_fetch_assoc($QueryResult);
				}
			} 
			
			// Set the salt length to same as current password.
			$this->VerifySaltLength($_POST['OldPassword']);
			
			// If the old password was incorrect, return false.
			if(!SaltedPassword($_POST['OldPassword'],$this->SaltLength,$QueryRow['Password'])) {
				$this->DebugMessage("ChangePassword","Supplied old passwords did not match");
				$this->AddUserFeedback($this->GetLanguageSpecificText('OldPasswordMissmatch'));	
				return false;
			} else {
				// If they do match, continue checking the new password.
				$this->DebugMessage("ChangePassword","Supplied old passwords match");
				
				$EncryptedPassword = $this->GeneratePasswordFromForm($_POST['NewPassword'], $_POST['PasswordRepeat']);
	
				
				if ($_POST['PasswordRepeat'] !== $_POST['NewPassword']) {
					$this->AddUserFeedback($this->GetLanguageSpecificText('NewPasswordUnmatched'));	
					return false;
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
		
					$EncryptedSecurityAnswer = SaltedPassword($_POST['UnlockSequenceAnswer'],strlen($_POST['UnlockSequenceAnswer']));					
					$this->BuildQuery = ',' . $AddedTable[2] . '="' . mysqli_real_escape_string($this->DatabaseHandle,$_POST['UnlockSequenceQuestion']).',' . $AddedTable[3] . '="' . mysqli_real_escape_string($this->DatabaseHandle,$_POST['UnlockSequenceAnswer']).'"';
				
				}
				
				//$EncryptedPassword = $this->GeneratePassword($_POST['NewPassword']);
				
				if(mysqli_query($this->DatabaseHandle,'UPDATE Users SET Password="'.$EncryptedPassword.'"'.$this->BuildQuery . ' WHERE UserID="'.$_SESSION[$this->Session_UserID].'"')) {				
					$this->DebugMessage("Registration", "[Success] Password changed for a user.");
					$this->SuccessfullPasswordChange();
					return true;
				} else {
					$this->DebugMessage("MySQLi","An error has occured while changing password for user: " . mysqli_error($this->DatabaseHandle));
					$this->FailedPasswordChange();
					return false;
				}
							
				
			}
			
			return false;
		}
	}
	
	public function ChangePasswordTC() {
		// Rebuild Change Password with Try Catch
			try {
				// Verify that the Submit button has been used.
				if(!isset($_POST['ChangePasswordBoxSubmit'])) {
					throw new exception("ChangePasswordBoxSubmit was not pressed.",99);
				}
				
				// Did the user supply an old password?
				if (strlen($_POST['OldPassword'])>1) {
					// Check that there is a valid mysqli database connection.
					if( (is_object($this->DatabaseHandle)) and (get_class($this->DatabaseHandle) == 'mysqli') ) {
						// Attempt to fetch userinformation.
						if( $QueryResult = mysqli_query($this->DatabaseHandle, "SELECT Password FROM Users WHERE Username='".mysqli_real_escape_string($this->DatabaseHandle,$_SESSION['Username'])."'") ) {
							$QueryRow = mysqli_fetch_assoc($QueryResult);
						}
					} else {
						throw new exception("Invalid connection to the database.");
					}
					
					// Set the salt length to same as current password.
				
					$this->VerifySaltLength($_POST['OldPassword']);
					
					// Check that the userprovided password match the one already stored in the database.
				
					if(!SaltedPassword($_POST['OldPassword'],$this->SaltLength,$QueryRow['Password'])) {
						$this->DebugMessage("ChangePassword","Supplied old passwords did not match");
						//$this->AddUserFeedback($this->GetLanguageSpecificText('OldPasswordMissmatch'));	
						throw new exception("OldPasswordMissmatch");
					}
					$this->DebugMessage("ChangePassword","Supplied old passwords match");
					
					if (strlen($_POST['NewPassword'])>1) {
						$EncryptedPassword = $this->GeneratePasswordFromForm($_POST['NewPassword'], $_POST['PasswordRepeat']);
						if($EncryptedPassword === false) {
							throw new exception("GeneratePasswordFromForm returned false.", 99);
						}
						if(strlen($this->BuildQuery)>1) {
							$this->BuildQuery .= ',';
						}
						$this->BuildQuery = 'Password="'.$EncryptedPassword.'"';
					}
					
					// Are HigherSecurity enabled? This does not depend on passwordchange actually. You can just change your question/answer anyway.
					if($this->AddedSecurity) {
						if (strlen($_POST['UnlockSequenceQuestion'])>1) {
							
							if (strlen($_POST['UnlockSequenceQuestion']) < $this->MinimumInputFieldLength) {
								//$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidQuestionLength'));
								throw new exception("InvalidQuestionLength");
							}

							if (strlen($_POST['UnlockSequenceAnswer']) < $this->MinimumInputFieldLength) {
								//$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidAnswerLength'));
								throw new exception("InvalidAnswerLength");
							}

							$EncryptedSecurityAnswer = SaltedPassword($_POST['UnlockSequenceAnswer'],strlen($_POST['UnlockSequenceAnswer']));					
							if(strlen($this->BuildQuery)>1) {
								$this->BuildQuery .= ',';
							}
							$this->BuildQuery .= $this->AddedTables[2] . '="' . mysqli_real_escape_string($this->DatabaseHandle,$_POST['UnlockSequenceQuestion']).',' . $this->AddedTables[3] . '="' . mysqli_real_escape_string($this->DatabaseHandle,$EncryptedSecurityAnswer).'"';
						}
					}

					// Are there any CustomFields?

					// Update the database with the new information.
					if(strlen($this->BuildQuery)>1) {
						echo 'UPDATE Users SET '.$this->BuildQuery . ' WHERE UserID="'.$_SESSION[$this->Session_UserID].'"'. "<br>";
					}
				}
			} catch (exception $e) {
				if($e->getCode() != 99) {
					//echo "Exception: " . $e->getMessage() . "<br>";
					if($this->GetLanguageSpecificText($e->getMessage()) == "Label Not Found") {
						$this->AddUserFeedback($e->getMessage());
					} else {
						$this->AddUserFeedback($this->GetLanguageSpecificText($e->getMessage()));
					}
				}
			}
	}
	
	/**************************************************************************************************************************
	 * 	Placeholder functions
	 **************************************************************************************************************************/
	 /**
	  * This function can be declared in an extension of ChangePasswordBox class.
	  * <code>
	  * <?php
	  * class MyClass extends ChangePasswordBox {
	  * 	function SuccessfullPasswordChange() {
	  * 		// Send user to another site after successfull password change.
	  * 	}
	  * }
	  * $TestVar = New MyClass($DatabaseConnection);
	  * ?>
	  * </code>
	  */
		protected function SuccessfullPasswordChange() {}
		
	 /**
	  * This function can be declared in an extension of ChangePasswordBox class.
	  * <code>
	  * <?php
	  * class MyClass extends ChangePasswordBox {
	  * 	function FailedPasswordChange() {
	  * 		// Send user to another site after a failed password change.
	  * 	}
	  * }
	  * $TestVar = New MyClass($DatabaseConnection);
	  * ?>
	  * </code>
	  */
		protected function FailedPasswordChange() {}		
}
?>