<?php
/**
 * LoginSystem (This DocBlock is not seen by APIGen)
 *
 * These classes are for Login and Registration functions. To enable an easy implementation.
 *
 * This module for loginhandeling requires a database with a "Users" table looking as follows:
 *
 * Users {
 * 		UserID (int(11), Primary Key, Auto-Increment)
 * 		Username (varchar(255))
 * 		Password (varchar(255)) (Stored encrypted in database)
 * 		SecuritySequence(varchar(255))
 * 		AccessLevel(int(11))
 * 		Mail (varchar(255))										// Added in Version 3.42
 * 		ResetKey (varchar(100))									// Added in Version 3.43
 * 		ResetRequested (int(1))									// Added in Version 3.43
 * 		ResetRequestedTime (datetime)							// Added in Version 3.43
 *
 * 		Locked(int)												// Only for HigherSecurity
 * 		AttemptedLogins(int)									// Only for HigherSecurity
 * 		SecurityQuestion(text)									// Only for HigherSecurity
 * 		SecurityAnswer(text)	(Stored encrypted in database)	// Only for HigherSecurity
 * 		}
 * 
 * Changelog
 * Version 4.0
 * Split the system into multiple class files.
 * Changelogs will be appearing in the relevant class files.
 * 
 * Version 3.43
 * Started implementing PasswordRecoverybox
 * Added $WebsiteTitle to hold the name of the website and get/set functions for this.
 * 
 * Version 3.42
 * Added Check-functions for AllowedSymbols, MinimumPasswordLength and MinimumInputLength. These checks
 * were done in a redundant maner before. Now a more streamlined, clearer, easier to maintain way.
 * Started implementing GeneratePasswordFromForm($NewPassword)
 * Added function "EchoArray" that iterates a array and echos it.
 * 
 * Version 3.41
 * Added GET-functions for settings
 * Added function to import settings from another instans of LoginSystem classes.
 *
 * Version 3.4
 * Added function to add translations from runtime via AddLanguageDefintion.
 * 
 * Version 3.3
 * Added ChangePasswordBox class - Fully implemented.
 * Made some adjustments to array calls to avoid warnings about undefined index.
 * Added function to LoginSystem to be able to control LogOutput(true/false)
 * Corrected an issue with undefinced variable $QueryRow['Locked'] by verifying that HigherSecurity is set.
 * Implemented GetLanguageSpecificText($Label) that returns the post from the language array based on Label.
 * 	Falls back on default language if asked language text is not found for the selected language set via SetLanguage.
 * $AddedTables2 has been removed.
 * $AddedTables has been converted to an array
 * Fixed an error that locked VerifySaltLength. Now Working as intended.
 * Implemented $SaltSetByUser, to not update saltlength if user has defined one.
 * 
 * Version 3.2
 * __Construct removed from childs (LoginBox and RegistrationBox).
 *
 * Version 3.1
 * Modified all debug outputs to also include trigger_error, defaults to e_user_error
 *
 * Version 3
 * Registration is added.
 *
 * Version 2.5
 * Added an abstract class to enable continous development and reuse of variables/functions.
 *
 * Version 2 of the LoginBox.
 * Built with Objectoriented programming in mind.
 *
 * @version Version 3.4
 * @package LoginSystem
 * @author Mikael Aspehed <Mikael@aspehed.se>
 *
 * @todo 1 Add function to define session timeout.
 * @todo 2 Verify all userinput with mysqli_real_escape_string
 * @todo 3 Log failed logins
 * @todo 4 Add HigherSecurity option; Case sensitive usernames.
 * @todo 5 Add Repeat password to RegistrationBox
 * @todo 6 Add more gracius error handling. (What if a table does not exist?)
 * @todo 7 Add CustomTables capabilities to ChangePasswordBox
 * @todo 8 Add functions for recovery of passwords. Add ForceReset, ResetKey, ResetPath(? Should this be via settings/Config?) to Users table in Database.
 * 		   Also, add function to send email to user with ResetKey if ForceReset is set. Go to current page, define a overlay
 * 		   in ShowBox LoginBox to show the ChangePassword form. This will probably work best as a own subclass.
 * 
 * 		   Add ResetPasswordPath variable and get/set functions
 * 
 * 
 * 
 * THOUGHTS:
 * 
 * How to handle errors etc?
 * Have a function called instead of Return false to break so it dosn't continue any further?
 * 
 * Try-Catch on MySQL Queries?
 */

/**
 * Inlusion of Crypt.php
 *
 * This file handles the encryption of passwords, securityanswers and securitysequence.
 * @since Version 1.0
 */
require_once("Dependency/Crypt.php");

/**
 * This class contains functions and variables shared among the other 3 classes.
 *
 * @since Version 2.5
 * @abstract
 */
abstract class LoginSystem {
	/*************************************************************************************************************************
	 * Definition of variables
	 *************************************************************************************************************************/
	/**
	 * Stores additional tables.
	 * @var string $AddedTables
	 */
	protected $AddedTables = array();

	/**
	 * Specifies if the additional security is enabled or not.
	 * @var boolean $AddedSecurity
	 */
	protected $AddedSecurity = false;
	
	/**
	 * String containing the regex with alloed symbols.
	 * @var string $AllowedSymbols
	 * @since Version 3.0
	 */
	protected $AllowedSymbols = "[\p{L}\p{P}\p{N}\p{S}]+";
	
	/**
	 * Contains the constructed additionas values in the case of HigherSecurity.
	 *
	 * @var string $AppendValues
	 * @since Version 3.0
	 */
	protected $AppendValues = "";
	
	/**
	 * A holder for the array of custom fields for the registrationform.
	 *
	 * @var array $ArrayOfFields
	 * @since Version 3.0
	 */
	protected $ArrayOfFields = array();	
	
	/**
	 * Used to build queries for additional security.
	 * @var string $BuildQuery
	 * @since Version 3.3
	 */
	protected $BuildQuery = "";
	
	/**
	 * Contains the finished constructed CustomTables that will be appended in the MySQLi query.
	 *
	 * @var string $CustomTables
	 * @since Version 3.0
	 */
	protected $CustomTables = "";
	
	/**
	 * Contains the finished constructed CustomValues that will be appended in the MySQLi query.
	 *
	 * @var boolean $CustomValues
	 * @since Version 3.0
	 */
	protected $CustomValues = "";
	
	/**
	 * Hold the databaseconnection.
	 * @var mysqli $Databasehandle
	 */
	protected $DatabaseHandle = "";
	
	/**
	 * Controls if the script should show any output in error_log
	 * @var boolean $EnableLogOutput
	 */
	protected $EnableLogOutput = false;

	/**
	 * Hold the selected languagecode.
	 * @var string $Language
	 */
	protected $Language = "en";

	/**
	 * Holds the targeted languagefile.
	 * @var string $Languagefile
	 */
	protected $LanguageFile = "/LoginSystemLanguage.txt";

	/**
	 * Location of the languagefile.
	 *
	 * This is defined to dirname($_SERVER['SCRIPT_FILENAME']) when a new instance is created.
	 * @var string $LanguageDirectory
	 */
	protected $LanguageDirectory = "";

	/**
	 * Holds the generated Messages to be displayed either to user or debug.
	 * @var array $LoginSystemMessage
	 */
	protected $LoginSystemMessage = array();

	/**
	 * Contains the text in separate subarrays ordered by language.
	 * @var array $LoginSystemText
	 */
	protected $LoginSystemText = array();
	
	/**
	 * Hold the value for the allowed minimumlength of the passwords.
	 * @var int $MinimumPasswordLength
	 * @since Version 3.0
	 */
	protected $MinimumPasswordLength = 8;
	
	/**
	 * Holds the allowed minimum length of Username, Unlocksequencequestion and answer inputfield. This is to prevent empty fields.
	 *
	 * @var int $MinimumInputFieldLength
	 * @since Version 3.0
	 */
	protected $MinimumInputFieldLength = 3;	

	/**
	 * Holds the amount of the salt.
	 * @var int $SaltLength
	 */
	protected $SaltLength = 0;
	
	/**
	 * Defines if salt has been defined by user
	 * @var boolean $SaltSetByUser
	 * @since Version 3.3
	 */
	protected $SaltSetByUser = false;

	/**
	 * Name of the global identifier of the currently logged in user.
	 * @var string $Session_UserID
	 */
	protected $Session_UserID = "UserID";
	
	/**
	 * Used to hold the name of the website where this system is used. This is used when resetting passwords.
	 * @var string $WebsiteName
	 * @since Version 3.43
	 */
	protected $WebsiteTitle = "";

	/**
	 * Sets up the class with predefined values.
	 *
	 * @param mysqli $dbhandle A MySQLi connection handle.
	 * @param boolean $EnableLogOutput Controls if the script should output to PHP-log or not.
	 * @param LoginSystem $ParentClass Used to import settings from another LoginSystem class instans. (Added in 3.41)
	 * @since Version 2.5
	 */
	function __construct($dbhandle,$EnableLogOutput = false,$ParentClass = false) {
	
		$this->LogOutput($EnableLogOutput);
		$this->DatabaseHandle = $dbhandle;
		$this->LanguageDirectory = dirname($_SERVER['SCRIPT_FILENAME']);
		
		$this->LoginSystemMessage[0] = null;
		$this->LoginSystemMessage[2] = null;
		$this->LoginSystemMessage[3] = array();
		
		$this->DefineDefaultLanguage();
		$this->DebugMessage("Classdefinition","Class (". __CLASS__ .") has been instantiated");
		
		if ($ParentClass !== false) {
			
			$this->SetAllowedSymbols($ParentClass->GetAllowedSymbols());
			$this->SetLanguage($ParentClass->GetLanguage(),false);
			$this->SetSaltLength($ParentClass->GetSaltLength());
			$this->SetSessionUserID($ParentClass->GetSessionUserID());
			$this->SetMinimumInputFieldLength($ParentClass->GetMinimumInputFieldLength());
			$this->SetMinimumPasswordLength($ParentClass->GetMinimumPasswordLength());
			$this->DebugMessage("Classdefinition","Loaded settings from ParentClass.");
		}
	}

	/*************************************************************************************************************************
	 * Definition of public functions
	 *************************************************************************************************************************/
	/**
	 * Used to add a language definition to LoginSystemText
	 * 
	 * @param string $LanguageCode eg. "en"
	 * @param string $TextTitle eg. "AccessLevel"
	 * @param string $Text eg. "Not Authorized"
	 * @access public
	 * @since Version 3.4
	 */
	public function AddLanguageDefinition($LanguageCode, $TextTitle, $Text) {
		$this->LoginSystemText[$TextTitle][$LanguageCode] = $Text;		
	}
	
	/**
	 * This function allows the programmer to pass aditional fields that shuld be included in the Insert sql query.
	 *
	 * There must be a corresponding inputfield to each column name.
	 * <code>
	 * <?php
	 * $TestVar->CustomFields(array("Field1","Field2"));
	 * ?>
	 * <input type="text" name="Field1">
	 * <input type="text" name="Field2">
	 * </code>
	 * @param array $ArrayOfFields an array of fields in the table that is an extension of the default for the class.
	 * @return boolean
	 * @since Version 3.0
	 */
	public function CustomFields($ArrayOfFields) {
		// The input fields needs to have the same name as the tablefields.
		// This should only be used if there is additional input fields.
		if(is_array($ArrayOfFields)) {
			$this->ArrayOfFields = $ArrayOfFields;
		} else {
			$this->DebugMessage("CustomFields","[ArrayOfFields] Argument needs to be an array.");
			return false;
		}
	}
	
		
	/**
	 * Used to generate passwords that are compatible with this loginsystem.
	 * @param string $NewPassword contains the password to be encrypted.
	 * @access public
	 */
	public function GeneratePassword($NewPassword) {
		$this->VerifySaltLength($NewPassword);
		return SaltedPassword($NewPassword,$this->SaltLength);
	}
	
	/**
	 * Used to create a password from forms (RegistrationBox and ChangePasswordBox)
	 * @param string $NewPassword contains the password to be checked and encrypted.
	 * @access public
	 * @return string generated password
	 * @since Version 3.42
	 */
	public function GeneratePasswordFromForm($NewPassword, $NewPasswordRepeat) {
		/* Check if the new password fullfills the requirements */
		if (strlen($NewPassword) < $this->MinimumPasswordLength) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidPasswordLength'));
			return false;
		}
		
		if (!$this->CheckAllowedSymbols($NewPassword)) {
			return false;
		}
		
		if (strcmp($NewPassword,$NewPasswordRepeat) !== 0) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('NewPasswordUnmatched'));	
			return false;	
		}
		
		/* Generate the new encrypted password and return it. */
		return $this->GeneratePassword($NewPassword);
	}
	
	/**
	 * Returns the settings for AllowedSymbols.
	 * @access public
	 * @since Version 3.41
	 */
	public function GetAllowedSymbols() {
		return $this->AllowedSymbols;
	}
	
	/**
	 * Return the selected languagecode.
	 * @access public
	 * @since Version 3.41
	 */ 
	public function GetLanguage() {
		return $this->Language;
	}

	/**
	 * Used to get text based on the current language and supplied label.
	 * @param string $Label The label of the text requested. Example: LoginIssues or Button_Login
	 * @return string
	 * @access public
	 * @since Version 3.3
	 */
	public function GetLanguageSpecificText($Label) {		
		if( isset($this->LoginSystemText[$Label][$this->Language]) ) {
			return $this->LoginSystemText[$Label][$this->Language];
		} elseif (isset($this->LoginSystemText[$Label]['en']) ) {
			return $this->LoginSystemText[$Label]['en'];
		} else {
			$this->DebugMessage("Language","Unable to find the requested Label in selected(".$this->Language.")/default(en) language: " . $Label);
		}
	}
	
	/**
	 * Returns the minimum length of inputfields.
	 * @access public
	 * @since Version 3.41
	 */
	public function GetMinimumInputFieldLength() {
		return $this->MinimumInputFieldLength;
	}
	
	/**
	 * Returns the minimum length of passwords
	 * @access public
	 * @since Version 3.41
	 */
	public function GetMinimumPasswordLength() {
		return $this->MinimumPasswordLength;
	}
	
	/**
	 * Returns the defined saltlength
	 * @access public
	 * @since Version 3.41
	 */ 
	public function GetSaltLength() {
		return $this->SaltLength;
	}
	
	/**
	 * Returns the value of the unique identifier for this session.
	 * @access public
	 * @since Version 3.41
	 */
	public function GetSessionUserID() {
		return $this->Session_UserID;
	}
	
	/**
	 * Used to fetch the messages for the user.
	 * @param boolean $OutputViaEcho Controlls if the function should echo directly or just return the complete array.
	 * 
	 * @access public
	 * @since Version 3.3
	 */
	public function GetUserFeedback($OutputViaEcho = false) {
		
		if($OutputViaEcho) {
			foreach($this->LoginSystemMessage[3] as $Message) {
				echo $Message . "<br>";	
			}
		} else {
			return $this->LoginSystemMessage[3];	
		}
	}	

	/**
	 * Used to enable heigher security
	 *
	 * Adds tables to the queries (Locked, AttemptedLogins, SecurityQuestion and SecurityAnswer)
	 *
	 * @access public
	 * @since Version 1.5
	 */
	public function HigherSecurity() {
		$this->DebugMessage("Security","Higher Security has been enabled.");
		//Deprecated: $this->AddedTables = ", Locked, AttemptedLogins, SecurityQuestion, SecurityAnswer";
		array_push($this->AddedTables,"Locked");
		array_push($this->AddedTables,"AttemptedLogins");
		array_push($this->AddedTables,"SecurityQuestion");
		array_push($this->AddedTables,"SecurityAnswer");
		$this->AddedSecurity = true;
	}
	
	/**
	 * Used to enable to disable output to the error_log
	 * @param boolean $Switch Contains true or false.
	 * 
	 * @access public
	 * @since Version 3.3
	 */
	public function LogOutput ($Switch) {
		$this->EnableLogOutput = $Switch;	
	} 	
	
	/**
	 * Used to show the debug information. Only use in development!
	 * @since Version 1.0
	 */
	public function ShowDebug($FriendlyOutput = false) {
		if ($FriendlyOutput) {
			$this->EchoArray($this->LoginSystemMessage);
		} else {
			print_r($this->LoginSystemMessage);
		}
	}
	
	/**
	 * Allows the programmer to change the allowed symbols for passwords and usernames.
	 * @param string $Regex String of regularexpressions.
	 * @return boolean
	 * @since Version 3.0
	 */
	public function SetAllowedSymbols($Regex) {
		if(preg_match("/".$Regex."/",null) === false) {
			$this->DebugMessage("SetAllowedSymbols","Incorrect regular expression");
			return false;
		}
		$this->AllowedSymbols = $Regex;
		return true;
	}	

	/**
	 * Used to set the language to use in user outputs.
	 *
	 * @param string $LanguageCode Contains a code representing the language. i.e: en or se
	 * @param boolean $LocalFile Controls whether the class should search for the languagefile in the modules directory or the including scripts directory.
	 * @since Version 1.5
	 */
	public function SetLanguage ($LanguageCode, $LocalFile = true) {
		if(!$LocalFile) {
			$this->LanguageDirectory = dirname(__FILE__);
		}
		$this->Language_Change($LanguageCode);
	}
	
	/**
	 * Allows the programmer to change the minimum username,securityquestion and answer length.
	 * @param int $Length
	 * @since Version 3.0
	 */
	public function SetMinimumInputFieldLength($Length) {
		$this->MinimumInputFieldLength = $Length;
	}
	
	/**
	 * Allows the programmer to change the minimum password length. As long as it is longer than MinimumInputFieldLength.
	 * @param int $Length
	 * @since Version 3.0
	 */
	public function SetMinimumPasswordLength($Length) {
		if($Length<$this->MinimumInputFieldLength) {
			$Length = $this->MinimumInputFieldLength;
		}
		$this->MinimumPasswordLength = $Length;
	}	
	
	/**
	 * Used to set the amount of salt to be used.
	 *
	 * @param int $Length The amount of salt expressed in numbers.
	 */
	public function SetSaltLength ($Length) {
		$this->SaltLength = $Length;
		$this->SaltSetByUser = true;
	}

	/**
	 * Sets the identifier global session variablename
	 *
	 * @param string $NewIdentifier
	 * @since Version 2.5
	 */
	public function SetSessionUserID ($NewIdentifier) {
		$this->Session_UserID = $NewIdentifier;
	}	

	/*************************************************************************************************************************
	 * Definition of private and protected functions
	 *************************************************************************************************************************/
	/**
	 * Used to organize all the feedback that is supposed to go back to the user.
	 * @param string $Message The inteded message, added at the end of the array.
	 * @since Version 3.3
	 */
	protected function AddUserFeedback($Message) {
		array_push($this->LoginSystemMessage[3],$Message);
	}	 
	
	/**
	 * Used to verify that a string contains valid symbols.
	 * @param string $StringToCheck The input value to validate.
	 * @since Version 3.42
	 * @access protected
	 */ 
	protected function CheckAllowedSymbols($StringToCheck) {
		if(! (preg_match("/\A".$this->AllowedSymbols."\z/",$StringToCheck)) ) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidPasswordSymbol'));
			return false;
		}
		return true;
	}
	
	/**
	 * Used to verify that a string follows the rules for length of a password.
	 * @param string $StringToCheck The input value to validate.
	 * @since Version 3.42
	 * @access protected
	 */ 	
	protected function CheckMinimumPasswordLength($StringToCheck) {
		if (strlen($StringToCheck) < $this->MinimumPasswordLength) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidPasswordLength'));
			return false;
		}
		return true;
	}

	/**
	 * Used to verify that a string follows the rules for length of a input field.
	 * @param string $StringToCheck The input value to validate.
	 * @since Version 3.42
	 * @access protected
	 */ 	
	protected function CheckMinimumInputLength($StringToCheck) {
		if (strlen($StringToCheck) < $this->MinimumInputFieldLength) {
			$this->AddUserFeedback($this->GetLanguageSpecificText('InvalidUsernameLength'));
			return false;
		}
		return true;
	}

	
	/**
	 * Used to channel debug messages both to the PHP-log file and to the LoginSystemMessage array.
	 *
	 * @param string $Category Used to categorize for easy reading
	 * @param string $Message the message in text
	 * @param string $Type the Error type that it should flag. Default to E_USER_NOTICE
	 * @since Version 3.1
	 */
	protected function DebugMessage($Category,$Message,$Type = E_USER_NOTICE) {
		if(!isset($this->LoginSystemMessage[0][$Category])) {
			$this->LoginSystemMessage[0][$Category] = null;
		}
		
		$this->LoginSystemMessage[0][$Category][count($this->LoginSystemMessage[0][$Category])] = $Message;
		
		if($this->EnableLogOutput) {
			trigger_error("[".$Category."] " . $Message, $Type);
		}
	}

	/**
	 * Sets up the dafault texts in english.
	 * Example of LoginSystemLanguage.txt:
	 * <code>
	 * <se>
	 *		LoginIssues=Felaktiga inloggningsuppgifter.
	 *		NotLoggedIn=Ej inloggad.
	 *		AccessLevel=Ej behörig.
	 *		UnlockSequenceQuestion=Säkerhetsfråga:
	 *		UnlockSequenceAnswer=Svar:
	 *		AccountLocked=Kontot är låst.
	 *		IncorrectSecurityAnswer=Felaktigt svar på säkerhetsfrågan.
	 *		Button_Login=Logga In
	 *		Button_Registration=Skapa Konto
	 *		Input_Username=Användarnamn:
	 *		Input_Password=Lösenord:
	 *		InvalidPasswordSymbol=Ogiltiga tecken i lösenordet.
	 *		InvalidUsernameSymbol=Ogiltiga tecken i användarnamnet.
	 *		InvalidPasswordLength=För kort lösenord.
	 *		InvalidUsernameLength=För kort användarnamn.
	 *		InvalidQuestionLength=Säkerhetsfrågan är för kort.
	 *		InvalidAnswerLength=Säkerhetssvaret är för kort.
	 *		UsernameExsists=Användarnamnet finns redan.
	 * </se>
	 * </code>
	 * @todo Rename all texts to include Button_/Error_/Input_/Text_ indications first to indicate usage.
	 * @since Version 1.5
	 */
	private function DefineDefaultLanguage() {
		$this->LoginSystemText['AccessLevel']['en']		 			= "Not Authorized.";
		$this->LoginSystemText['AccountLocked']['en'] 				= "Account has been locked.";
		$this->LoginSystemText['Button_ChangePassword']['en'] 		= "Change Password";
		$this->LoginSystemText['Button_Login']['en'] 				= "Login";
		$this->LoginSystemText['Button_PasswordRecovery']['en'] 	= "Reset Password";
		$this->LoginSystemText['Button_Registration']['en'] 		= "Create Account";
		$this->LoginSystemText['Error_Database']['en'] 				= "An error has occured with the database. Please try again later.";
		$this->LoginSystemText['IncorrectSecurityAnswer']['en'] 	= "Incorrect answer to the security question.";
		$this->LoginSystemText['Input_Mail']['en'] 					= "E-mail";
		$this->LoginSystemText['Input_NewPassword']['en'] 			= "New Password";
		$this->LoginSystemText['Input_OldPassword']['en'] 			= "Old Password";
		$this->LoginSystemText['Input_Password']['en'] 				= "Password";
		$this->LoginSystemText['Input_PasswordRepeat']['en'] 		= "Repeat Password";
		$this->LoginSystemText['Input_Username']['en'] 				= "Username:";
		$this->LoginSystemText['InvalidAnswerLength']['en'] 		= "Securityanswer is too short.";
		$this->LoginSystemText['InvalidMailSymbol']['en']	 		= "Invalid symbols in the provided mail.";
		$this->LoginSystemText['InvalidPasswordLength']['en'] 		= "Password is too short.";
		$this->LoginSystemText['InvalidPasswordSymbol']['en'] 		= "Invalid symbols in password";
		$this->LoginSystemText['InvalidQuestionLength']['en'] 		= "Securityquestion is too short.";
		$this->LoginSystemText['InvalidUsernameLength']['en'] 		= "Username is too short.";
		$this->LoginSystemText['InvalidUsernameSymbol']['en'] 		= "Invalid symbols in username";
		$this->LoginSystemText['LoginIssues']['en'] 				= "Invalid credentials.";
		$this->LoginSystemText['MailContent']['en'] 				= "Hi, there has been a request to reset your password. Click <a href='http://RESETKEYPATH'>here</a> to change your password.";
		$this->LoginSystemText['NewPasswordInvalid']['en'] 			= "Please provide a valid new password.";
		$this->LoginSystemText['NewPasswordUnmatched']['en'] 		= "The new password and repeated password do not match.";
		$this->LoginSystemText['NotLoggedIn']['en'] 				= "Not logged in.";		
		$this->LoginSystemText['OldPasswordMissmatch']['en'] 		= "Supplied old password incorrect.";		
		$this->LoginSystemText['OldPasswordNotSupplied']['en'] 		= "Old password not supplied.";		
		$this->LoginSystemText['UnlockSequenceAnswer']['en'] 		= "Answer:";
		$this->LoginSystemText['UnlockSequenceQuestion']['en'] 		= "Securityquestion:";
		$this->LoginSystemText['UsernameExsists']['en'] 			= "Username already exists.";
		$this->LoginSystemText['Error_SystemError']['en']			= "A system error has occured. Contact the system administrator.";
	}
	
	/**
	 * Used to print out arrays independent of depth
	 * @param $Array Array to echo
	 * @access private
	 * @since Version 3.42
	 */ 
	private function EchoArray ($Array) {
		foreach($Array as $ArrayCell) {
			if (is_array($ArrayCell)) {
				$this->EchoArray($ArrayCell);
			} else {
				echo $ArrayCell . "<br>";
			}
			
		}
	}

	/**
	 * Used to change the active language to the supplied one. This reads from the languagefile if it exsists.
	 *
	 * @param string $NewLanguage Languagecode that can identify the language in both the file and in $LoginSystemText[].
	 */
	private function Language_Change ($NewLanguage) {
		$LanguageFileRow = array();

		// If the selected languagefile exists, read it and split on lineending.
		if(file_exists($this->LanguageDirectory . $this->LanguageFile)) {
			$LanguageFileRow = file($this->LanguageDirectory . $this->LanguageFile,FILE_IGNORE_NEW_LINES);

			$StartKey = array_search("<".$NewLanguage.">",$LanguageFileRow);
			if(!($StartKey === false )) {
				$this->Language = $NewLanguage;
				$this->DebugMessage("Language","Changed to new language:" . $this->Language);
				$EndKey = array_search("</".$this->Language.">",$LanguageFileRow);
				for($i=$StartKey+1;$i<$EndKey;$i++) {
					$this->LoginSystemText[trim(substr($LanguageFileRow[$i],0,strpos($LanguageFileRow[$i],"=")))][$this->Language] = substr($LanguageFileRow[$i],strpos($LanguageFileRow[$i],"=")+1);

				}
			}
		}
	}
	
	/**
	 * Used to set a saltlength if it has not been defined earlier.
	 *
	 * @param string $PasswordString Users password defines the length of the salt.
	 * @since Version 2.5
	 */
	protected function VerifySaltLength($PasswordString) {
		
		if ( ($this->SaltSetByUser === false) or ($this->SaltLength == 0) ) {
			$this->SaltLength = strlen($PasswordString);	
		}
	}
}