<?php
if (0 > version_compare(PHP_VERSION, '5')) {
	die('This file was generated for PHP 5');
}


class AssignDescriptor
	extends GenerisConnector 
{
	
	public $leftVariable;

	public $rightOperation;//expression
	public $rightVariable;//string
	public $rightConstant;//string
	
	public function __toString(){
		$left = '^'.$this->leftVariable;
		$operator = ':=';
		$right = '';
		if(isset($this->rightConstant)){
			if(is_numeric($this->rightConstant)){//"numerical strings" are not allowed
				$right = $this->rightConstant;
			}else{
				$right = "'{$this->rightConstant}'";
			}
		}elseif(isset($this->rightVariable)){
			$right =  '^'.$this->rightVariable;
		}elseif(isset($this->rightOperation)){
			$right =  $this->rightOperation->__toString();
		}else{
			$right =  "???";
		}
		
		return $left.' '.$operator.' '.$right;
	}
	
	
	public function import()
	{
		//creates the inferenceRule
		
		$assignmentClass = new core_kernel_classes_Class(CLASS_ASSIGNMENT,__METHOD__);
		//label in correct format??
		$assignment = $assignmentClass->createInstance($this, __(" generated by CapiImport on ") . date(DATE_ISO8601));
		
		
		//the use of that???
		/*
		//find the uri of the property behind the variable
		$predicate  = core_kernel_classes_Session::singleton()->model->execSQL("AND predicate='".PROPERTY_CODE."' AND object ='".$this->leftVariable."'");
		
		if (isset($predicate[0][0]))
		{
			$predicateUri = $predicate[0][0];	
			
		}
		else //create it
		{
			//build Intreviewee Property
			$intervieweeClass = new core_kernel_classes_Class(CLASS_INTERVIEWEE,__METHOD__);
			$intervieweeProp = $intervieweeClass->createProperty("inf_".$this->leftVariable . ' Generated Property' , __(" generated by CapiImport on ") . date(DATE_ISO8601));
			$intervieweeProp->setLgDependent(true);
			//put code on it
			$intervieweeProp->setPropertyValue(new core_kernel_classes_Property(PROPERTY_CODE),"".$this->leftVariable);
			$predicateUri =$intervieweeProp->uriResource;	
			$intervieweeProp->setPropertyValue(new core_kernel_classes_Property(RDFS_RANGE),RDFS_LITERAL);
		}
			*/

		//creates the left term
		$spxInstance = $this->importTermSPX($this->leftVariable);

		//put the left term on it
		$assignment->setPropertyValue(new core_kernel_classes_Property(PROPERTY_ASSIGNMENT_VARIABLE),$spxInstance->uriResource);
		
		if (isset($this->rightVariable)){
					
				//$this->rightVariable should be the code of an existing proc var: check before pliz!
				
				//creates the right term
				$spxInstance = $this->importTermSPX($this->rightVariable);

				//put spx on assignement
				$assignment->setPropertyValue(new core_kernel_classes_Property(PROPERTY_ASSIGNMENT_VALUE),$spxInstance->uriResource);
		}else{
			if (isset($this->rightConstant))
			{
				$constantTerm = $this->importTermConstant($this->rightConstant);
				//put constant
				$assignment->setPropertyValue(new core_kernel_classes_Property(PROPERTY_ASSIGNMENT_VALUE),$constantTerm->uriResource);
			}
			else
			{
				if (isset($this->rightOperation ))
				{
					$operationTerm =  $this->rightOperation->importTermOperation();
					//put operation
					$assignment->setPropertyValue(new core_kernel_classes_Property(PROPERTY_ASSIGNMENT_VALUE),$operationTerm->uriResource);
					
				}
			}
		}
		return $assignment;
	}


/*****************************************
The following code is common with condition , do not modify, lets wait that lle finishes conditiondescriptor edition
********/

/**
* import either $leftPart or $rightpart given in $variable, $variable must be a variable
**/

private function importTermSPX($variable){

		$termClass = new core_kernel_classes_Class(CLASS_TERM_SUJET_PREDICATE_X,__METHOD__);
		//creates a Term
		$termInstance =$termClass->createInstance("Term : SPX " . $variable , __(" generated by Condition Descriptor on ") . date(DATE_ISO8601));

		$subjectProperty = new core_kernel_classes_Property(PROPERTY_TERM_SPX_SUBJET,__METHOD__);
		$predicateProperty = new core_kernel_classes_Property(PROPERTY_TERM_SPX_PREDICATE,__METHOD__);
		$codeProperty = new core_kernel_classes_Property(PROPERTY_CODE,__METHOD__);

		//get the resource with the code "$variable"
		$processInstancePropertyCollection = $this->generisApi->getSubject($codeProperty->uriResource, $variable);
		if(!$processInstancePropertyCollection->isEmpty()){
		
			$processInstanceProperty = $processInstancePropertyCollection->get(0);
			
			$termInstance->setPropertyValue($subjectProperty , 'VAR_PROCESS_INSTANCE');
			$termInstance->setPropertyValue($predicateProperty , $processInstanceProperty->uriResource);
		}
		else{
			throw new common_Exception("the variable $variable doesn't exist, please create it before");//perform a check 
		}

		return $termInstance;



	}
/**
* import either $leftPart or $rightpart given in $constant, $variable must be a constant
**/
private function importTermConstant($constant)
	{
			if ( strtoupper($constant) == 'NULL') {
				return new core_kernel_classes_Resource(INSTANCE_TERM_IS_NULL, __METHOD__);
			}
			$termValueProperty = new core_kernel_classes_Property(PROPERTY_TERM_VALUE,__METHOD__);
			$logicalOperatorProperty = new core_kernel_classes_Property(PROPERTY_HASLOGICALOPERATOR,__METHOD__);
			$terminalExpressionProperty = new core_kernel_classes_Property(PROPERTY_TERMINAL_EXPRESSION,__METHOD__);

			

			$termConstClass = new core_kernel_classes_Class(CLASS_TERM_CONST,__METHOD__); 
			$termConstInstance =  $termConstClass->createInstance("Term : Constante " . $constant , __(" generated by CapiImport on ") . date(DATE_ISO8601));
			$termConstInstance->setPropertyValue($terminalExpressionProperty,$termConstInstance->uriResource);
			$termConstInstance->setPropertyValue($logicalOperatorProperty,INSTANCE_EXISTS_OPERATOR_URI);
			$termConstInstance->setPropertyValue($termValueProperty,$constant);
			
			return $termConstInstance;
	}





}




?>
