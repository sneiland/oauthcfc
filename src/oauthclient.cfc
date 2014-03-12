<cfcomponent accessors="true" displayname="Oauth Client" extends="oauthutils" output="false" hint="Implements an oauth 1.0a client">
	
	<cfset variables.requestTokenUrl = "">
    <cfset variables.accessTokenUrl = "">
    <cfset variables.authorizeUrl = "">
	<cfset variables.consumerKey = ""><!--- Also known as the api key --->
	<cfset variables.consumerSecret = "">
	<cfset variables.accessToken = "">
    <cfset variables.accessTokenSecret = "">
	
	<!--- *** Public Functions *** --->
	
	<cffunction name="getRequestToken">
		<cfset var authHeader = "">
		<cfset var params = {
				  oauth_nonce : "#getNonce()#"
				, oauth_consumer_key : "#getConsumerKey()#"
				, oauth_signature_method : "HMAC-SHA1"
				, oauth_timestamp : generateTimeStamp()
				, oauth_version="1.0"
			}>

		<!--- Get the authorization header --->
		<cfset authHeader = generateAuthHeader('POST', variables.requestTokenUrl, params)>

		<!--- Get the request token--->
		<cfset sendRequest('POST',variables.requestTokenUrl,authHeader,"")>
		
		<!--- TODO Complete this --->
	</cffunction>
	
	
	<cffunction name="postMessage" output="false" hint="Sends the actual message content">
		<cfargument name="message" required="true" type="string">

		<cfset var authHeader = "">
		<cfset var returnSuccess = FALSE>
		<cfset var params = {
			    oauth_consumer_key : variables.consumerKey
			  , oauth_nonce : getNonce()
			  , oauth_signature_method : "HMAC-SHA1"
			  , oauth_token : variables.accessToken
			  , oauth_version : "1.0"
			  , oauth_timestamp : generateTimestamp()
			  , status = encodeUrl(arguments.message)
			}>
		
		<!--- Note the status must run through the encoder twice: once here and once when building the auth header --->

		<!--- Get the authorization header --->
		<cfset authHeader = generateAuthHeader('POST', getPostUrl(), params)>
		
		<!--- Reset the status to its non url encoded format --->
		<cfset params.status = arguments.message>

		<!--- Post to twitter--->
		<cfset returnSuccess = sendRequest('POST',getPostUrl(),authHeader,params)>
		
		<cfreturn returnSuccess>
	</cffunction>
	
	<!--- *** Private Functions *** --->
	
	<cffunction name="generateAuthHeader" output="false">
		<cfargument name="httpMethod" required="true" type="string" hint="POST or GET">
		<cfargument name="apiUrl" required="true" type="string" hint="The url for the specific twitter api method">
		<cfargument name="params" required="false" type="any" default="" hint="Any additional parameters to send to the api">

		<cfset var authHeader = "OAuth ">
		<cfset var count = 0>
		<cfset var keys = "">
		<cfset var key = "">
		<cfset var signatureBaseString = "">
		<cfset var compositeSigningKey = "">
		<cfset var oauth_signature = "">

		<!--- Get the signature base string. --->
		<cfset signatureBaseString = generateSignatureBaseString('POST', arguments.apiUrl, params)>

		<!--- Create the composite signing key. --->
		<cfif NOT compareNoCase(variables.requestTokenUrl,arguments.apiUrl)>
			<!--- The request token api call does not expect the accessTokenSecret --->
			<cfset compositeSigningKey = variables.consumerSecret & "&">
		<cfelse>
			<cfset compositeSigningKey = variables.consumerSecret & "&" & variables.accessTokenSecret>
		</cfif>

		<!--- Get signature. --->
		<cfset oauth_signature = signSignature(signatureBaseString,compositeSigningKey) />

		<!--- Append the signature to the params --->
		<cfset params.oauth_signature = oauth_signature>

		<cfset keys = StructKeyArray(params)>

		<!--- Append params to the auth header --->
		<cfloop array="#keys#" index="key">
			<cfset count = count+1>
			<cfif count GT 1>
				<cfset authHeader = authHeader & ", ">
			</cfif>
			<cfset authHeader = authHeader & lcase(key) & "=""" & encodeUrl(params[key]) & """">
		</cfloop>

		<cfreturn authHeader>
	</cffunction>
	
	
	<cffunction name="generateSignatureBaseString" output="false" returntype="string">
		<cfargument name="httpMethod" type="string" required="true" hint="GET OR POST">
		<cfargument name="baseUrl" type="string" required="true">
		<cfargument name="values" type="struct" required="true">

		<!---
			Append the parameters to the signature base string as a single url encoded querystring
			In the following formatted string 'POST[encodedurl]&encoded(param1=val1)%26encoded(param2=val2)'
			Note how the first param is seperated from the url by the "&" symbol
			whereas all the subsequent params are seperated from each other by "%26"
		 --->

	  	<cfset var signatureBaseString = "#httpMethod#&#encodeUrl(baseUrl)#">
	  	<cfset var keys = StructKeyArray(values)>
	  	<cfset var key = "">
		<cfset var count = 0>

		<cfset ArraySort(keys, "textNoCase")>

		<cfloop array="#keys#" index="key">
			<cfset count = count + 1>
		  	<cfif count EQ 1>
	   			<cfset signatureBaseString &= "&" & encodeUrl("#lcase(key)#=#values[key]#")>
	    	<cfelse>
	    		<cfset signatureBaseString &= "%26" & encodeUrl("#lcase(key)#=#values[key]#")>
	    	</cfif>
		</cfloop>

		<cfreturn signatureBaseString>
	</cffunction>
	
	
	<cffunction name="sendRequest" access="private" output="false" returntype="boolean" hint="Send the request to oAuth agent">
		<cfargument name="httpMethod" 	required="true" 	type="string" hint="POST or GET">
		<cfargument name="apiUrl" 		required="true" 	type="string" hint="The url for the specific twitter api method">
		<cfargument name="authHeader" 	required="true" 	type="string" hint="The authorization header">
		<cfargument name="params" 		required="false" 	type="any" 	default="" hint="Any additional parameters to send to the api">

		<cfset var keys = "">
		<cfset var key = "">
		<cfset var httpResponse = "">
		<cfset var returnSuccess = TRUE>
		
		<cfhttp	result="httpResponse" method="#arguments.httpMethod#" url="#arguments.apiUrl#" useragent="#variables.userAgent#">
			<cfhttpparam type="header" name="Authorization"	value="#arguments.authHeader#"/>

			<!--- Attach any non 'oauth_' parameters --->
			<cfif IsStruct(arguments.params) AND NOT StructIsEmpty(arguments.params)>
				<cfset keys = StructKeyArray(arguments.params)>
				<cfloop array="#keys#" index="key">
					<cfif NOT reFindNoCase( "oauth_", #key# )>
						<cfhttpparam type="formfield" name="#lcase(key)#" value="#params[key]#">
					</cfif>
				</cfloop>
			</cfif>
		</cfhttp>
		
		<!--- TODO: error handling --->
		<cfif isDefined("httpResponse.status_code") AND httpResponse.status_code EQ "401">
			<cfset returnSuccess = FALSE>
		</cfif>

		<cfreturn returnSuccess>
	</cffunction>
	
	
	<cffunction name="signSignature" access="public" output="false"  returntype="string"
				hint="Sign the signature base string using the given signing key and the HMAC-SHA1 hashing algorithm.">
					
		<cfargument	name="signatureBaseString" type="string" required="true" hint="I am the signature base string."/>
		<cfargument	name="signingKey" type="string" required="true"	hint="I am the signing key."/>

		<cfset var secretKeySpec = "">
		<cfset var mac = "">
		<cfset var encryptedBytes = "">
		<cfset var signature = "">

		<!---
			Create our secret key generator. This can create a secret from a given
			byte array. Initialize it with the byte array version of our signing key
			and the algorithm we want to use to generate the secret key.
		--->
		<cfset secretKeySpec = createObject( "java", "javax.crypto.spec.SecretKeySpec" ).init(toBinary( toBase64( arguments.signingKey ) ),"HmacSHA1")>

		<!---
			Create our MAC (Message Authentication Code) generator to encrypt the message
			data using the secret key specification.
		--->
		<cfset mac = createObject( "java", "javax.crypto.Mac" ).getInstance( "HmacSHA1" )>

		<!--- Initialize the MAC instance using our secret key generator. --->
		<cfset mac.init( secretKeySpec ) />

		<!---
			Complete the mac operation, encrypting the base signature string using the
			given secret key (that we created above).
		--->
		<cfset encryptedBytes = mac.doFinal(toBinary( toBase64( arguments.signatureBaseString ) ))>

		<!--- Convert the byte array to a base64-encoded string. --->
		<cfset signature = toBase64( encryptedBytes ) />

		<!--- Return the signature. --->
		<cfreturn signature />
	</cffunction>
	
</cfcomponent>