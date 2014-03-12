<cfcomponent displayname="Oauth Utilities" output="false" hint="Utility component containing functions used by both the server and client components">
	
	<cffunction name="init" access="public" output="false">
		<cfreturn this>
	</cffunction>
	
	
	<cffunction name="encodeUrl" access="private" output="false" returntype="string"
			hint="Url Encode a string to the RFC 3986 specifications.">
				
		<cfargument name="urlString" type="string" required="true" hint="The string we plan to url encode">

		<!---
            According to the RFC 3986 specification the following characters should NOT be encoded
            ALPHA, DIGIT, '-', '.', '_', '~'

            Start with ColdFusion's urlEncodedFormat() and then unescape the above characters
		--->
		
		<cfset var encodedString = urlEncodedFormat(arguments.urlString, "utf-8" )>
		<cfset var safeCharacter = "">

		<!---Loop through the unreserved characters and unescape them to comply with RFC 3986.--->
		<cfloop list="- . _ ~" delimiters=" " index="safeCharacter">
			<!--- Unescape the safe characters. --->
			<cfset encodedString = replaceNoCase(
				encodedString
				, "%#right( ('0' & formatBaseN( asc(safeCharacter), 16 )), 2 )#"
				, safeCharacter
				, "all"
			)>
		</cfloop>

		<cfreturn encodedString>
	</cffunction>
	
	
	<cffunction name="generateNonce" access="private" output="false" returntype="string"
			hint="Create a UUID and string out dashes">
				
       <!--- Get a UUID-based value. --->
		<cfset var nonce = ("OAUTH" & createUUID())>

		<!--- Strip out the UUID dashes. --->
		<cfset nonce = replace( nonce, "-", "", "all" )>

		<cfreturn nonce>
	</cffunction>
	
	
	<cffunction name="generateTimeStamp" access="private" output="false" returnType="string">
		<cfreturn fix(getTickCount()/1000)>
	</cffunction>
	
</cfcomponent>