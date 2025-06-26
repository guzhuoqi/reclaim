
# Provider

A "provider" in reclaim's context is simply a set of functions that tells the attestor how to format the request & check the validity of the response, that proves a claim.

For example, you could have a provider termed "google-login" that is configured to verify claims of ownership of google accounts.

The library makes it fairly simple to add new providers for particular use cases. Here is how you can add your own:

1. Decide on a kebab case name for your provider. For example, if you're creating a provider to verify claims of ownership of google accounts, you could name it `google-login`
2. Create two files in the [./provider-schemas](/provider-schemas) folder:
	- `{provider-name}/parameters.yaml`: This file should contain the JSON schema for the parameters that the user will provide to the provider.
   		- These parameters are used to make the request to the server & are publicly visible
		- For example, in the case of the google-login provider, the parameters could be the email address of the user.
		- The attestor will use this schema to verify whether the parameters provided by the user are valid for the provider
	- `{provider-name}/secret-parameters.yaml`: This file should contain the JSON schema for the secret parameters that the user will provide to the provider.
   		- These parameters are used to authenticate the request to the server & are hidden from the attestor
		- For example, in the case of the google-login provider, the secret parameters could be the access token of the user.
		- Presently, we don't validate the secret parameters on the client before sending them. Instead this schema is kept for future use, and to keep the types store consistent for the secret parameters & parameters

	Note: for both schemas, the "title" property of the schema should be a PascalCase named string. Look at the [http provider](/provider-schemas/http) schemas for an example.
3. Generate the types for the provider by running the following command:
   ```sh
   npm run generate:provider-types
   ```
4. Now, you'll need to write the code for this provider to create the request & validate the transcript. Now, any new provider must conform to the `Provider` interface.
   ```ts
	/**
	 * Generic interface for a provider that can be used to verify
	* claims on a TLS receipt
	*
	* @notice "Params" are the parameters you want to claim against.
	* These would typically be found in the response body
	*
	* @notice "SecretParams" are the parameters that are used to make the API request.
	* These must be redacted in the request construction in "createRequest" & cannot be viewed by anyone
	*/
	export interface Provider<
	N extends ProviderName,
	Params = ProviderParams<N>,
	SecretParams = ProviderSecretParams<N>
	> {
		/**
		* host:port to connect to for this provider;
		* the protocol establishes a connection to the first one
		* when a request is received from a user.
		*
		* Run on attestor side when creating a new session
		*
		* Eg. "www.google.com:443", (p) => p.url.host
		* */
		hostPort: ProviderField<Params, string>
		/**
		* Which geo location to send the request from
		* Provide 2 letter country code, or a function
		* that returns the country code
		* @example "US", "IN"
		*/
		geoLocation?: ProviderField<Params, string | undefined>
		/**
		 * extra options to pass to the client like root CA certificates
		 */
		additionalClientOptions?: TLSConnectionOptions
		/**
		* default redaction mode to use. If not specified,
		* the default is 'key-update'.
		*
		* It's switched to 'zk' for TLS1.2 requests as TLS1.2
		* don't support key updates
		*
		* @default 'key-update'
		*/
		writeRedactionMode?: ProviderField<Params, RedactionMode | undefined>
		/** generate the raw request to be sent to through the TLS receipt */
		createRequest(
			secretParams: SecretParams,
			params: Params
		): CreateRequestResult
		/**
		* Return the slices of the response to redact
		* Eg. if the response is "hello my secret is xyz",
		* and you want to redact "xyz", you would return
		* [{start: 17, end: 20}]
		*
		* This is run on the client side, to selct which portions of
		* the server response to send to the attestor
		* */
		getResponseRedactions?(response: Uint8Array, params: Params): ArraySlice[]
		/**
		* verify a generated TLS receipt against given parameters
		* to ensure the receipt does contain the claims the
		* user is claiming to have
		*
		* This is run on the attestor side.
		* @param receipt application data messages exchanged in the TLS session
		* @param params the parameters to verify the receipt against. Eg. `{"email": "abcd@gmail.com"}`
		* @returns sucessful verification or throws an error message.
		*  Optionally return parameters extracted from the receipt
		*  that will then be included in the claim context
		* */
		assertValidProviderReceipt(
			receipt: Transcript<Uint8Array>,
			params: Params
		): void | Promise<void> | { extractedParams: { [key: string]: string } }
	}
   ```

   Note: a "ProviderField" is either a constant value of the field or a function that returns the field value from the parameters passed to the provider.
2. Should default export the newly constructed provider
3. Should kebab case the file name & store it in `src/providers/{app-name}.ts`
4. Finally, export this new application from `src/providers/index.ts`

Example providers:
- [HTTP](/src/providers/http/index.ts)
	- This is a generic provider that can be used to verify any HTTP request

## Testing a Provider with a Remote Attestor

We'd of course recommend writing automated tests for your provider. Examples of such tests can be found in the [tests folder](/src/tests).
However, if you'd like to test your provider with a remote attestor, you can do so by following these steps:

1. Create a JSON outlining the parameters for the provider. For eg. for the HTTP provider, this would look like:
   ```json
   {
   	"name": "google-login",
   	"params": {
   		"emailAddress": "abcd@gmail.com"
   	},
   	"secretParams": {
   		"token": "{{GOOGLE_ACCESS_TOKEN}}"
   	}
   }
   ```
   - Note any parameters specified by `{{*}}` will be replaced by the value of the environment variable with the same name. By default, the script will look for a `.env` file
2. Run the receipt generation script with the JSON as input.
   ```sh
	npm run create:claim -- --json google-login-params.json
   ```
   This will use the default attestor server to generate a receipt for the given provider. To use a custom attestor server, use the `--attestor` flag
   ```sh
   	npm run create:claim -- --json google-login-params.json --attestor ws://localhost:8080/ws
   ```
3. The script will output the receipt alongside whether the receipt contained a valid claim from the provider

## Considerations & tests

It's crucial to process `redactions` correctly when creating a request.
Make sure & double check that PII data like oauth tokens & passwords are processed correctly.

Each application should have test in `tests` folder. `redactions` and `assertValidApplicationReceipt` should be the first things to test

## HTTP Provider

Since almost all APIs we'd encounter would be HTTP based, we've created a generic HTTP provider that can be used to verify any HTTP request.

All you need to do is provide the URL, method, headers & body of the request you want to verify along with the secret parameters required to make the request (that are hidden from the attestor any other party).

Let's look at a detailed example of how to prove the date of birth of a user without revealing any other information. We'd be doing this via the "Aadhar" API. For context, Aadhar is a unique identification number issued by the Indian government to its citizens.

The parameters of the request would be:
``` json
{
    "name": "http",
    "params": {
		// specifies the API/webpage URL that contains the date of birth
		// or the data you want to prove
        "url": "https://tathya.uidai.gov.in/ssupService/api/demographics/request/v4/profile",
		// http method
        "method": "POST",
		// the body of the request -- we've included a "template" here
		// that will be replaced by the actual UID number. Templates in
		// the http provider are mustache templates.
		// https://mustache.github.io/
        "body": "{\"uidNumber\":\"{{uid}}\"}",
		// optionally, we've specified which country the request should be
		// sent from. This is useful when the API you're hitting is geo
		// restricted
        "geoLocation": "IN",
		// this is the response redaction. This tells our client
		// what portions of the data are relevant to the claim
		// we're trying to prove. The client will slice the response
		// in such a way that only the portions specified here are
		// sent to the attestor. This redaction can be done via
		// JSONPath, XPath or regex. If all are specified, the attestor will
		// first find the element matching the xpath -> then use the JSONPath
		// to find the specific data & finally use the regex to match the data
        "responseRedactions": [
            {
				// json path for date of birth
                "jsonPath": "$.responseData.dob",
            },
			// if TOPRF is enabled (which is for the official attestor from
			// Reclaim), you can consistently hash the data here
			// instead of redacting it.
			// This allows you to de-duplicate proofs without seeing
			// the true identity of the user, as the hash is
			// consistent across all proofs.
			{
				// json path for date of UUID
                "jsonPath": "$.responseData.uuid",
                "hash": "oprf"
            }
        ],
		// This tells the attestor what to look for in the response.
		// If the response doesn't match this -- the attestor will reject the claim.
		// This match can be done either by a simple string match
		// or regex
		"responseMatches": [
			{
				"type": "regex",
				"value": "(?<dob>\\d{4}-\\d{2}-\\d{2})"
			}
		],
		// headers to be sent with the request that help access
		// the API/webpage. The headers present in the "params"
		// are meant to be public & can be viewed by anyone -- 
		// including the attestor
		"headers": {
			"accept": "application/json, text/plain, */*",
            "accept-language": "en_IN",
            "appid": "SSUP",
            "content-type": "application/json",
		},
		"paramValues": {
			"uid": "123456789012"
		}
    },
	// secret parameters that are used to make the request
	// these are hidden from the attestor & any other party
    "secretParams": {
		// the headers present in the "secretParams" are meant to be
		// secret & cannot be viewed by anyone -- including the attestor
		// these are redacted by the client before sending the transcript
		// to the attestor
        "headers": {
            "x-request-id": "{{requestId}}",
			"Authorization": "Bearer {{bearerToken}}"
        },
		// the paramValues are the values that will replace the templates
		// only in the secretParams. These parameters will of course, not
		// be visible to the attestor.
		// To replace the templates in the params, you can place a
		// "paramValues" key in the params object
		"paramValues": {
			"requestId": "1234",
			// bearer token can be found using the network inspector
			// on the Aadhar website
			"bearerToken": "replace-this-with-your-token"
		}
    }
}
```

Now, you may be wondering we've not actually specified the date of birth in the parameters. It's simply a regex that matches any date. So, how does the attestor know what date to prove?

This is where "extractedParameters" come in. When the attestor processes the transcript, it'll use the regex specified in the `responseMatches` to extract the date of birth from the response.

This date of birth will then be included in the `context` property of the claim. It'll be specified by the name of the regex group. In our case that was `dob`. In the absence of a named group -- the parameter will not be extracted. Read more on named regex groups [here](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Regular_expressions/Named_capturing_group)

Therefore, upon a successful claim -- the claim object will look like:
``` json
{
	"provider": "http",
	"parameters: "{\"url\":\"https://...",
	"context": {
		"extractedParameters": {
			"dob": "1999-01-01"
		}
	},
	"owner": "0x1234...",
	...
}
```

And there you have it! You can now use this claim to prove the age of a person without revealing any other information.

For more info on how TOPRF works to hide sensitive data in a consistent way, refer to the [TOPRF section](/docs/claim-creation.md#toprf)

You can read the full types of the HTTP provider [here](/src/providers/http-provider/types.ts?ref_type=heads#L55)

### Notable Considerations

The HTTP provider handles other considerations when creating the request & parsing the response to prevent abuse, and false generation of claims. This list is not exhaustive, but some notable considerations include:

1. `Connection: close` header is added to the request to prevent the server from keeping the connection open. This is done to prevent the user from sending multiple requests to the server & getting different responses, and perhaps using one of those responses to falsely generate a claim.
	- The attestor of course verifies the presence of this header in the transcript
2. `Accept-Encoding: identity` header is added to the request to prevent the server from compressing the response. This is done because we can't correctly validate the response if it's compressed & redacted.
3. Validation of the `Host` header in the request is done to ensure the request is being sent to the correct server.