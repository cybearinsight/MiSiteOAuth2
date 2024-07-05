# MiSiteOAuth2
 Google OAuth2 example for MiServer



This is an example on how to access the Contacts you have on your google account in your own MiServer service, it is provided without any guaranties.



When the MiServer starts it will create an instance of the OAuth calls with the client it and client Secret optained from Google.
The Application credentials needs to be configured in the Config\server.xml


All the examples are in 'testing' folder, during the login you will be redirected to Google for the login and then redirected back to the Comeback.page

After the login the Authorization token is converted to a access token. 
See the Code\OAuth2.dyalog for the specifics.




