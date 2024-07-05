:class OAuth2
    :field client_id
    :field client_secret
    :field host
    :field authorizationcode
    :field scope
    :field access_token
    :field refresh_token
    :field token_type
    :field expires
    :field OAuthState

    Date←{0:: 0⋄+ 2 ⎕nq '.' 'datetoidn', 2⊃¨⎕VFI¨ 1↓¨('-'='-',⍵)⊂'-',⍵}
    IsoDateToFloat←'- :'∘ {ts←7↑⊃¨2⊃¨⎕VFI¨ 1↓¨(((1↑⍺),⍵)∊⍺)⊂' ',⍵ ⋄ (24 60 60 1000 { (⍺⊥⍵)÷×/⍺  }  3↓ts)   + 2 ⎕nq ('.' 'datetoidn' ),3↑ ts}
    TsToFloat←{ (24 60 60 1000 { (⍺⊥⍵)÷×/⍺  }  3↓⍵)   + 2 ⎕nq ('.' 'datetoidn' ),3↑ ⍵}
    FloatToIsoDate←'- :,' ∘ {ts←(3↑+2 ⎕nq '.' 'idntodate' ,⌊⍵),  24 60 60 1000 {⍺⊤⌊⍵××/⍺} 1|⍵ ⋄ ¯1↓⊃,/ (2 1 2 2/⍺),⍨¨  4 2 2 2 2 2 3{ (-⍺)↑'0',⍕⍵}¨ts}
    TsToIsoDate←'- :,' ∘ { ¯1↓⊃,/ (2 1 2 2/⍺),⍨¨  4 2 2 2 2 2 3{ (-⍺)↑'0',⍕⍵}¨⍵}




    ∇ Make arg
      :Implements Constructor
      :Access Public
      (client_id client_secret scope host)←4↑arg
      http←⎕NEW #.HttpCommand
      authorizationcode←''
      access_token←''
      refresh_token←''
      token_type←''
      expires←TsToFloat ⎕TS
      OAuthState←'New'
    ∇



    ∇ url←GenerateGoogleOAuth2URL;Params
      :Access public
      URL←'https://accounts.google.com/o/oauth2/auth'
      Params←⊂'client_id'client_id
      Params,←⊂'response_type' 'code'
      Params,←⊂'scope'scope
      Params,←⊂'redirect_uri'('http://',host,'/testing/comeback')
      Params,←⊂'prompt' 'consent'
      Params,←⊂'access_type' 'offline'
     
      url←URL,'?',(1↓⊃,/'&',¨{⍺,'=',#.HttpCommand.UrlEncode ⍵}/↑Params)
    ∇



    ∇ SetAuthorizationCode arg;ixs;mask
      :Access public
      ixs←arg[;1]⍳'code' 'scope'
     
      mask←ixs≤≢arg
      (authorizationcode scope)←arg[mask/ixs;2]@{mask} authorizationcode scope
      :If 0<≢authorizationcode
          OAuthState←'Registered'  
          ExchangeAuthorizationForTokens
      :EndIf
    ∇


    ∇ ExchangeAuthorizationForTokens;res
      :Access public
      http.Command←'post'
      http.URL←'https://oauth2.googleapis.com/token'
      http.Headers←'content-type' 'application/x-www-form-urlencoded'
      http.Params←1 2⍴'code'authorizationcode
      http.Params⍪←'client_id'client_id
      http.Params⍪←'redirect_uri'('http://',host,'/testing/comeback')
      http.Params⍪←'client_secret'client_secret
      http.Params⍪←'scope' ''
      http.Params⍪←'grant_type' 'authorization_code'
     
     
      res←http.Run
      
      :if 0 'OK' 200 ≡res.(rc HttpMessage HttpStatus) 
        auth←⎕JSON res.Data
        access_token refresh_token token_type←auth.(access_token refresh_token token_type)
        expires←(TsToFloat ⎕TS)+(auth.expires_in÷24×60×60)
        OAuthState←'Tokens'
      :else 
        (OAuthState authorizationcode) ←'New' ''
      :endif
    ∇


    ∇ RefreshTokens
      :Access public
      http.Command←'post'
      http.URL←'https://oauth2.googleapis.com/token'
      http.Headers⍪←'content-type' 'application/x-www-form-urlencoded'
      http.Params←⊂'client_id'client_id
      http.Params,←⊂'client_secret'client_secret
      http.Params,←⊂'grant_type' 'refresh_token'
      http.Params,←⊂'refresh_token'refresh_token
     
     
      res←http.Run
     
      auth←⎕JSON res.Data
      access_token token_type←auth.(access_token token_type)
      expires←(TsToFloat ⎕TS)+(auth.expires_in÷24×60×60)
      OAuthState←'Tokens'
    ∇

    ∇ bool←Expired
      bool←expires<TsToFloat ⎕TS
    ∇

    ∇ tok←GetAccessToken
      :If ''≡access_token
          ExchangeAuthorizationForTokens
      :EndIf
      :If Expired
          RefreshTokens
      :EndIf
     
      tok←access_token
    ∇




    ∇ list←GetMyContacts;res
      :Access public
      tok←GetAccessToken
      http.Command←'get'
      http.URL←'https://people.googleapis.com/v1/people/me/connections'
      http.Headers←'Authorization'('Bearer ',tok)
      http.Params←'personFields' 'names'
     
      res←http.Run
      contacts←⎕JSON res.Data
      list←contacts.connections.(resourceName names.displayName)
     
    ∇

    ∇ user←GetCurrentUser;res;userns
      :Access public
     
      :If OAuthState≡'Tokens'
          tok←GetAccessToken
          http.Command←'get'
          http.URL←'https://people.googleapis.com/v1/people/me'
          http.Headers←'Authorization'('Bearer ',tok)
          http.Params←'personFields' 'names'
     
          res←http.Run
          userns←⎕JSON res.Data
          user←userns.names.displayName
      :Else
          user←''
      :EndIf
     
    ∇

    ∇ user←GetUser resourceName
      :Access public
     
      :If OAuthState≡'Tokens'
          tok←GetAccessToken
          http.Command←'get'
          http.URL←'https://people.googleapis.com/v1/',resourceName
          http.Headers←'Authorization'('Bearer ',tok)
          http.Params←'personFields' 'names,addresses,emailAddresses,phoneNumbers,photos,organizations'
          res←http.Run
          user←⎕JSON res.Data
      :Else
          user←''
      :EndIf
    ∇
:endclass
