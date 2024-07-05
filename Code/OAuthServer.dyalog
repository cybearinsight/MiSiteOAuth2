:Class OAuthServer : #.MiServer

    ∇ Make config
      :Access Public
      :Implements Constructor   :base config
    ∇

    ∇ onSessionStart req;code
      :Access public override
      ⎕←'SessionStart'
      
      
      
      :if 0∊req.Server.Config.⎕nc 'client_id' 'client_secret' 'scope'
         ⎕←'Config missing'
      :else
        ⍝ Create the OAuth2 instance for the session
          req.Session.OAuth←⎕NEW #.OAuth2 req.(Server.Config.(client_id client_secret scope),⊂Host)
     
        ⍝ get the Authorization Code from the Cookies.
⍝          code←req.GetCookie'OAuthCode'
⍝          req.Session.OAuth.SetAuthorizationCode (0<≢code) 2⍴'code'code
          ⎕←'OAuth2 instance created'
      :Endif
     
     
    ∇

    ∇ onSessionEnd session
      :Access public override
      ⎕←'SessionEnd'
      ⎕EX'session.OAuth'
    ∇
:EndClass
