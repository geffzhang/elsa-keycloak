Simple sample to demo keycloak integration into Elsa V3 server and studio (blazor server)

![alt](chrome_sj0kfgIftr.gif)

There are some known issues
- studio blazor (server mode): get access_token from HttpContext
   ```c#
    var token = await _jwtAccessor.ReadTokenAsync(TokenNames.AccessToken);
    //replaced by
    var token = await _httpContextAccessor.HttpContext.GetTokenAsync("access_token");
   ```

- elsa server: add this code to program.cs to disable permission
   ```c#
    Elsa.EndpointSecurityOptions.DisableSecurity();
   ```    

- ...