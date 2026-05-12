package org.example.forsapidev.Controllers;


import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.example.forsapidev.Services.Interfaces.IAuthService;
import org.example.forsapidev.Services.Implementation.FaceAuthService;
import org.example.forsapidev.Services.Implementation.WebAuthnService;
import org.example.forsapidev.payload.request.FaceEnrollRequest;
import org.example.forsapidev.payload.request.FaceLoginRequest;
import org.example.forsapidev.payload.request.ForgottenPasswordRequest;
import org.example.forsapidev.payload.request.LoginRequest;
import org.example.forsapidev.payload.request.ResetRequest;
import org.example.forsapidev.payload.request.SignupRequest;
import org.example.forsapidev.payload.request.WebAuthnBeginLoginRequest;
import org.example.forsapidev.payload.request.WebAuthnBeginRegisterRequest;
import org.example.forsapidev.payload.request.WebAuthnFinishLoginRequest;
import org.example.forsapidev.payload.request.WebAuthnFinishRegisterRequest;
import org.example.forsapidev.payload.response.MessageResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {


  @Autowired
  private IAuthService iAuthService;
  @Autowired
  private WebAuthnService webAuthnService;
  @Autowired
  private FaceAuthService faceAuthService;

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
    return iAuthService.authenticateUser(loginRequest);
  }
  @GetMapping("/google-login-url")
  public ResponseEntity<?> getGoogleLoginUrl(HttpServletRequest request) {
    String baseUrl = "https://forsa-backend.loca.lt/forsaPidev";
    String googleAuthUrl = baseUrl + "/oauth2/authorization/google";
    return ResponseEntity.ok(new MessageResponse(googleAuthUrl));
  }

  @PostMapping("/signup")
  public ResponseEntity<?> register(@Valid @RequestBody SignupRequest signUpRequest) {
    return iAuthService.register(signUpRequest);
  }
  @PutMapping("/activate/{id}")
  public ResponseEntity<?> ValidateUser(@PathVariable("id") long id) {
    return iAuthService.ValidateUser(id);
  }
  @PostMapping("/ForgottenPassword")
  public ResponseEntity<?> ForgottenPassword(@Valid @RequestBody ForgottenPasswordRequest forgottenPasswordRequest) throws Exception {
    return iAuthService.ForgottenPassword(forgottenPasswordRequest);
  }

  @PostMapping("/resetpass")
  public ResponseEntity<?> resetpass(@RequestBody ResetRequest resetRequest) throws Exception {
    return iAuthService.resetpass(resetRequest);
  }

  /** Returns the authenticated user when a valid Bearer JWT is sent. */
  @GetMapping("/current")
  public ResponseEntity<?> getCurrentUser() {
    return iAuthService.getCurrentUser();
  }

  @PostMapping("/webauthn/register/begin")
  public ResponseEntity<?> beginPasskeyRegister(
          Authentication authentication,
          @RequestBody(required = false) WebAuthnBeginRegisterRequest request,
          HttpServletRequest httpRequest) {
    return webAuthnService.beginRegister(authentication, request, httpRequest);
  }

  @PostMapping("/webauthn/register/finish")
  public ResponseEntity<?> finishPasskeyRegister(
          Authentication authentication,
          @Valid @RequestBody WebAuthnFinishRegisterRequest request) {
    return webAuthnService.finishRegister(authentication, request);
  }

  @PostMapping("/webauthn/login/begin")
  public ResponseEntity<?> beginPasskeyLogin(
          @RequestBody WebAuthnBeginLoginRequest request,
          HttpServletRequest httpRequest) {
    return webAuthnService.beginLogin(request, httpRequest);
  }

  @PostMapping("/webauthn/login/finish")
  public ResponseEntity<?> finishPasskeyLogin(@Valid @RequestBody WebAuthnFinishLoginRequest request) {
    return webAuthnService.finishLogin(request);
  }

  @GetMapping("/webauthn/credentials")
  public ResponseEntity<?> listPasskeys(Authentication authentication) {
    return webAuthnService.listCredentials(authentication);
  }

  @DeleteMapping("/webauthn/credentials/{credentialId}")
  public ResponseEntity<?> deletePasskey(Authentication authentication, @PathVariable String credentialId) {
    return webAuthnService.deleteCredential(authentication, credentialId);
  }

  @PostMapping("/face/enroll")
  public ResponseEntity<?> enrollFace(Authentication authentication, @Valid @RequestBody FaceEnrollRequest request) {
    return faceAuthService.enroll(authentication, request);
  }

  @PostMapping("/face/login")
  public ResponseEntity<?> loginWithFace(@Valid @RequestBody FaceLoginRequest request) {
    return faceAuthService.login(request);
  }
}
