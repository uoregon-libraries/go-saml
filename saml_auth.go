package go_saml

import(
  "context"
  "crypto/rsa"
  "crypto/tls"
  "crypto/x509"
  "net/http"
  "net/url"
  "path/filepath"
  "github.com/crewjam/saml/samlsp"
  "github.com/labstack/echo/v4"
  "github.com/tidwall/gjson"
  "fmt"
  "log"
  "os"
)

type SamlMW struct{
  Mware *samlsp.Middleware
}
// redoes serveACS
func (m SamlMW)SamlReturnHandler(c echo.Context) error{
  err := c.Request().ParseForm()
  if err != nil { m.Mware.OnError(c.Response(), c.Request(), err); return err }
  possibleRequestIDs := []string{}
  if m.Mware.ServiceProvider.AllowIDPInitiated {
    possibleRequestIDs = append(possibleRequestIDs, "")
  }
  trackedRequests := m.Mware.RequestTracker.GetTrackedRequests(c.Request())
  for _, tr := range trackedRequests {
    possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
  }
  assertion, err := m.Mware.ServiceProvider.ParseResponse(c.Request(), possibleRequestIDs)
  if err != nil { m.Mware.OnError(c.Response(), c.Request(), err); return err}
  m.Mware.CreateSessionFromAssertion(c.Response(), c.Request(), assertion, m.Mware.ServiceProvider.DefaultRedirectURI)
  return nil
}

func SamlSetup()(*samlsp.Middleware){
  cert := os.Getenv("SAML_CERT")
  key := os.Getenv("SAML_KEY")
  idp_url := os.Getenv("SAML_IDP_METADATA_URL")
  base_url := os.Getenv("BASE_URL")

  keyPair, err := tls.LoadX509KeyPair(cert, key)
  if err != nil { log.Println(err) }
  keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
  if err != nil { log.Println(err) }
  idpMetadataURL, err := url.Parse(idp_url)
  if err != nil { log.Println(err) }

  // Initialize metadata of the IDP
  idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
  if err != nil { log.Println(err) }
  rootURL, err := url.Parse(base_url)
  if err != nil { log.Println(err) }

  samlSP, _ := samlsp.New(samlsp.Options{
    URL: *rootURL,
    IDPMetadata: idpMetadata,
    Key: keyPair.PrivateKey.(*rsa.PrivateKey),
    Certificate: keyPair.Leaf,
  })
  return samlSP
}

func (m SamlMW) SamlMetadata( c echo.Context) error{
  m.Mware.ServeMetadata(c.Response(), c.Request())
  return nil
}

func CheckUser(next echo.HandlerFunc) echo.HandlerFunc{
  return func(c echo.Context) error{
    email := samlsp.AttributeFromContext(c.Request().Context(), "eduPersonPrincipalName")
    home_dir := os.Getenv("HOME_DIR")
    json, err := os.ReadFile(filepath.Join(home_dir, "files/users.json"))
    if err != nil { log.Println(err); return echo.NewHTTPError(400, err) }
	query := fmt.Sprintf("users.#(email=\"%s\")", email)
    value := gjson.GetBytes(json, query)
    if value.Exists(){ return next(c) }else{ return c.String(http.StatusOK, "not auth") }
    }
}
// redoes RequireAccount
func (m SamlMW)SamlAuth(next echo.HandlerFunc) echo.HandlerFunc{
  return func(c echo.Context) error{
    session, err := m.Mware.Session.GetSession(c.Request())
    if session != nil { 
      r := c.Request().WithContext(samlsp.ContextWithSession(c.Request().Context(), session))
      c.SetRequest(r)
      return next(c)
    }
    if err == samlsp.ErrNoSession {
      m.Mware.HandleStartAuthFlow(c.Response(), c.Request())
      return nil
    }
    log.Println(err)
    m.Mware.OnError(c.Response(), c.Request(), err)
    return nil
  }
}
