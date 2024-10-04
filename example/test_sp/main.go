package main

import(
  "github.com/labstack/echo/v4"
  "github.com/labstack/echo/v4/middleware"
  "github.com/crewjam/saml/samlsp"
  "github.com/tidwall/gjson"
  "net/http"
  "log"
  "os"
  "path/filepath"
  "github.com/uoregon-libraries/go-saml/saml"
)

func main(){
  e := echo.New()

  var samlmw = saml.SamlMW{ Mware: saml.SamlSetup() }

  e.Use(middleware.Logger())
  e.Use(middleware.Recover())
  e.POST("/saml/acs", samlmw.SamlReturnHandler)
  e.GET("/saml/metadata", samlmw.SamlMetadata)
  g := e.Group("/greets")
  g.Use(samlmw.SamlAuth)
  g.Use(saml.CheckUser)

  g.GET("/hello", hello)

  e.Logger.Fatal(e.Start(":8080"))
  }

func hello(c echo.Context) error{
  name := samlsp.AttributeFromContext(c.Request().Context(), "eduPersonPrincipalName")
  return c.String(http.StatusOK, "hello: " + name)
}

