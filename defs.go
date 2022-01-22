package paracentric

import (
   "errors"
   "crypto/rsa"
   "crypto/x509"
   "image/color"
   "github.com/luisfurquim/goose"
   "github.com/makiuchi-d/gozxing"
)

var Goose goose.Alert = goose.Alert(1)

var CertReadError error = errors.New("Error decoding certificate")
var KeyReadError error = errors.New("Error decoding key")
var KeyWrongTypeError error = errors.New("Error wrong type key")
var PrivGenError error = errors.New("Failed to generate private key")
var CrtGenError error = errors.New("Failed to generate certificate")
var CsrGenError error = errors.New("Failed to generate certificate request")
var CsrParseError error = errors.New("Failed to parse certificate request")
var SerialGenError error = errors.New("Failed to generate serial number")
var UrlParseError error = errors.New("URL parse error")
var MailParseError error = errors.New("Mail parse error")
var MailOrUrlNeededError error = errors.New("Mail or URL needed")
var CsrSigError error = errors.New("CSR signature invalid")
var CsrNotSupportedPubKeyError error = errors.New("Csr not supported public key error")
var MarshalPubKeyError error = errors.New("Marshal public key error")


type PkiT struct {
   Cert *x509.Certificate
   PK *rsa.PrivateKey
}

type ChallImageT struct {
   gozxing.BitMatrix
}

func (ci ChallImageT) ColorModel() color.Model {
   return color.RGBAModel
}

func (ci ChallImageT) At(x, y int) color.Color {
   var c color.Color
   var r, g, b uint32

   c = ci.BitMatrix.At(x, y)
   r, g, b, _  = c.RGBA()

   if r==0xffff && g==0xffff && b==0xffff {
      return c
   }

   return color.RGBA{
      R: 0x4e,
      G: 0x34,
      B: 0x8a,
      A: 0xff,
   }
}
