package main

import (
   "fmt"
   "bytes"
   "image"
   "errors"
   "strings"
   "image/gif"
   "image/png"
   "image/jpeg"
   "syscall/js"
   "encoding/pem"
   "encoding/base64"
   "crypto/x509/pkix"
   "github.com/luisfurquim/goose"
   "github.com/luisfurquim/paracentric"
   "github.com/vincent-petithory/dataurl"
   "github.com/makiuchi-d/gozxing"
   "github.com/makiuchi-d/gozxing/qrcode"
)

var InvNumArg error = errors.New("Invalid no of arguments passed")
var NoEmail error = errors.New("No E-mail configured")
var EmailNotReg error = errors.New("E-mail not registered")

func toArray(in []byte) []interface{} {
   var out []interface{}
   var i int
   var b byte

   out = make([]interface{}, len(in))
   for i, b = range in {
      out[i] = b
   }

   return out
}

func fromArray(in js.Value) []byte {
   var out []byte
   var i int

   out = make([]byte, in.Length())
   for i=0; i<in.Length(); i++ {
      out[i] = byte(in.Index(i).Int())
   }

   return out
}

func NewCert() js.Func {
   var fn js.Func

   fn = js.FuncOf(func(this js.Value, args []js.Value) interface{} {
      var pk *paracentric.PkiT
      var jsPk js.Value
      var ls, wPk, wCert js.Value
      var email string
      var pw string
      var err error

      if len(args) != 0 && len(args) != 2 {
         //fmt.Printf("%s %d\n", InvNumArg, len(args))
         return []interface{}{ nil, InvNumArg.Error()}
      }

      pk = paracentric.New()
      ls = js.Global().Get("localStorage")

      jsPk = js.ValueOf(map[string]interface{}{})
      jsPk.Set("status", js.ValueOf(0))


      if len(args) != 0  && !args[0].IsUndefined() && !args[1].IsUndefined() && !args[0].IsNull() && !args[1].IsNull() {
         email = args[0].String()
         pw = args[1].String()

         wPk = ls.Call("getItem","wasmcert." + args[0].String() + ".Pk")

         if !wPk.IsUndefined() && !wPk.IsNull() {
            err = pk.NewPemKeyFromMemory([]byte(wPk.String()),pw)
            if err != nil {
               return []interface{}{ nil, err.Error()}
            }

            wCert = ls.Call("getItem","wasmcert." + email + ".Cert")
//            fmt.Printf("wCert: %s\n", wCert.String())
            if !wCert.IsUndefined() && !wCert.IsNull() {
               err = pk.NewPemCertFromMemory([]byte(wCert.String()))
               if err != nil {
                  return []interface{}{ nil, err.Error()}
               }

               if ls.Call("getItem","wasmcert." + email + ".isValidated").String() == "true" {
                  jsPk.Set("status", js.ValueOf(2))
               } else {
                  jsPk.Set("status", js.ValueOf(1))
               }

//               fmt.Printf("%#v\n", pk.Cert)
               jsPk.Set("keyId", js.ValueOf(fmt.Sprintf("%2X", pk.Cert.SubjectKeyId)))
            }
         }
      }

      jsPk.Set("ValidateRegister",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         if len(args) != 0 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         ls.Call("setItem","wasmcert." + email + ".isValidated", "true")
         jsPk.Set("status", js.ValueOf(2))
         return []interface{}{true, nil}
      }))


      jsPk.Set("GenerateClientCSR",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var name pkix.Name
         var err error
         var der []byte
         var subject, password string
         var pembuf []byte

         if len(args) != 3 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         subject = args[0].String()
         name.CommonName = subject
         email = args[1].String()
         password = args[2].String()

         der, err = pk.GenerateClientCSR(name, email)
         if err != nil {
//            fmt.Printf("Generation of certificate request has failed (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         pembuf, err = pk.PemKey(password)
         if err != nil {
//            fmt.Printf("PEM encoding has failed (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         ls.Call("setItem","wasmcert." + email + ".Pk", js.ValueOf(string(pembuf)))
         ls.Call("setItem","wasmcert." + email + ".isValidated", js.ValueOf(false))
         jsPk.Set("status", js.ValueOf(1))

         return []interface{}{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil}
      }))

      jsPk.Set("sign",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var err error
         var signature []byte
         var b64Signature string

         if len(args) != 1 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         if pk.PK == nil {
            fmt.Printf("%s\n", EmailNotReg)
            return []interface{}{nil, EmailNotReg.Error()}
         }

         signature, err = pk.Sign(args[0].String())
         if err != nil {
//            fmt.Printf("Failed signing message (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         b64Signature = base64.StdEncoding.EncodeToString(signature)

         return []interface{}{b64Signature, nil};
      }))

      jsPk.Set("verify",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var err error
         var signature []byte

         if len(args) != 2 {
//            fmt.Printf("Wrong parameters number\n", err)
            return []interface{}{nil, err.Error()}
         }

         signature, err = base64.StdEncoding.DecodeString(args[1].String())
         if err != nil {
//            fmt.Printf("Failed decoding signature (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         err = pk.Verify(args[0].String(), signature)
         if err != nil {
            return []interface{}{false, nil}
         }

         return []interface{}{true, nil}
      }))

      jsPk.Set("encrypt",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var err error
         var encrypted []byte

         if len(args) != 1 {
//            fmt.Printf("%s\n", InvNumArg)
            return []interface{}{nil, InvNumArg.Error()}
         }

         encrypted, err = pk.Encrypt([]byte(args[0].String()))
         if err != nil {
//            fmt.Printf("Failed encrypting message (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         return []interface{}{toArray(encrypted), nil};
      }))

      jsPk.Set("decrypt",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var err error
         var decrypted []byte

         if len(args) != 1 {
//            fmt.Printf("%s\n", InvNumArg)
            return []interface{}{nil, InvNumArg.Error()}
         }

         decrypted, err = pk.Decrypt(fromArray(args[0]))
         if err != nil {
//            fmt.Printf("Failed decrypting message (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         return []interface{}{string(decrypted), nil}
      }))


      jsPk.Set("qrKeyId",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var img []byte
         var err error
         var challenge []byte

         if len(args) != 1 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         if len(email) == 0 {
            fmt.Printf("%s\n", NoEmail)
            return []interface{}{nil, NoEmail.Error()}
         }

         challenge, err = pk.Decrypt(fromArray(args[0]))
         if err != nil {
//            fmt.Printf("Failed decrypting challenge (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         img, err = pk.QrKeyId(fmt.Sprintf("%2X",pk.Cert.SubjectKeyId), challenge)
         if err != nil {
            return []interface{}{nil, err.Error()}
         }

         return []interface{}{dataurl.EncodeBytes(img), nil}
      }))

      jsPk.Set("qrDecode",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var img image.Image
         var err error
         var qrReader gozxing.Reader
         var bmp *gozxing.BinaryBitmap
         var result *gozxing.Result
         var dataURL *dataurl.DataURL

         if len(args) != 1 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         dataURL, err = dataurl.Decode(strings.NewReader(args[0].String()))
         if err != nil {
            return []interface{}{nil, err.Error()}
         }

         if dataURL.MediaType.ContentType() == "image/png" {
            img, err = png.Decode(bytes.NewReader(dataURL.Data))
            if err != nil {
               return []interface{}{nil, err.Error()}
            }
         } else if dataURL.MediaType.ContentType() == "image/jpeg" {
            img, err = jpeg.Decode(bytes.NewReader(dataURL.Data))
            if err != nil {
               return []interface{}{nil, err.Error()}
            }
         } else if dataURL.MediaType.ContentType() == "image/gif" {
            img, err = gif.Decode(bytes.NewReader(dataURL.Data))
            if err != nil {
               return []interface{}{nil, err.Error()}
            }
         } else {
//            fmt.Printf("Only PNG/JPEG/GIF QrCodes are supported!\n")
            return []interface{}{nil, "Only PNG/JPEG/GIF QrCodes are supported!\n"}
         }

         // prepare BinaryBitmap
         bmp, err = gozxing.NewBinaryBitmapFromImage(img)
         if err != nil {
            return []interface{}{nil, err.Error()}
         }

         // decode image
         qrReader = qrcode.NewQRCodeReader()
         result, err = qrReader.Decode(bmp, nil)
         if err != nil {
            return []interface{}{nil, err.Error()}
         }

         return []interface{}{result.GetText(), nil}
      }))


      jsPk.Set("getChallenge",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         var data []byte
         var challenge []byte
         var qrImg []byte

         if len(args) != 1 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         data, err = base64.StdEncoding.DecodeString(args[0].String())
         if err != nil {
            return []interface{}{nil, err.Error()}
         }

         challenge, err = pk.Decrypt(data)
         if err != nil {
//            fmt.Printf("Failed decrypting challenge (%s)\n", err)
            return []interface{}{nil, err.Error()}
         }

         qrImg, err = pk.QrKeyId(fmt.Sprintf("%2X",pk.Cert.SubjectKeyId), challenge)
         if err != nil {
            return []interface{}{nil, err.Error()}
         }

         return []interface{}{dataurl.EncodeBytes(qrImg), nil}
      }))

      jsPk.Set("b64Encode",js.FuncOf(func(this js.Value, args []js.Value) interface{} {
         if len(args) != 1 {
            return []interface{}{nil, InvNumArg.Error()}
         }

         return []interface{}{base64.StdEncoding.EncodeToString([]byte(args[0].String())), nil}
      }))

      return []interface{}{jsPk, nil}
  })
  return fn
}

func main() {
   goose.TraceOn()
   js.Global().Set("NewCert", NewCert())
   <-make(chan bool)
}
