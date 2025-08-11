package paracentric


import (
   "io"
   "os"
   "fmt"
   "time"
   "bytes"
   "crypto"
   "runtime"
   "net/mail"
   "math/big"
   "image/png"
   "crypto/rsa"
   "crypto/rand"
   "crypto/x509"
   "encoding/pem"
   "crypto/sha1"
   "crypto/sha256"
   "crypto/sha512"
   "encoding/asn1"
   "encoding/base64"
   "crypto/x509/pkix"
   "github.com/youmark/pkcs8"
   "github.com/makiuchi-d/gozxing"
   "github.com/makiuchi-d/gozxing/qrcode"
)

func New() *PkiT {
   return &PkiT{}
}

func (pk *PkiT) GenerateClientCSR(subject pkix.Name, email string) ([]byte, error) {
   var err error
   var template *x509.CertificateRequest
   var csr []byte

   if len(email) > 0 {
      _, err = mail.ParseAddress(email)
      if err != nil {
         Goose.Logf(1,"%s: %s", MailParseError, err)
         return nil, MailParseError
      }
   } else {
      if err != nil {
         Goose.Logf(1,"%s", MailOrUrlNeededError)
         return nil, MailOrUrlNeededError
      }
   }

   pk.PK, err = rsa.GenerateKey(rand.Reader, 2048)
   if err != nil {
      Goose.Logf(1,"%s: %s", PrivGenError, err)
      return nil, PrivGenError
   }

   template = &x509.CertificateRequest{
      Subject:              subject,
      SignatureAlgorithm:   x509.SHA256WithRSA,
      EmailAddresses:     []string{email},
   }

   csr, err = x509.CreateCertificateRequest(rand.Reader, template, pk.PK)
   if err != nil {
      Goose.Logf(1,"%s: %s", CsrGenError, err)
      return nil, CsrGenError
   }

   return csr, nil
}

func (pk *PkiT) GenerateClient(asn1Data []byte) (*x509.Certificate, *rsa.PublicKey, error) {
   var csr *x509.CertificateRequest
   var err error
   var notBefore, notAfter time.Time
   var serialNumber *big.Int
   var template *x509.Certificate
   var email string
   var der []byte
   var ok bool
   var cert *x509.Certificate
   var pub *rsa.PublicKey

   csr, err = x509.ParseCertificateRequest(asn1Data)
   if err != nil {
      Goose.Logf(1,"%s: %s", CsrParseError, err)
      return nil, nil, CsrParseError
   }

   if pub, ok = csr.PublicKey.(*rsa.PublicKey); !ok {
      Goose.Logf(1,"%s: %s", CsrNotSupportedPubKeyError, err)
      return nil, nil, CsrNotSupportedPubKeyError
   }

   err = csr.CheckSignature()
   if err != nil {
      Goose.Logf(1,"%s: %s", CsrSigError, err)
      return nil, nil, CsrSigError
   }

   if len(csr.EmailAddresses)==0 && len(csr.URIs)==0 {
      return nil, nil, MailOrUrlNeededError
   }

   for _, email = range csr.EmailAddresses {
      _, err = mail.ParseAddress(email)
      if err != nil {
         Goose.Logf(1,"%s on %s: %s", MailParseError, email, err)
         return nil, nil, MailParseError
      }
   }

   notBefore = time.Now()
   notAfter  = notBefore.Add(time.Hour * 24 * 90)

   serialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
   if err != nil {
      Goose.Logf(1,"%s: %s", SerialGenError, err)
      return nil, nil, SerialGenError
   }

   template = &x509.Certificate{
      SerialNumber:          serialNumber,
      Subject:               csr.Subject,
      NotBefore:             notBefore,
      NotAfter:              notAfter,
      IsCA:                  false,
      EmailAddresses:        csr.EmailAddresses,
//      URIs:                  csr.URIs,
      KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
      ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
      UnknownExtKeyUsage:    []asn1.ObjectIdentifier{
         []int{1,3,6,1,4,1,311,20,2,2}, // SmartCard Logon
         []int{1,3,6,1,4,1,311,10,3,16}, // Verify signature for nonrepudiation?
      },
      BasicConstraintsValid: true,
   }

   s := ""
   s1 := sha256.Sum256(pub.N.Bytes())
   s = string(s1[:])
   s2 := sha512.Sum512_224(pub.N.Bytes())
   s = s + string(s2[:])
   s3 := sha512.Sum512_256(pub.N.Bytes())
   s = s + string(s3[:])
   s4 := sha512.Sum512_256(pub.N.Bytes())
   s = s + string(s4[:])
   s5 := sha512.Sum512(pub.N.Bytes())
   s = s + string(s5[:])
   s6 := sha1.Sum(pub.N.Bytes())
   s = s + string(s6[:])
   ski := ""
   for _, b := range s {
      ski = ski + fmt.Sprintf("%d", b)
   }
   template.SubjectKeyId = []byte(ski)

   der, err = x509.CreateCertificate(rand.Reader, template, pk.Cert, csr.PublicKey, pk.PK)
   if err != nil {
      Goose.Logf(1,"%s: %s", CrtGenError, err)
      return nil, nil, CrtGenError
   }

   cert, err  = x509.ParseCertificate(der)
   if err != nil {
      Goose.Logf(1,"Failed parsing certificate %s",err)
      return nil, nil, err
   }


   return cert, pub, nil
}



func (pk *PkiT) NewPemCertReqFromReader(rd io.Reader) error {
   var buf []byte
   var buf2 *pem.Block
   var err error

   buf, err = io.ReadAll(rd)
   if err != nil {
      Goose.Logf(1,"Error reading certificate: %s", err)
      return err
   }

   buf2, _ = pem.Decode(buf)
   if buf2 == nil {
      Goose.Logf(1,"%s: [%s]", CertReadError, buf2)
      return CertReadError
   }

   pk.Cert, err  = x509.ParseCertificate(buf2.Bytes)
   if err != nil {
      Goose.Logf(1,"Failed parsing certificate %s",err)
      return err
   }

   return nil
}

func (pk *PkiT) NewPemCertFromMemory(buf []byte) error {
   var buf2 *pem.Block
   var err error

   buf2, _ = pem.Decode(buf)
   if buf2 == nil {
      Goose.Logf(1,"%s: [%s]", CertReadError, buf2)
      return CertReadError
   }

   pk.Cert, err  = x509.ParseCertificate(buf2.Bytes)
   if err != nil {
      Goose.Logf(1,"Failed parsing certificate %s",err)
      return err
   }

   return nil
}

func (pk *PkiT) NewPemCertFromReader(rd io.Reader) error {
   var buf []byte
   var err error

   buf, err = io.ReadAll(rd)
   if err != nil {
      Goose.Logf(1,"Error reading certificate: %s", err)
      return err
   }

   return pk.NewPemCertFromMemory(buf)
}

func (pk *PkiT) NewPemCertFromFile(fname string) error {
   var fh *os.File
   var err error

   fh, err = os.Open(fname)
   if err != nil {
      Goose.Logf(1,"Failed opening certificate %s",err)
      return err
   }

   return pk.NewPemCertFromReader(fh)
}



func (pk *PkiT) NewPemKeyFromMemory(buf []byte, password string) error {
   var buf2 *pem.Block
   var err, err2 error
   var pkInt interface{}
   var ok bool
   var key *rsa.PrivateKey

   buf2, _ = pem.Decode(buf)
   if buf2 == nil || buf2.Type != "RSA PRIVATE KEY" {
      Goose.Logf(1,"%s", KeyReadError)
      return KeyReadError
   }

   pkInt, err = pkcs8.ParsePKCS8PrivateKey(buf2.Bytes, []byte(password))
   if err != nil {
      key, err2  = x509.ParsePKCS1PrivateKey(buf2.Bytes)
      if err2 != nil {
         Goose.Logf(1,"Failed parsing key %s",err)
         return err
      }
      pk.PK = key
      return nil
   }

   if key, ok = pkInt.(*rsa.PrivateKey); !ok {
      Goose.Logf(1,"Failed parsing key: %s (%#v)", KeyWrongTypeError, pkInt)
      return KeyWrongTypeError
   }

   pk.PK = key
   return nil
}

func (pk *PkiT) NewPemKeyFromReader(rd io.Reader, password string) error {
   var buf []byte
   var err error

   buf, err = io.ReadAll(rd)
   if err != nil {
      Goose.Logf(1,"Error reading key: %s", err)
      return err
   }

   return pk.NewPemKeyFromMemory(buf, password)
}

func (pk *PkiT) NewPemKeyFromFile(fname string, password string) error {
   var fh *os.File
   var err error

   fh, err = os.Open(fname)
   if err != nil {
      Goose.Logf(1,"Failed opening key %s",err)
      return err
   }

   return pk.NewPemKeyFromReader(fh, password)
}

func (pk *PkiT) PemKey(password string) ([]byte, error) {
   var err error
   var crypt_priv []byte

   crypt_priv, err = pkcs8.MarshalPrivateKey(pk.PK, []byte(password), &pkcs8.Opts{
      Cipher: pkcs8.AES256CBC,
      KDFOpts: pkcs8.ScryptOpts{
         CostParameter:            1 << 2,
         BlockSize:                8,
         ParallelizationParameter: 1,
         SaltSize:                 16,
      },
   })


//   crypt_priv, err = x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(pk.PK), []byte(password), x509.PEMCipher3DES)


   if err != nil {
      Goose.Logf(1,"Failed to encrypt: %s", err)
      return nil, err
   }

   return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: crypt_priv}), nil
}


func (pk *PkiT) PemKeyToFile(fname, password string) error {
   var err error
   var buf []byte

   buf, err = pk.PemKey(password)
   if err != nil {
      return err
   }

   err = os.WriteFile(fname, buf, 0640)
   if err != nil {
      Goose.Logf(1,"Failed to save %s: %s", fname, err)
      return err
   }

   return nil
}


func (pk *PkiT) PemCsr(der []byte, fname string) error {
   var err error

   certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})

   err = os.WriteFile(fname, certOut, 0640)
   if err != nil {
      Goose.Logf(1,"Failed to save %s: %s", fname, err)
      return err
   }

   return nil
}


func (pk *PkiT) NewPemCert(fname string) error {
   var certOut []byte
   var err error

   certOut = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pk.Cert.Raw})

   err = os.WriteFile(fname, certOut, 0640)
   if err != nil {
      Goose.Fatalf(0,"Failed to save %s: %s", fname, err)
   }

   return nil
}




func (pk *PkiT) Sign(msg string) ([]byte, error) {
   var sum [sha256.Size]byte
   var err error
   var msgDigest, msgSignature []byte

   sum = sha256.Sum256([]byte(msg))
   msgDigest = sum[:]

   msgSignature, err = rsa.SignPSS(rand.Reader, pk.PK, crypto.SHA256, msgDigest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
   if err != nil {
      Goose.Logf(1,"Failed to sign: %s", err)
      return nil, err
   }

   return msgSignature, nil
}



func (pk *PkiT) Verify(msg string, signature []byte) error {
   var err error
   var sum [sha256.Size]byte

   sum = sha256.Sum256([]byte(msg))

   err = rsa.VerifyPSS(&pk.PK.PublicKey, crypto.SHA256, sum[:], signature, nil)
   if err != nil {
      Goose.Logf(1,"Error from verification: %s", err)
      return err
   }

   return nil
}

func (pk *PkiT) Encrypt(msg []byte) ([]byte, error) {
   var secret, buf []byte
   var err error

   for len(msg) > 0 {
      if len(msg) > 190 {
         buf, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pk.PK.PublicKey, msg[:190], []byte{})
      } else {
         buf, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, &pk.PK.PublicKey, msg, []byte{})
      }
      if err != nil {
         return nil, err
      }

      secret = append(secret, buf...)

      if len(msg) > 190 {
         msg = msg[190:]
      } else {
         msg = nil
      }
   }

   return secret, nil
}


func (pk *PkiT) Decrypt(secret []byte) ([]byte, error) {
   var msg, buf []byte
   var err error

   for len(secret) > 0 {
      buf, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, pk.PK, secret[:256], []byte{})
      if err != nil {
         Goose.Logf(1,"Error from decryption: %s", err)
         return nil, err
      }

      msg = append(msg, buf...)

      secret = secret[256:]
   }

   return msg, nil
}

func int64ToBytes(n uint64) []byte {
   return []byte{
      byte(n & 0xff),
      byte((n>>8) & 0xff),
//      byte((n>>16) & 0xff),
//      byte((n>>24) & 0xff),
//      byte((n>>32) & 0xff),
//      byte((n>>40) & 0xff),
//      byte((n>>48) & 0xff),
//      byte((n>>56)),
   }
}

func (pk *PkiT) Challenge() ([]byte, []byte, error) {
   var challenge []byte
   var encrypted []byte
   var err error
   var encoder *qrcode.QRCodeWriter
   var btmtrx *gozxing.BitMatrix
   var finalBuf *bytes.Buffer
   var ms runtime.MemStats
   var ci ChallImageT

   challenge = make([]byte, 128)
   _, err = rand.Read(challenge)
   if err != nil {
      Goose.Logf(1,"Error creating challenge: %s", err)
      return nil, nil, err
   }

   runtime.ReadMemStats(&ms)
   challenge[0] = challenge[0] ^ int64ToBytes(ms.TotalAlloc)[0]
   challenge[1] = challenge[1] ^ int64ToBytes(ms.TotalAlloc)[1]
   challenge[2] = challenge[2] ^ int64ToBytes(ms.Lookups)[0]
   challenge[3] = challenge[3] ^ int64ToBytes(ms.Lookups)[1]
   challenge[4] = challenge[4] ^ int64ToBytes(ms.MCacheInuse)[0]
   challenge[5] = challenge[5] ^ int64ToBytes(ms.LastGC)[0]
   challenge[6] = challenge[6] ^ int64ToBytes(ms.GCSys)[0]
   challenge[7] = challenge[7] ^ int64ToBytes(ms.PauseTotalNs)[0]

   encrypted, err = pk.Encrypt(challenge)
   if err != nil {
      Goose.Logf(1,"Error encrypting challenge: %s", err)
      return nil, nil, err
   }

   encoder = qrcode.NewQRCodeWriter()
   btmtrx, err = encoder.Encode(base64.StdEncoding.EncodeToString(encrypted), gozxing.BarcodeFormat_QR_CODE, 300, 300, nil)
   if err != nil {
      Goose.Logf(1,"Error encoding challenge: %s", err)
      return nil, nil, err
   }

   finalBuf = bytes.NewBuffer(nil)
   ci.BitMatrix = *btmtrx
   err = png.Encode(finalBuf, &ci)
   if err != nil {
      Goose.Logf(1,"Error imaging challenge: %s", err)
      return nil, nil, err
   }

   return challenge, finalBuf.Bytes(), nil
}

func (pk *PkiT) QrKeyId(keyId string, challenge []byte) ([]byte, error) {
   var err error
   var encoder *qrcode.QRCodeWriter
   var btmtrx *gozxing.BitMatrix
   var finalBuf *bytes.Buffer
   var sig, chall string
   var sigBytes []byte

   sigBytes, err = pk.Sign(keyId+string(challenge))
   if err != nil {
      Goose.Logf(1,"Error signing keyId: %s", err)
      return nil, err
   }

   sig = base64.StdEncoding.EncodeToString(sigBytes)
   chall = base64.StdEncoding.EncodeToString(challenge)

   encoder = qrcode.NewQRCodeWriter()
   btmtrx, err = encoder.Encode(keyId + ":" + chall + ":" + sig, gozxing.BarcodeFormat_QR_CODE, 300, 300, nil)
   if err != nil {
      Goose.Logf(1,"Error signing keyId: %s", err)
      return nil, err
   }

   finalBuf = bytes.NewBuffer(nil)
   err = png.Encode(finalBuf, btmtrx)
   if err != nil {
      Goose.Logf(1,"Error signing keyId: %s", err)
      return nil, err
   }

   return finalBuf.Bytes(), nil
}

func (pk *PkiT) Certificate() []byte {
   return pk.Cert.Raw
}



