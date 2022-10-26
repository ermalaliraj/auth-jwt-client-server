# JWT token Authentication with RSA key

How to configure authentication in Spring boot application using JWT token and RSA private/public key.

## Run

(1) Run API `JwtApplication.java`

(2)  Generate Token
```
POST http://localhost:8080/token
Authorization: Basic ZXJtYWw6ZXJtYWw=
```
OR
```
curl -X POST http://localhost:8080/token -u "ermal:ermal"
```
Copy the granted accessToken and use it in the next call for authentication.

(3) Call API with granted Token in header
```
GET http://localhost:8080/
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJlcm1hbCIsInNjb3BlIjoicmVhZCIsImlzcyI6InNlbGYiLCJleHAiOjE2NjY1MzUxNjYsImlhdCI6MTY2NjUzMTU2Nn0.ZnK7B36kXKLl8Pu-QMu4qn2Wq3oXWYzhlRsDKBayGQHnr1Vmd4lDFJRGV3bFR8gB-TF_oJhWccxEC1Ynek-7Jtk_4ikYfoaVtbRientL6bTb76G2xyNwSVkIYNy-_dsuuls1uc3cW79krx6EWQ465sE8VfQED5hrhUk8lS3_FqPWG5QHS7joHM2CbGsV4dyRGywgbxhy8rFnJRAyUEwtoaY1iEdzjf6s6p9XHY7A1hrkS1bMNw60T2JT3nXKPg10oEAo2CufmCih_XhgAJC2nuc9vn1eRm7iarSI1kJ4fF8IfDUfVTc3oqvjls3xsv7RZZOGCjEp0zBpt2PlEndpeVRjH6EaIOVMJOTeGXjA_Ok9YNBpk9wYWpusMlpTlW0kWNatRT4cUVytO6fvOHCyIYdZoDn7wh-J5LHztu5IJPeFBSSaMJ5pN1j7MGUnMF8LPP7-qc1to6Li5lfbFfGfv7LlOvM
```
OR
```
curl http://localhost:8080/ -H "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzZWxmIiwic3ViIjoiZXJtYWwiLCJleHAiOjE2NjY1NDA1NzQsImlhdCI6MTY2NjUzNjk3NCwic2NvcGUiOiJyZWFkIn0.ZJJsU2se7Qn6e5iCa44L6-mRUCWPeQyjI8ad1r6AJLoCZYo10i71TXRblLLRidqkGr2oP3tlLhZPPMMdDktJf6ruMr7bRJ0a54qzu6e4frzEguRMx86khSpzWOoWskaOvMfyWsuc7mhxClHSC1iKniOZmM7xsXI2lIvcHhRv1xv_xmu0iZHNaHfv0VZ3_iCEK4KRWG08pcGiIID_NiIVOHDrJfto5rpRhKxMjDGENaBI6vgb90rdD3BVi8LqvqXAYYvPHRsONJtGz_qBvpbCd6rQUdVSpz6Nd3m_dna9YjOV8s5QuJ3PR6mwVsLSeCf6MU7O_8Ofm_DhYoUg-bAEjTLR_wFDqEMJumoNKofklaVOmNsZsRkSn2WBdlT8_Lv031CRuvO1dY3f1xQBhIm66mCoQv0zb2teD7QXEvH1n14KGoovPdKM6bt0ro3g6lj_bmQtNf0fdHXcTxWvJVuElsN3DZc"
```

You should see as response "Hello JWT! User: ermal"

## RSA key generations

1. Generate Private key `openssl genrsa -out keypair.pem 2848`
2. Extract public key `openssl rsa -in keypair.pem -pubout -out public.pem`
3. Generate Encrypted Private Key `openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out private.pem`
(if we use keypair.pem as a private key the system will complain.  "The private key needs to be in a PEM encoded pkcs8 format")


## Links
* [Youtube tutorial - Spring Security JWT](https://www.youtube.com/watch?v=KYNR5js2cXE)

