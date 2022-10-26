//package com.ea.jwt.util;
//
//import com.nimbusds.jose.crypto.impl.RSAKeyUtils;
//
//import java.security.PublicKey;
//import java.util.List;
//
//public class JwtUtil {
//
//    public void decodeJwt(String jwt2) throws Exception {
//
////        // read public key from a file or config or something
////        String publicKeyPEM =
////                "-----BEGIN PUBLIC KEY-----\n" +
////                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAixn0CGu8/M4txn4pdp8K\n" +
////                        "m8RQfVa+cHX25/a5sPmzP49u7YlQsRvtOexzgdwDcfUJm3hHMZcbZBtrHKsS8q4Q\n" +
////                        "QtGQioyVml8EaLuFNFYisaIEldVyRbXFG54FNp03vSU9ImS/cOiM9swo+1w5JgWO\n" +
////                        "F9efy7JO40LA9E7lv64COUYjFhrn+HRZuKoblL19+Sj49FyXexAUS29UM9PfIdY6\n" +
////                        "ar1FA8cxzPqW7EkXZ0Mua3IzNnYcjMvUL9TJwoLAAz9S1Tv4Is5jupy9UXkuJ4r8\n" +
////                        "Jx9DqI3Q3ur0VekYSd5tnTI4K+no9ABCFVv7+6Q45Ec2eB0xMwlqI+phcGhGMVCX\n" +
////                        "1QIDAQAB\n" +
////                        "-----END PUBLIC KEY-----";
////
////        // decode to its constituent bytes
////        publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----\n", "");
////        publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
////        BASE64Decoder base64Decoder = new BASE64Decoder();
////        byte[] publicKeyBytes = base64Decoder.decodeBuffer(publicKeyPEM);
////
////        // create a key object from the bytes
////        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
////        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
////        PublicKey publicKey = keyFactory.generatePublic(keySpec);
////
////        // create a JWT consumer
////        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
////                .setRequireExpirationTime()
////                .setVerificationKey(publicKey)
////                .build();
////
////        // validate and decode the jwt
////        // eg: jwt = "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6Ik1DaGFtYmU0IiwiZXhwIjoxNDU2OTEwODgzLCJzY29wZSI6WyJvcGVuaWQiLCJwMnAiLCJociIsImRhcyIsIm1lIl0sImNsaWVudF9pZCI6Im1vYmlsZSIsImp0aSI6ImNZcHBMYXltVzlmNXFBZk4ifQ.QqZI9vV8IznTjN-GtUSCri9-6HH6Yl1Oae6K8-d2yjQ4fysF5d3wStdL2kMazl7xeqbtSIsw-F5Aol9eHdGAu54b9IyBEM_QIasy0lnT8xFk0Zi36NJ-7yhl_89f6SB6TGimM59xUvzXxuAw3FzWM6TbiptInrCL2TXkhS69Gng-ANPeiSITUX5A1TDInssds6ZoSb7IOUMtxPGfrbO9sBjx8aJlIu9igkqk4OX5xBmxLp3icoo98I5v9Wt_Huu7eWKBfOskMSEav4X_m5_phbAZJ_F8nWRmcxk6O7hCQdawzegnhMxP2IPIhwlWRNX_8WxkNErq2fJgdazDf8pS_Q";
////        JwtClaims jwtDecoded = jwtConsumer.processToClaims(jwt);
////        Map<String, Object> jwtClaims = jwtDecoded.getClaimsMap();
////        String username = (String) jwtClaims.get("username"); // "MChambe4"
////
////        // ensure the required scope is claimed
////        String requiredScope = "das";
////        ArrayList scopes = (ArrayList) jwtClaims.get("scope");
////        // ensure claims contains the required scope
////        if (!scopes.stream().anyMatch(scope -> scope == requiredScope)) {
////            throw new Exception("Required scope is not claimed: " + requiredScope);
////        }
//    }
//
//    public void decodeJwt2() throws Exception {
//        String jwt = "eyJhbGciOiJSUzI1NiJ9.eyJ1c2VybmFtZSI6Ik1DaGFtYmU0IiwiZXhwIjoxNDU2OTEwODgzLCJzY29wZSI6WyJvcGVuaWQiLCJwMnAiLCJociIsImRhcyIsIm1lIl0sImNsaWVudF9pZCI6Im1vYmlsZSIsImp0aSI6ImNZcHBMYXltVzlmNXFBZk4ifQ.QqZI9vV8IznTjN-GtUSCri9-6HH6Yl1Oae6K8-d2yjQ4fysF5d3wStdL2kMazl7xeqbtSIsw-F5Aol9eHdGAu54b9IyBEM_QIasy0lnT8xFk0Zi36NJ-7yhl_89f6SB6TGimM59xUvzXxuAw3FzWM6TbiptInrCL2TXkhS69Gng-ANPeiSITUX5A1TDInssds6ZoSb7IOUMtxPGfrbO9sBjx8aJlIu9igkqk4OX5xBmxLp3icoo98I5v9Wt_Huu7eWKBfOskMSEav4X_m5_phbAZJ_F8nWRmcxk6O7hCQdawzegnhMxP2IPIhwlWRNX_8WxkNErq2fJgdazDf8pS_Q";
//
//        // read public key from a file or config or something
//        String publicKeyPEM =
//                "-----BEGIN PUBLIC KEY-----\n" +
//                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAixn0CGu8/M4txn4pdp8K\n" +
//                        "m8RQfVa+cHX25/a5sPmzP49u7YlQsRvtOexzgdwDcfUJm3hHMZcbZBtrHKsS8q4Q\n" +
//                        "QtGQioyVml8EaLuFNFYisaIEldVyRbXFG54FNp03vSU9ImS/cOiM9swo+1w5JgWO\n" +
//                        "F9efy7JO40LA9E7lv64COUYjFhrn+HRZuKoblL19+Sj49FyXexAUS29UM9PfIdY6\n" +
//                        "ar1FA8cxzPqW7EkXZ0Mua3IzNnYcjMvUL9TJwoLAAz9S1Tv4Is5jupy9UXkuJ4r8\n" +
//                        "Jx9DqI3Q3ur0VekYSd5tnTI4K+no9ABCFVv7+6Q45Ec2eB0xMwlqI+phcGhGMVCX\n" +
//                        "1QIDAQAB\n" +
//                        "-----END PUBLIC KEY-----";
//
//        RSAKeyUtils rsaKeyUtil = new RSAKeyUtils();
//        PublicKey publicKey = rsaKeyUtil.fromPemEncoded(publicKeyPEM);
//
//        // create a JWT consumer
//        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
//                .setRequireExpirationTime()
//                .setVerificationKey(publicKey)
//                .build();
//
//        // validate and decode the jwt
//        JwtClaims jwtDecoded = jwtConsumer.processToClaims(jwt);
//        String username = jwtDecoded.getStringClaimValue("username"); // "MChambe4"
//
//        // ensure the required scope is claimed
//        String requiredScope = "das";
//        List<String> scopes = jwtDecoded.getStringListClaimValue("scope");
//        if (!scopes.stream().anyMatch(scope -> scope.equals(requiredScope))) {
//            throw new Exception("Required scope is not claimed: " + requiredScope);
//        }
//    }
//}
