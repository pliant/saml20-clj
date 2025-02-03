(ns saml20-clj.crypto
  "Provides crypto and codec capabilities to the library."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.data.codec.base64 :as b64])
  (:import [java.io ByteArrayInputStream]
           [java.security KeyStore]
           [java.security.cert Certificate
                               CertificateFactory]
           [java.util Random]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))


(defn jcert->public-key
  "Extracts a public key object from a java cert object."
  [java-cert-obj]
  (.getPublicKey java-cert-obj))


(defn clean-x509-filter
  "Turns a base64 string into a byte array to be decoded, which includes sanitization."
  [x509-string]
  (-> x509-string
      (str/replace #"[\n ]" "")
      ((partial map byte))
      byte-array
      bytes))


(defn certificate-x509
  "Takes in a raw X.509 certificate string, parses it, and creates a Java certificate."
  [x509-string]
  (let [x509-byte-array (clean-x509-filter x509-string)
        fty (CertificateFactory/getInstance "X.509")
        bais (new ByteArrayInputStream (bytes (b64/decode x509-byte-array)))]
    (.generateCertificate fty bais)))


(defn random-bytes
  "Generate a byte array of a specific size with random bytes.  Default size is 20 bytes."
  ([] (random-bytes 20))
  ([size]
   (let [ba (byte-array size)]
     (doto (Random.)
           (.nextBytes ba)))))


(defn hexify
  "Convert byte sequence to hex string"
  [coll]
  (let [hex [\0 \1 \2 \3 \4 \5 \6 \7 \8 \9 \a \b \c \d \e \f]]
    (letfn [(hexify-byte [b]
              (let [v (bit-and b 0xFF)]
                [(hex (bit-shift-right v 4)) (hex (bit-and v 0x0F))]))]
      (apply str (mapcat hexify-byte coll)))))


(defn hmac-str
  "Generates a message authentication code as a hex string."
  [^SecretKeySpec key-spec ^String code]
  (let [mac (doto (Mac/getInstance "HmacSHA1")
              (.init key-spec))
        hs (.doFinal mac (.getBytes code "UTF-8"))]
    (hexify hs)))


(defn secret-key-spec
  "Creates a new SecretKey spec using HmacSHA1."
  []
  (new SecretKeySpec (random-bytes) "HmacSHA1"))


(defn file->keystore
  "Loads a Java Keystore from a file and returns it."
  [file-path password]
  (when (and (not (nil? file-path))
             (.exists (io/as-file file-path)))
    (with-open [is (io/input-stream file-path)]
      (doto (KeyStore/getInstance "JKS")
        (.load is (.toCharArray password))))))


(defn get-certificate-b64
  "Extracts a certificate from a keystore and encodes it using base 64."
  [^KeyStore keystore ^String alias]
  (when keystore
    (let [certificate (.getCertificate keystore alias)
          encoded     (.getEncoded ^Certificate certificate)]
      (-> encoded b64/encode (String. "UTF-8")))))
