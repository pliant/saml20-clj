(ns saml20-clj.shared
  (:require [clj-time.core :as ctime]
            [clj-time.format :as ctimeformat]
            [clojure.data.codec.base64 :as b64])
  (:import [java.io BufferedReader
                    ByteArrayInputStream
                    ByteArrayOutputStream
                    InputStreamReader]
           [java.util.zip DeflaterOutputStream
                          Deflater
                          InflaterInputStream
                          Inflater]
           [java.nio.charset Charset]))


; Time Functions

(def instant-format (ctimeformat/formatters :date-time-no-ms))

(defn make-issue-instant
  "Converts a date-time to a SAML 2.0 time string."
  [ii-date]
  (ctimeformat/unparse instant-format ii-date))


(defn time-since
  [time-span]
  (ctime/minus (ctime/now) time-span))


(defn timeout-filter-fn
  "Creates a function for clojure.core/filter to keep all dates after
  a given date."
  [timespan]
  (fn [i]
    (ctime/after? (second i) (time-since timespan))))


; Codec Functions

(def ^Charset UTF-8 (Charset/forName "UTF-8"))


(defn read-to-end
  [stream]
  (let [sb (StringBuilder.)]
    (with-open [reader (-> stream
                           InputStreamReader.
                           BufferedReader.)]
      (loop [c (.read reader)]
        (if (neg? c)
          (str sb)
          (do
            (.append sb (char c))
            (recur (.read reader))))))))


(defn str->inputstream
  "Unravels a string into an input stream so we can work with Java constructs."
  [unravel]
  (ByteArrayInputStream. (.getBytes unravel UTF-8)))


(defn byte-deflate
  "Compresses a byte array using zip compression."
  [str-bytes]
  (let [out (ByteArrayOutputStream.)
        deflater (DeflaterOutputStream. out (Deflater. -1 true) 1024)]
    (.write deflater str-bytes)
    (.close deflater)
    (.toByteArray out)))


(defn byte-inflate
  "Decompresses the bytes of zip compressed data into a string."
  [comp-bytes]
  (let [input (ByteArrayInputStream. comp-bytes)
        inflater (InflaterInputStream. input (Inflater. true) 1024)
        result (read-to-end inflater)]
    (.close inflater)
    result))


(defn str->bytes
  [some-string]
  (.getBytes some-string UTF-8))


(defn bytes->str
  [some-bytes]
  (String. some-bytes UTF-8))


(defn str->base64
  [base64able-string]
  (-> base64able-string str->bytes b64/encode bytes->str))

; Not Used
(defn base64->str
  [stringable-base64]
  (-> stringable-base64 str->bytes b64/decode bytes->str))


(defn str->deflate->base64
  [deflatable-str]
  (let [byte-str (str->bytes deflatable-str)]
    (bytes->str (b64/encode (byte-deflate byte-str)))))


(defn base64->inflate->str
  [string]
  (let [byte-str (str->bytes string)]
    (bytes->str (b64/decode byte-str))))
