(ns saml20-clj.xml-test
  (:require [clojure.test :refer [deftest testing is]]
            [saml20-clj.xml :refer [str->xmldoc]])
  (:import  [org.xml.sax SAXParseException]))


(deftest test-load-large-file
  (testing "Throws exception when loading large file"
    (is (thrown? SAXParseException (str->xmldoc (slurp "test-resources/xml-bomb.txt"))))))
