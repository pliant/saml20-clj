(ns ^{:doc "The compojure based routes for the SAML Service Provider (SP)"
      :author "Stelios Sfakianakis"}
  saml20-clj.routes
  (:require [compojure.core :as cc]
            [ring.util.response :refer [redirect]]
            [ring.util.codec :refer [form-encode]]
            [saml20-clj.crypto :as crypto]
            [saml20-clj.saml :as saml]
            [saml20-clj.sp :as sp]
            [saml20-clj.shared :as shared]
            [clojure.string :as str]))


(defn redirect-to-saml
  "Creates a ring response map with a location to include a SAML redirect."
  [continue-to-url]
  {:status  302 ;; Found
   :headers {"Location" (str "/saml?continue=" continue-to-url)}
   :body    ""})


(defn uri-query-str
  [clean-hash]
  (form-encode clean-hash))


(defn get-idp-redirect
  "Return Ring response for HTTP 302 redirect."
  [idp-url saml-request relay-state]
  (redirect
    (str idp-url
         (if (re-seq #"\?" idp-url) "&" "?")
         (let [saml-request (shared/str->deflate->base64 saml-request)]
           (uri-query-str
             {:SAMLRequest saml-request :RelayState relay-state})))))



(defn create-hmac-relay-state
  [secret-key-spec relay-state]
  (str relay-state ":" (crypto/hmac-str secret-key-spec relay-state)))


(defn valid-hmac-relay-state?
  [secret-key-spec hmac-relay-state]
  (let [[relay-state hmac] (str/split hmac-relay-state #":")
        valid? (= hmac (crypto/hmac-str secret-key-spec relay-state))]
    [valid? relay-state]))

;
; These functions just repeat what is used in routing.
;
(defn meta-response
  "Response function to handle GET /saml/meta"
  [req]
  (let [{:keys [app-name acs-uri cert]} (:saml20 req)]
    {:status 200
     :headers {"Content-type" "text/xml"}
     :body (sp/metadata app-name acs-uri cert)}))


(defn new-request-handler
  "Response function to handle GET /saml, which redirects to the IDP"
  [req]
  (let [continue-url (get-in req [:params :continue] "/")
        relay-state (create-hmac-relay-state
                      (get-in req [:saml20 :mutables :secret-key-spec])
                      continue-url)]
    (get-idp-redirect
      (get-in req [:saml20 :idp-uri])
      ((get-in req [:saml20 :saml20-req-factory!]))
      relay-state)))


(defn process-response-handler
  "Response function to handle POST /saml, receives assertions from the IDP about the user session."
  [{:keys [saml20 params session]}]
  (let [xml-response (shared/base64->inflate->str (:SAMLResponse params))
        [valid-relay-state? continue-url] (valid-hmac-relay-state?
                                            (get-in saml20 [:mutables :secret-key-spec])
                                            (:RelayState params))
        saml-resp (sp/xml-string->saml-resp xml-response)
        valid-signature? (if (:idp-cert saml20)
                           (sp/validate-saml-response-signature saml-resp (:idp-cert saml20))
                           true)
        valid? (and valid-relay-state? valid-signature?)
        saml-info (when valid?
                    (sp/saml-resp->assertions saml-resp (:decrypter saml20)))]
    (if valid?
      {:status 303
       :headers {"Location" continue-url}
       :session (assoc session :saml20 saml-info)
       :body ""}
      {:status 500
       :body "The SAML response from the IdP did not validate!"})))

;
;
;

(defn saml-routes
  "The SP routes. They can be combined with application specific routes. Also it is assumed that
  they are wrapped with compojure.handler/site or wrap-params and wrap-session.

  The single argument is a map containing the following fields:

  :app-name - The application's name
  :base-uri - The Base URI for the application i.e. its remotely accessible hostname and
              (if needed) port, e.g. https://example.org:8443 This is used for building the
              'AssertionConsumerService' URI for the HTTP-POST Binding, by prepending the
              base-uri to the '/saml' string.
  :idp-uri  - The URI for the IdP to use. This should be the URI for the HTTP-Redirect SAML Binding
  :idp-cert - The IdP certificate that contains the public key used by IdP for signing responses.
              This is optional: if not used no signature validation will be performed in the responses
  :keystore-file - The filename that is the Java keystore for the private key used by this SP for the
                   decryption of responses coming from IdP
  :keystore-password - The password for opening the keystore file
  :key-alias - The alias for the private key in the keystore

  The created routes are the following:

  - GET /saml/meta : This returns a SAML metadata XML file that has the needed information
                     for registering this SP. For example, it has the public key for this SP.

  - GET /saml : it redirects to the IdP with the SAML request envcoded in the URI per the
                HTTP-Redirect binding. This route accepts a 'continue' parameter that can
                have the relative URI, where the browser should be redirected to after the
                successful login in the IdP.

  - POST /saml : this is the endpoint for accepting the responses from the IdP. It then redirects
                 the browser to the 'continue-url' that is found in the RelayState paramete, or the '/' root
                 of the app.
  "
 [{:keys [app-name base-uri idp-uri idp-cert keystore-file keystore-password key-alias]}]
 (let [keystore (crypto/file->keystore keystore-file keystore-password)
       decrypter (sp/saml-decrypter keystore keystore-password key-alias)
       cert (crypto/get-certificate-b64 keystore key-alias)
       mutables (assoc (sp/generate-mutables)
                       :xml-signer (sp/saml-signer keystore keystore-password key-alias))

       acs-uri (str base-uri "/saml")
       saml-req-factory! (sp/create-request-factory mutables
                                                    idp-uri
                                                    saml/urn-redirect
                                                    app-name
                                                    acs-uri)
       prune-fn! (partial sp/prune-timed-out-ids!
                          (:saml-id-timeouts mutables))
       state {:mutables mutables
              :saml-req-factory! saml-req-factory!
              :timeout-pruner-fn! prune-fn!
              :certificate-x509 cert}]
   (cc/routes
     (cc/GET "/saml/meta" [] {:status 200
                              :headers {"Content-type" "text/xml"}
                              :body (sp/metadata app-name acs-uri cert)})
     (cc/GET "/saml" [:as req])
             ;;; Update this to actually do something. :|

     (cc/POST "/saml" {params :params session :session}
              (let [xml-response (shared/base64->inflate->str (:SAMLResponse params))
                    relay-state (:RelayState params)
                    [valid-relay-state? continue-url] (valid-hmac-relay-state? (:secret-key-spec mutables) relay-state)
                    saml-resp (sp/xml-string->saml-resp xml-response)
                    valid-signature? (if idp-cert
                                       (sp/validate-saml-response-signature saml-resp idp-cert)
                                       true)
                    valid? (and valid-relay-state? valid-signature?)
                    saml-info (when valid? (sp/saml-resp->assertions saml-resp decrypter))]
             ;;(prn saml-info)
               (if valid?
                 {:status  303 ;; See other
                  :headers {"Location" continue-url}
                  :session (assoc session :saml saml-info)
                  :body ""}
                 {:status 500
                  :body "The SAML response from IdP does not validate!"}))))))
