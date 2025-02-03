(ns saml20-clj.saml)




(def urn-redirect "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
(def urn-success "urn:oasis:names:tc:SAML:2.0:status:Success")


(defn status-success?
  "Checks if the value passed is a status:Success URN"
  [status]
  (if (= status urn-success)
    true false))


;; https://www.purdue.edu/apps/account/docs/Shibboleth/Shibboleth_information.jsp
;;  Or
;; https://wiki.library.ucsf.edu/display/IAM/EDS+Attributes
(def attr->name
  "Converts an attribute URN to it's short name.  If a short name has not been defined
   the provided attribute URN is returned."
  (let [names {"urn:oid:0.9.2342.19200300.100.1.1" "uid"
               "urn:oid:0.9.2342.19200300.100.1.3" "mail"
               "urn:oid:2.16.840.1.113730.3.1.241" "displayName"
               "urn:oid:2.5.4.3" "cn"
               "urn:oid:2.5.4.4" "sn"
               "urn:oid:2.5.4.12" "title"
               "urn:oid:2.5.4.20" "phone"
               "urn:oid:2.5.4.42" "givenName"
               "urn:oid:2.5.6.8" "organizationalRole"
               "urn:oid:2.16.840.1.113730.3.1.3" "employeeNumber"
               "urn:oid:2.16.840.1.113730.3.1.4" "employeeType"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.1" "eduPersonAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.2" "eduPersonNickname"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.6" "eduPersonPrincipalName"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.9" "eduPersonScopedAffiliation"
               "urn:oid:1.3.6.1.4.1.5923.1.1.1.10" "eduPersonTargetedID"
               "urn:oid:1.3.6.1.4.1.5923.1.6.1.1" "eduCourseOffering"}]
    (fn [attr-oid]
      (get names attr-oid attr-oid))))
