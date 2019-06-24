(defproject kirasystems/saml20-clj "0.1.13-SNAPSHOT"
  :description "Basic SAML 2.0 library for SSO."
  :url "https://github.com/k2n/saml20-clj"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :source-paths ["src"]
  :dependencies [[clj-time "0.11.0"]
                 [compojure "1.5.0"]
                 [org.apache.santuario/xmlsec "2.0.4"]
                 [org.clojure/clojure "1.8.0"]
                 [org.clojure/data.codec "0.1.0"]
                 [org.clojure/data.xml "0.0.7"]
                 [org.clojure/data.zip "0.1.1"]
                 [org.opensaml/opensaml "2.6.4"]
                 [org.vlacs/helmsman "1.0.0-alpha5"]
                 [ring "1.4.0"]]
  :pedantic :warn
  :profiles {:dev {:source-paths ["dev" "test"]
                   :dependencies [[org.clojure/tools.namespace "0.2.10"]
                                  [org.clojure/tools.nrepl "0.2.3"]
                                  [hiccup "1.0.5"]
                                  [http-kit "2.1.18"]]}}
  :repositories [["releases" {:url "https://clojars.org/repo"
                              :sign-releases false
                              :username :env
                              :password :env}]]
  :release-tasks [["vcs" "assert-committed"]
                  ["change" "version" "leiningen.release/bump-version" "release"]
                  ["vcs" "commit"]
                  ["vcs" "tag" "--no-sign"]
                  ["change" "version" "leiningen.release/bump-version"]
                  ["vcs" "commit"]
                  ["vcs" "push"]])
