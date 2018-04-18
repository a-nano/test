
(asdf:defsystem "com.informatimago.pkcs11"
  :description "PKCS11 wrapper."
  :author "Pascal J. Bourguignon"
  :version "0.0.0"
  :license "AGPL3"
  :depends-on ("cffi")
  :components ((:file "pkcs11-cffi" :depends-on ())
               (:file "pkcs11"      :depends-on ("pkcs11-cffi")))
  #+adsf3 :in-order-to #+adsf3 ((asdf:test-op (asdf:test-op "com.informatimago.pkcs11.test"))))

;;;; THE END ;;;;
