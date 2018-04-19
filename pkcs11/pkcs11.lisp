;;;; -*- mode:lisp;coding:utf-8 -*-
;;;;**************************************************************************
;;;;FILE:               pkcs11.lisp
;;;;LANGUAGE:           Common-Lisp
;;;;SYSTEM:             Common-Lisp
;;;;USER-INTERFACE:     NONE
;;;;DESCRIPTION
;;;;
;;;;    XXX
;;;;
;;;;AUTHORS
;;;;    <PJB> Pascal J. Bourguignon <pjb@informatimago.com>
;;;;MODIFICATIONS
;;;;    2018-04-18 <PJB> Created.
;;;;BUGS
;;;;LEGAL
;;;;    AGPL3
;;;;
;;;;    Copyright Pascal J. Bourguignon 2018 - 2018
;;;;
;;;;    This program is free software: you can redistribute it and/or modify
;;;;    it under the terms of the GNU Affero General Public License as published by
;;;;    the Free Software Foundation, either version 3 of the License, or
;;;;    (at your option) any later version.
;;;;
;;;;    This program is distributed in the hope that it will be useful,
;;;;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;;    GNU Affero General Public License for more details.
;;;;
;;;;    You should have received a copy of the GNU Affero General Public License
;;;;    along with this program.  If not, see <http://www.gnu.org/licenses/>.
;;;;**************************************************************************

(defpackage "COM.INFORMATIMAGO.PKCS11"
  (:use "COMMON-LISP" "CFFI")
  (:import-from "COM.INFORMATIMAGO.PKCS11.LOW" "LOAD-LIBRARY")
  (:export "PKCS11-ERROR"
           "PKCS11-ERROR-CODE" "PKCS11-ERROR-LABEL" "PKCS11-ERROR-FUNCTION"
           "CHECK-RV" "WITH-PKCS11"
           "LOAD-LIBRARY")
  (:export "GET-INFO")

  (:documentation "Lispy interface over pkcs11 version 2.02"))

(in-package "COM.INFORMATIMAGO.PKCS11")



(defun flags (operation flags map)
  (ecase operation
    ((:decode)
     (loop :for (flag . keyword) :in map
           :when (= flag (logand flags flag))
             :collect keyword))
    ((:encode)
     (loop :for (flag . keyword) :in map
           :when (member keyword flags)
             :sum flag))))

(defun enum (operation value map)
  (ecase operation
    ((:decode) (or (cdr (assoc  value map)) value))
    ((:encode) (or (car (rassoc value map))
                   (error "Unknown enum keyword ~S, expected one of `{~S~^ ~}."
                          value (mapcar (function cdr) map))))))

(defmacro define-flag-converter (name map)
  `(defun ,name (operation value)
     (flags operation value (load-time-value
                             (list ,@(mapcar (lambda (entry)
                                               "(ck-constant keyword) -> (cons ck-constant keyword)"
                                               `(cons ,@entry))
                                             map))))))

(defmacro define-enum-converter (name map)
  `(defun ,name (operation value)
     (enum operation value (load-time-value
                            (list ,@(mapcar (lambda (entry)
                                              "(ck-constant keyword) -> (cons ck-constant keyword)"
                                              `(cons ,@entry))
                                            map))))))

(define-enum-converter return-value
    ((%ck:+ok+                                 :ok)
     (%ck:+cancel+                             :cancel)
     (%ck:+host-memory+                        :host-memory)
     (%ck:+slot-id-invalid+                    :slot-id-invalid)
     (%ck:+general-error+                      :general-error)
     (%ck:+function-failed+                    :function-failed)
     (%ck:+arguments-bad+                      :arguments-bad)
     (%ck:+no-event+                           :no-event)
     (%ck:+need-to-create-threads+             :need-to-create-threads)
     (%ck:+cant-lock+                          :cant-lock)
     (%ck:+attribute-read-only+                :attribute-read-only)
     (%ck:+attribute-sensitive+                :attribute-sensitive)
     (%ck:+attribute-type-invalid+             :attribute-type-invalid)
     (%ck:+attribute-value-invalid+            :attribute-value-invalid)
     (%ck:+data-invalid+                       :data-invalid)
     (%ck:+data-len-range+                     :data-len-range)
     (%ck:+device-error+                       :device-error)
     (%ck:+device-memory+                      :device-memory)
     (%ck:+device-removed+                     :device-removed)
     (%ck:+encrypted-data-invalid+             :encrypted-data-invalid)
     (%ck:+encrypted-data-len-range+           :encrypted-data-len-range)
     (%ck:+function-canceled+                  :function-canceled)
     (%ck:+function-not-parallel+              :function-not-parallel)
     (%ck:+function-not-supported+             :function-not-supported)
     (%ck:+key-handle-invalid+                 :key-handle-invalid)
     (%ck:+key-size-range+                     :key-size-range)
     (%ck:+key-type-inconsistent+              :key-type-inconsistent)
     (%ck:+key-not-needed+                     :key-not-needed)
     (%ck:+key-changed+                        :key-changed)
     (%ck:+key-needed+                         :key-needed)
     (%ck:+key-indigestible+                   :key-indigestible)
     (%ck:+key-function-not-permitted+         :key-function-not-permitted)
     (%ck:+key-not-wrappable+                  :key-not-wrappable)
     (%ck:+key-unextractable+                  :key-unextractable)
     (%ck:+mechanism-invalid+                  :mechanism-invalid)
     (%ck:+mechanism-param-invalid+            :mechanism-param-invalid)
     (%ck:+object-handle-invalid+              :object-handle-invalid)
     (%ck:+operation-active+                   :operation-active)
     (%ck:+operation-not-initialized+          :operation-not-initialized)
     (%ck:+pin-incorrect+                      :pin-incorrect)
     (%ck:+pin-invalid+                        :pin-invalid)
     (%ck:+pin-len-range+                      :pin-len-range)
     (%ck:+pin-expired+                        :pin-expired)
     (%ck:+pin-locked+                         :pin-locked)
     (%ck:+session-closed+                     :session-closed)
     (%ck:+session-count+                      :session-count)
     (%ck:+session-handle-invalid+             :session-handle-invalid)
     (%ck:+session-parallel-not-supported+     :session-parallel-not-supported)
     (%ck:+session-read-only+                  :session-read-only)
     (%ck:+session-exists+                     :session-exists)
     (%ck:+session-read-only-exists+           :session-read-only-exists)
     (%ck:+session-read-write-so-exists+       :session-read-write-so-exists)
     (%ck:+signature-invalid+                  :signature-invalid)
     (%ck:+signature-len-range+                :signature-len-range)
     (%ck:+template-incomplete+                :template-incomplete)
     (%ck:+template-inconsistent+              :template-inconsistent)
     (%ck:+token-not-present+                  :token-not-present)
     (%ck:+token-not-recognized+               :token-not-recognized)
     (%ck:+token-write-protected+              :token-write-protected)
     (%ck:+unwrapping-key-handle-invalid+      :unwrapping-key-handle-invalid)
     (%ck:+unwrapping-key-size-range+          :unwrapping-key-size-range)
     (%ck:+unwrapping-key-type-inconsistent+   :unwrapping-key-type-inconsistent)
     (%ck:+user-already-logged-in+             :user-already-logged-in)
     (%ck:+user-not-logged-in+                 :user-not-logged-in)
     (%ck:+user-pin-not-initialized+           :user-pin-not-initialized)
     (%ck:+user-type-invalid+                  :user-type-invalid)
     (%ck:+user-another-already-logged-in+     :user-another-already-logged-in)
     (%ck:+user-too-many-types+                :user-too-many-types)
     (%ck:+wrapped-key-invalid+                :wrapped-key-invalid)
     (%ck:+wrapped-key-len-range+              :wrapped-key-len-range)
     (%ck:+wrapping-key-handle-invalid+        :wrapping-key-handle-invalid)
     (%ck:+wrapping-key-size-range+            :wrapping-key-size-range)
     (%ck:+wrapping-key-type-inconsistent+     :wrapping-key-type-inconsistent)
     (%ck:+random-seed-not-supported+          :random-seed-not-supported)
     (%ck:+random-no-rng+                      :random-no-rng)
     (%ck:+domain-params-invalid+              :domain-params-invalid)
     (%ck:+buffer-too-small+                   :buffer-too-small)
     (%ck:+saved-state-invalid+                :saved-state-invalid)
     (%ck:+information-sensitive+              :information-sensitive)
     (%ck:+state-unsaveable+                   :state-unsaveable)
     (%ck:+cryptoki-not-initialized+           :cryptoki-not-initialized)
     (%ck:+cryptoki-already-initialized+       :cryptoki-already-initialized)
     (%ck:+mutex-bad+                          :mutex-bad)
     (%ck:+mutex-not-locked+                   :mutex-not-locked)
     (%ck:+function-rejected+                  :function-rejected)))

(define-flag-converter convert-slot-info-flags
    ((%ck:+token-present+     :token-present)
     (%ck:+removable-device+  :removable-device)
     (%ck:+hw-slot+           :hardware-slot)
     (%ck:+array-attribute+   :array-attribute)))

(define-flag-converter convert-token-info-flags
    ((%ck:+rng+                            :rng)
     (%ck:+write-protected+                :write-protected)
     (%ck:+login-required+                 :login-required)
     (%ck:+user-pin-initialized+           :user-pin-initialized)
     (%ck:+restore-key-not-needed+         :restore-key-not-needed)
     (%ck:+clock-on-token+                 :clock-on-token)
     (%ck:+protected-authentication-path+  :protected-authentication-path)
     (%ck:+dual-crypto-operations+         :dual-crypto-operations)
     (%ck:+token-initialized+              :token-initialized)
     (%ck:+secondary-authentication+       :secondary-authentication)
     (%ck:+user-pin-count-low+             :user-pin-count-low)
     (%ck:+user-pin-final-try+             :user-pin-final-try)
     (%ck:+user-pin-locked+                :user-pin-locked)
     (%ck:+user-pin-to-be-changed+         :user-pin-to-be-changed)
     (%ck:+so-pin-count-low+               :so-pin-count-low)
     (%ck:+so-pin-final-try+               :so-pin-final-try)
     (%ck:+so-pin-locked+                  :so-pin-locked)
     (%ck:+so-pin-to-be-changed+           :so-pin-to-be-changed)))

(define-enum-converter user-type
    ((%ck:+so+                :so)
     (%ck:+user+              :user)
     (%ck:+context-specific+  :context-specific)))

(define-enum-converter state
    ((%ck:+ro-public-session+  :ro-public-session)
     (%ck:+ro-user-functions+  :ro-user-functions)
     (%ck:+rw-public-session+  :rw-public-session)
     (%ck:+rw-user-functions+  :rw-user-functions)
     (%ck:+rw-so-functions+    :rw-so-functions)))

(define-flag-converter convert-session-info-flags
    ((%ck:+rw-session+        :rw-session)
     (%ck:+serial-session+    :serial-session)))

(define-flag-converter convert-wait-for-slot-event-flags
    ((%ck:+DONT-BLOCK+ :dont-block)))

(define-enum-converter object-class
    ((%ck:+o-data+              :data)
     (%ck:+o-certificate+       :certificate)
     (%ck:+o-public-key+        :public-key)
     (%ck:+o-private-key+       :private-key)
     (%ck:+o-secret-key+        :secret-key)
     (%ck:+o-hw-feature+        :hw-feature)
     (%ck:+o-domain-parameters+ :domain-parameters)
     (%ck:+o-mechanism+         :mechanism)
     (%ck:+vendor-defined+      :vendor-defined)))

(define-enum-converter hardware-feature
    ((%ck:+h-monotonic-counter+ :monotonic-count)
     (%ck:+h-clock+             :clock)
     (%ck:+h-user-interface+    :user-interface)
     (%ck:+vendor-defined+      :vendor-defined)))

(define-enum-converter key-type
    ((%ck:+k-rsa+             :rsa)
     (%ck:+k-dsa+             :dsa)
     (%ck:+k-dh+              :dh)
     (%ck:+k-ecdsa+           :ecdsa)
     (%ck:+k-ec+              :ec)
     (%ck:+k-x9-42-dh+        :x9-42-dh)
     (%ck:+k-kea+             :kea)
     (%ck:+k-generic-secret+  :generic-secret)
     (%ck:+k-rc2+             :rc2)
     (%ck:+k-rc4+             :rc4)
     (%ck:+k-des+             :des)
     (%ck:+k-des2+            :des2)
     (%ck:+k-des3+            :des3)
     (%ck:+k-cast+            :cast)
     (%ck:+k-cast3+           :cast3)
     (%ck:+k-cast128+         :cast128)
     (%ck:+k-rc5+             :rc5)
     (%ck:+k-idea+            :idea)
     (%ck:+k-skipjack+        :skipjack)
     (%ck:+k-baton+           :baton)
     (%ck:+k-juniper+         :juniper)
     (%ck:+k-cdmf+            :cdmf)
     (%ck:+k-aes+             :aes)
     (%ck:+k-blowfish+        :blowfish)
     (%ck:+k-twofish+         :twofish)
     (%ck:+vendor-defined+    :vendor-defined)))

(define-enum-converter certificate-type
    ((%ck:+c-x-509+            :x-509)
     (%ck:+c-x-509-attr-cert+  :x-509-attr-cert)
     (%ck:+c-wtls+             :wtls)
     (%ck:+vendor-defined+     :vendor-defined)))

(define-enum-converter attribute-type
    ((%ck:+a-class+                       :class)
     (%ck:+a-token+                       :token)
     (%ck:+a-private+                     :private)
     (%ck:+a-label+                       :label)
     (%ck:+a-application+                 :application)
     (%ck:+a-value+                       :value)
     (%ck:+a-object-id+                   :object-id)
     (%ck:+a-certificate-type+            :certificate-type)
     (%ck:+a-issuer+                      :issuer)
     (%ck:+a-serial-number+               :serial-number)
     (%ck:+a-ac-issuer+                   :ac-issuer)
     (%ck:+a-owner+                       :owner)
     (%ck:+a-attr-types+                  :attr-types)
     (%ck:+a-trusted+                     :trusted)
     (%ck:+a-certificate-category+        :certificate-category)
     (%ck:+a-java-midp-security-domain+   :java-midp-security-domain)
     (%ck:+a-url+                         :url)
     (%ck:+a-hash-of-subject-public-key+  :hash-of-subject-public-key)
     (%ck:+a-hash-of-issuer-public-key+   :hash-of-issuer-public-key)
     (%ck:+a-check-value+                 :check-value)
     (%ck:+a-key-type+                    :key-type)
     (%ck:+a-subject+                     :subject)
     (%ck:+a-id+                          :id)
     (%ck:+a-sensitive+                   :sensitive)
     (%ck:+a-encrypt+                     :encrypt)
     (%ck:+a-decrypt+                     :decrypt)
     (%ck:+a-wrap+                        :wrap)
     (%ck:+a-unwrap+                      :unwrap)
     (%ck:+a-sign+                        :sign)
     (%ck:+a-sign-recover+                :sign-recover)
     (%ck:+a-verify+                      :verify)
     (%ck:+a-verify-recover+              :verify-recover)
     (%ck:+a-derive+                      :derive)
     (%ck:+a-start-date+                  :start-date)
     (%ck:+a-end-date+                    :end-date)
     (%ck:+a-modulus+                     :modulus)
     (%ck:+a-modulus-bits+                :modulus-bits)
     (%ck:+a-public-exponent+             :public-exponent)
     (%ck:+a-private-exponent+            :private-exponent)
     (%ck:+a-prime-1+                     :prime-1)
     (%ck:+a-prime-2+                     :prime-2)
     (%ck:+a-exponent-1+                  :exponent-1)
     (%ck:+a-exponent-2+                  :exponent-2)
     (%ck:+a-coefficient+                 :coefficient)
     (%ck:+a-prime+                       :prime)
     (%ck:+a-subprime+                    :subprime)
     (%ck:+a-base+                        :base)
     (%ck:+a-prime-bits+                  :prime-bits)
     (%ck:+a-sub-prime-bits+              :sub-prime-bits)
     (%ck:+a-value-bits+                  :value-bits)
     (%ck:+a-value-len+                   :value-len)
     (%ck:+a-extractable+                 :extractable)
     (%ck:+a-local+                       :local)
     (%ck:+a-never-extractable+           :never-extractable)
     (%ck:+a-always-sensitive+            :always-sensitive)
     (%ck:+a-key-gen-mechanism+           :key-gen-mechanism)
     (%ck:+a-modifiable+                  :modifiable)
     (%ck:+a-ecdsa-params+                :ecdsa-params)
     (%ck:+a-ec-params+                   :ec-params)
     (%ck:+a-ec-point+                    :ec-point)
     (%ck:+a-secondary-auth+              :secondary-auth)
     (%ck:+a-auth-pin-flags+              :auth-pin-flags)
     (%ck:+a-always-authenticate+         :always-authenticate)
     (%ck:+a-wrap-with-trusted+           :wrap-with-trusted)
     (%ck:+a-hw-feature-type+             :hw-feature-type)
     (%ck:+a-reset-on-init+               :reset-on-init)
     (%ck:+a-has-reset+                   :has-reset)
     (%ck:+a-pixel-x+                     :pixel-x)
     (%ck:+a-pixel-y+                     :pixel-y)
     (%ck:+a-resolution+                  :resolution)
     (%ck:+a-char-rows+                   :char-rows)
     (%ck:+a-char-columns+                :char-columns)
     (%ck:+a-color+                       :color)
     (%ck:+a-bits-per-pixel+              :bits-per-pixel)
     (%ck:+a-char-sets+                   :char-sets)
     (%ck:+a-encoding-methods+            :encoding-methods)
     (%ck:+a-mime-types+                  :mime-types)
     (%ck:+a-mechanism-type+              :mechanism-type)
     (%ck:+a-required-cms-attributes+     :required-cms-attributes)
     (%ck:+a-default-cms-attributes+      :default-cms-attributes)
     (%ck:+a-supported-cms-attributes+    :supported-cms-attributes)
     (%ck:+a-wrap-template+               :wrap-template)
     (%ck:+a-unwrap-template+             :unwrap-template)
     (%ck:+a-allowed-mechanisms+          :allowed-mechanisms)
     (%ck:+vendor-defined+                :vendor-defined)))

(define-enum-converter mechanism-type
    ((%ck:+m-rsa-pkcs-key-pair-gen+      :rsa-pkcs-key-pair-gen)
     (%ck:+m-rsa-pkcs+                   :rsa-pkcs)
     (%ck:+m-rsa-9796+                   :rsa-9796)
     (%ck:+m-rsa-x-509+                  :rsa-x-509)
     (%ck:+m-md2-rsa-pkcs+               :md2-rsa-pkcs)
     (%ck:+m-md5-rsa-pkcs+               :md5-rsa-pkcs)
     (%ck:+m-sha1-rsa-pkcs+              :sha1-rsa-pkcs)
     (%ck:+m-ripemd128-rsa-pkcs+         :ripemd128-rsa-pkcs)
     (%ck:+m-ripemd160-rsa-pkcs+         :ripemd160-rsa-pkcs)
     (%ck:+m-rsa-pkcs-oaep+              :rsa-pkcs-oaep)
     (%ck:+m-rsa-x9-31-key-pair-gen+     :rsa-x9-31-key-pair-gen)
     (%ck:+m-rsa-x9-31+                  :rsa-x9-31)
     (%ck:+m-sha1-rsa-x9-31+             :sha1-rsa-x9-31)
     (%ck:+m-rsa-pkcs-pss+               :rsa-pkcs-pss)
     (%ck:+m-sha1-rsa-pkcs-pss+          :sha1-rsa-pkcs-pss)
     (%ck:+m-dsa-key-pair-gen+           :dsa-key-pair-gen)
     (%ck:+m-dsa+                        :dsa)
     (%ck:+m-dsa-sha1+                   :dsa-sha1)
     (%ck:+m-dh-pkcs-key-pair-gen+       :dh-pkcs-key-pair-gen)
     (%ck:+m-dh-pkcs-derive+             :dh-pkcs-derive)
     (%ck:+m-x9-42-dh-key-pair-gen+      :x9-42-dh-key-pair-gen)
     (%ck:+m-x9-42-dh-derive+            :x9-42-dh-derive)
     (%ck:+m-x9-42-dh-hybrid-derive+     :x9-42-dh-hybrid-derive)
     (%ck:+m-x9-42-mqv-derive+           :x9-42-mqv-derive)
     (%ck:+m-sha256-rsa-pkcs+            :sha256-rsa-pkcs)
     (%ck:+m-sha384-rsa-pkcs+            :sha384-rsa-pkcs)
     (%ck:+m-sha512-rsa-pkcs+            :sha512-rsa-pkcs)
     (%ck:+m-sha256-rsa-pkcs-pss+        :sha256-rsa-pkcs-pss)
     (%ck:+m-sha384-rsa-pkcs-pss+        :sha384-rsa-pkcs-pss)
     (%ck:+m-sha512-rsa-pkcs-pss+        :sha512-rsa-pkcs-pss)
     (%ck:+m-rc2-key-gen+                :rc2-key-gen)
     (%ck:+m-rc2-ecb+                    :rc2-ecb)
     (%ck:+m-rc2-cbc+                    :rc2-cbc)
     (%ck:+m-rc2-mac+                    :rc2-mac)
     (%ck:+m-rc2-mac-general+            :rc2-mac-general)
     (%ck:+m-rc2-cbc-pad+                :rc2-cbc-pad)
     (%ck:+m-rc4-key-gen+                :rc4-key-gen)
     (%ck:+m-rc4+                        :rc4)
     (%ck:+m-des-key-gen+                :des-key-gen)
     (%ck:+m-des-ecb+                    :des-ecb)
     (%ck:+m-des-cbc+                    :des-cbc)
     (%ck:+m-des-mac+                    :des-mac)
     (%ck:+m-des-mac-general+            :des-mac-general)
     (%ck:+m-des-cbc-pad+                :des-cbc-pad)
     (%ck:+m-des2-key-gen+               :des2-key-gen)
     (%ck:+m-des3-key-gen+               :des3-key-gen)
     (%ck:+m-des3-ecb+                   :des3-ecb)
     (%ck:+m-des3-cbc+                   :des3-cbc)
     (%ck:+m-des3-mac+                   :des3-mac)
     (%ck:+m-des3-mac-general+           :des3-mac-general)
     (%ck:+m-des3-cbc-pad+               :des3-cbc-pad)
     (%ck:+m-cdmf-key-gen+               :cdmf-key-gen)
     (%ck:+m-cdmf-ecb+                   :cdmf-ecb)
     (%ck:+m-cdmf-cbc+                   :cdmf-cbc)
     (%ck:+m-cdmf-mac+                   :cdmf-mac)
     (%ck:+m-cdmf-mac-general+           :cdmf-mac-general)
     (%ck:+m-cdmf-cbc-pad+               :cdmf-cbc-pad)
     (%ck:+m-md2+                        :md2)
     (%ck:+m-md2-hmac+                   :md2-hmac)
     (%ck:+m-md2-hmac-general+           :md2-hmac-general)
     (%ck:+m-md5+                        :md5)
     (%ck:+m-md5-hmac+                   :md5-hmac)
     (%ck:+m-md5-hmac-general+           :md5-hmac-general)
     (%ck:+m-sha-1+                      :sha-1)
     (%ck:+m-sha-1-hmac+                 :sha-1-hmac)
     (%ck:+m-sha-1-hmac-general+         :sha-1-hmac-general)
     (%ck:+m-ripemd128+                  :ripemd128)
     (%ck:+m-ripemd128-hmac+             :ripemd128-hmac)
     (%ck:+m-ripemd128-hmac-general+     :ripemd128-hmac-general)
     (%ck:+m-ripemd160+                  :ripemd160)
     (%ck:+m-ripemd160-hmac+             :ripemd160-hmac)
     (%ck:+m-ripemd160-hmac-general+     :ripemd160-hmac-general)
     (%ck:+m-sha256+                     :sha256)
     (%ck:+m-sha256-hmac+                :sha256-hmac)
     (%ck:+m-sha256-hmac-general+        :sha256-hmac-general)
     (%ck:+m-sha384+                     :sha384)
     (%ck:+m-sha384-hmac+                :sha384-hmac)
     (%ck:+m-sha384-hmac-general+        :sha384-hmac-general)
     (%ck:+m-sha512+                     :sha512)
     (%ck:+m-sha512-hmac+                :sha512-hmac)
     (%ck:+m-sha512-hmac-general+        :sha512-hmac-general)
     (%ck:+m-cast-key-gen+               :cast-key-gen)
     (%ck:+m-cast-ecb+                   :cast-ecb)
     (%ck:+m-cast-cbc+                   :cast-cbc)
     (%ck:+m-cast-mac+                   :cast-mac)
     (%ck:+m-cast-mac-general+           :cast-mac-general)
     (%ck:+m-cast-cbc-pad+               :cast-cbc-pad)
     (%ck:+m-cast3-key-gen+              :cast3-key-gen)
     (%ck:+m-cast3-ecb+                  :cast3-ecb)
     (%ck:+m-cast3-cbc+                  :cast3-cbc)
     (%ck:+m-cast3-mac+                  :cast3-mac)
     (%ck:+m-cast3-mac-general+          :cast3-mac-general)
     (%ck:+m-cast3-cbc-pad+              :cast3-cbc-pad)
     (%ck:+m-cast5-key-gen+              :cast5-key-gen)
     (%ck:+m-cast128-key-gen+            :cast128-key-gen)
     (%ck:+m-cast5-ecb+                  :cast5-ecb)
     (%ck:+m-cast128-ecb+                :cast128-ecb)
     (%ck:+m-cast5-cbc+                  :cast5-cbc)
     (%ck:+m-cast128-cbc+                :cast128-cbc)
     (%ck:+m-cast5-mac+                  :cast5-mac)
     (%ck:+m-cast128-mac+                :cast128-mac)
     (%ck:+m-cast5-mac-general+          :cast5-mac-general)
     (%ck:+m-cast128-mac-general+        :cast128-mac-general)
     (%ck:+m-cast5-cbc-pad+              :cast5-cbc-pad)
     (%ck:+m-cast128-cbc-pad+            :cast128-cbc-pad)
     (%ck:+m-rc5-key-gen+                :rc5-key-gen)
     (%ck:+m-rc5-ecb+                    :rc5-ecb)
     (%ck:+m-rc5-cbc+                    :rc5-cbc)
     (%ck:+m-rc5-mac+                    :rc5-mac)
     (%ck:+m-rc5-mac-general+            :rc5-mac-general)
     (%ck:+m-rc5-cbc-pad+                :rc5-cbc-pad)
     (%ck:+m-idea-key-gen+               :idea-key-gen)
     (%ck:+m-idea-ecb+                   :idea-ecb)
     (%ck:+m-idea-cbc+                   :idea-cbc)
     (%ck:+m-idea-mac+                   :idea-mac)
     (%ck:+m-idea-mac-general+           :idea-mac-general)
     (%ck:+m-idea-cbc-pad+               :idea-cbc-pad)
     (%ck:+m-generic-secret-key-gen+     :generic-secret-key-gen)
     (%ck:+m-concatenate-base-and-key+   :concatenate-base-and-key)
     (%ck:+m-concatenate-base-and-data+  :concatenate-base-and-data)
     (%ck:+m-concatenate-data-and-base+  :concatenate-data-and-base)
     (%ck:+m-xor-base-and-data+          :xor-base-and-data)
     (%ck:+m-extract-key-from-key+       :extract-key-from-key)
     (%ck:+m-ssl3-pre-master-key-gen+    :ssl3-pre-master-key-gen)
     (%ck:+m-ssl3-master-key-derive+     :ssl3-master-key-derive)
     (%ck:+m-ssl3-key-and-mac-derive+    :ssl3-key-and-mac-derive)
     (%ck:+m-ssl3-master-key-derive-dh+  :ssl3-master-key-derive-dh)
     (%ck:+m-tls-pre-master-key-gen+     :tls-pre-master-key-gen)
     (%ck:+m-tls-master-key-derive+      :tls-master-key-derive)
     (%ck:+m-tls-key-and-mac-derive+     :tls-key-and-mac-derive)
     (%ck:+m-tls-master-key-derive-dh+   :tls-master-key-derive-dh)
     (%ck:+m-ssl3-md5-mac+               :ssl3-md5-mac)
     (%ck:+m-ssl3-sha1-mac+              :ssl3-sha1-mac)
     (%ck:+m-md5-key-derivation+         :md5-key-derivation)
     (%ck:+m-md2-key-derivation+         :md2-key-derivation)
     (%ck:+m-sha1-key-derivation+        :sha1-key-derivation)
     (%ck:+m-pbe-md2-des-cbc+            :pbe-md2-des-cbc)
     (%ck:+m-pbe-md5-des-cbc+            :pbe-md5-des-cbc)
     (%ck:+m-pbe-md5-cast-cbc+           :pbe-md5-cast-cbc)
     (%ck:+m-pbe-md5-cast3-cbc+          :pbe-md5-cast3-cbc)
     (%ck:+m-pbe-md5-cast5-cbc+          :pbe-md5-cast5-cbc)
     (%ck:+m-pbe-md5-cast128-cbc+        :pbe-md5-cast128-cbc)
     (%ck:+m-pbe-sha1-cast5-cbc+         :pbe-sha1-cast5-cbc)
     (%ck:+m-pbe-sha1-cast128-cbc+       :pbe-sha1-cast128-cbc)
     (%ck:+m-pbe-sha1-rc4-128+           :pbe-sha1-rc4-128)
     (%ck:+m-pbe-sha1-rc4-40+            :pbe-sha1-rc4-40)
     (%ck:+m-pbe-sha1-des3-ede-cbc+      :pbe-sha1-des3-ede-cbc)
     (%ck:+m-pbe-sha1-des2-ede-cbc+      :pbe-sha1-des2-ede-cbc)
     (%ck:+m-pbe-sha1-rc2-128-cbc+       :pbe-sha1-rc2-128-cbc)
     (%ck:+m-pbe-sha1-rc2-40-cbc+        :pbe-sha1-rc2-40-cbc)
     (%ck:+m-pkcs5-pbkd2+                :pkcs5-pbkd2)
     (%ck:+m-pba-sha1-with-sha1-hmac+    :pba-sha1-with-sha1-hmac)
     (%ck:+m-key-wrap-lynks+             :key-wrap-lynks)
     (%ck:+m-key-wrap-set-oaep+          :key-wrap-set-oaep)
     (%ck:+m-skipjack-key-gen+           :skipjack-key-gen)
     (%ck:+m-skipjack-ecb64+             :skipjack-ecb64)
     (%ck:+m-skipjack-cbc64+             :skipjack-cbc64)
     (%ck:+m-skipjack-ofb64+             :skipjack-ofb64)
     (%ck:+m-skipjack-cfb64+             :skipjack-cfb64)
     (%ck:+m-skipjack-cfb32+             :skipjack-cfb32)
     (%ck:+m-skipjack-cfb16+             :skipjack-cfb16)
     (%ck:+m-skipjack-cfb8+              :skipjack-cfb8)
     (%ck:+m-skipjack-wrap+              :skipjack-wrap)
     (%ck:+m-skipjack-private-wrap+      :skipjack-private-wrap)
     (%ck:+m-skipjack-relayx+            :skipjack-relayx)
     (%ck:+m-kea-key-pair-gen+           :kea-key-pair-gen)
     (%ck:+m-kea-key-derive+             :kea-key-derive)
     (%ck:+m-fortezza-timestamp+         :fortezza-timestamp)
     (%ck:+m-baton-key-gen+              :baton-key-gen)
     (%ck:+m-baton-ecb128+               :baton-ecb128)
     (%ck:+m-baton-ecb96+                :baton-ecb96)
     (%ck:+m-baton-cbc128+               :baton-cbc128)
     (%ck:+m-baton-counter+              :baton-counter)
     (%ck:+m-baton-shuffle+              :baton-shuffle)
     (%ck:+m-baton-wrap+                 :baton-wrap)
     (%ck:+m-ecdsa-key-pair-gen+         :ecdsa-key-pair-gen)
     (%ck:+m-ec-key-pair-gen+            :ec-key-pair-gen)
     (%ck:+m-ecdsa+                      :ecdsa)
     (%ck:+m-ecdsa-sha1+                 :ecdsa-sha1)
     (%ck:+m-ecdh1-derive+               :ecdh1-derive)
     (%ck:+m-ecdh1-cofactor-derive+      :ecdh1-cofactor-derive)
     (%ck:+m-ecmqv-derive+               :ecmqv-derive)
     (%ck:+m-juniper-key-gen+            :juniper-key-gen)
     (%ck:+m-juniper-ecb128+             :juniper-ecb128)
     (%ck:+m-juniper-cbc128+             :juniper-cbc128)
     (%ck:+m-juniper-counter+            :juniper-counter)
     (%ck:+m-juniper-shuffle+            :juniper-shuffle)
     (%ck:+m-juniper-wrap+               :juniper-wrap)
     (%ck:+m-fasthash+                   :fasthash)
     (%ck:+m-aes-key-gen+                :aes-key-gen)
     (%ck:+m-aes-ecb+                    :aes-ecb)
     (%ck:+m-aes-cbc+                    :aes-cbc)
     (%ck:+m-aes-mac+                    :aes-mac)
     (%ck:+m-aes-mac-general+            :aes-mac-general)
     (%ck:+m-aes-cbc-pad+                :aes-cbc-pad)
     (%ck:+m-dsa-parameter-gen+          :dsa-parameter-gen)
     (%ck:+m-dh-pkcs-parameter-gen+      :dh-pkcs-parameter-gen)
     (%ck:+m-x9-42-dh-parameter-gen+     :x9-42-dh-parameter-gen)
     (%ck:+vendor-defined+               :vendor-defined)))

(define-flag-converter convert-mechanism-info-flags
    ((%ck:+f-hw+                 :hw)
     (%ck:+f-encrypt+            :encrypt)
     (%ck:+f-decrypt+            :decrypt)
     (%ck:+f-digest+             :digest)
     (%ck:+f-sign+               :sign)
     (%ck:+f-sign-recover+       :sign-recover)
     (%ck:+f-verify+             :verify)
     (%ck:+f-verify-recover+     :verify-recover)
     (%ck:+f-generate+           :generate)
     (%ck:+f-generate-key-pair+  :generate-key-pair)
     (%ck:+f-wrap+               :wrap)
     (%ck:+f-unwrap+             :unwrap)
     (%ck:+f-derive+             :derive)
     (%ck:+f-extension+          :extension)))




(define-condition pkcs11-error (error)
  ((label      :initarg :label     :reader pkcs11-error-label)
   (code       :initarg :code      :reader pkcs11-error-code)
   (function   :initarg :function  :reader pkcs11-error-function))
  (:report (lambda (condition stream)
             (format stream "PKCS11 Error: ~A (~A) in ~A"
                     (pkcs11-error-label condition)
                     (pkcs11-error-code condition)
                     (pkcs11-error-function condition))
             condition)))

(defun check-rv (rv &optional function)
  (if (zerop rv)
      (values)
      (error 'pkcs11-error :label (return-value :decode rv)
                           :code rv
                           :function function)))

(defmacro with-pkcs11 (&body body)
  `(progn
     (check-rv (%ck:initialize (cffi:null-pointer)) "C_Initialize")
     (unwind-protect (progn ,@body)
       (check-rv (%ck:finalize (cffi:null-pointer)) "C_Finalize"))))


(defstruct version
  major
  minor)

(defun version (operation version)
  (ecase operation
    ((:decode) (with-foreign-slots ((%ck:major %ck:minor) version (:struct %ck:version))
                 (make-version :major %ck:major
                               :minor %ck:minor)))))

(defstruct info
  cryptoki-version
  manufacturer-id
  flags
  library-description
  library-version)

(defun get-info ()
    (with-foreign-object (info '(:struct %ck:info))
      (check-rv (%ck:get-info info) "C_GetInfo")
      (flet ((str (slot size)
               (foreign-string-to-lisp
                (foreign-slot-pointer info '(:struct %ck:info) slot)
                :max-chars size :encoding :ascii))
             (ver (slot)
               (version :decode (foreign-slot-pointer info '(:struct %ck:info) slot))))
        (make-info
         :cryptoki-version    (ver '%ck:cryptoki-version)
         :manufacturer-id     (str '%ck:manufacturer-id 32)
         ;; flags is reserved for future extensions, should be 0.
         :flags               (foreign-slot-value info '(:struct %ck:info) '%ck:flags)
         :library-description (str '%ck:library-description 32)
         :library-version     (ver '%ck:library-version)))))



(defun ckbool (generalized-boolean)
  (if generalized-boolean
      %ck:+true+
      %ck:+false+))

(defun get-slot-list (token-present)
  (with-foreign-object (count :ulong)
    (check-rv (%ck:get-slot-list (ckbool token-present) (cffi:null-pointer) count) "C_GetSlotList")
    (let ((slot-count  (mem-ref count :ulong)))
      (when (plusp slot-count)
        (with-foreign-object (slot-ids '%ck:slot-id slot-count)
          (check-rv (%ck:get-slot-list (ckbool token-present) slot-ids count))
          (loop :for i :below slot-count
                :collect (mem-aref slot-ids '%ck:slot-id i)))))))

(defstruct slot-info
  slot-description
  manufacturer-id
  flags
  hardware-version
  firmware-version)

(defun get-slot-info (slot-id)
  (with-foreign-object (info '(:struct %ck:slot-info))
    (check-rv (%ck:get-slot-info slot-id info) "C_GetSlotInfo")
    (flet ((str (slot size)
               (foreign-string-to-lisp
                (foreign-slot-pointer info '(:struct %ck:slot-info) slot)
                :max-chars size :encoding :ascii))
             (ver (slot)
               (version :decode (foreign-slot-pointer info '(:struct %ck:slot-info) slot))))
      (make-slot-info
       :slot-description (str '%ck:slot-description 64)
       :manufacturer-id  (str '%ck:manufacturer-id  32)
       :flags            (convert-slot-info-flags :decode (foreign-slot-value info '(:struct %ck:slot-info) '%ck:flags))
       :hardware-version (ver '%ck:hardware-version)
       :firmware-version (ver '%ck:firmware-version)))))


(defstruct token-info
  label manufacturer-id model serial-number flags max-session-count
  session-count max-rw-session-count rw-session-count max-pin-len
  min-pin-len total-public-memory free-public-memory
  total-private-mmeory free-private-memory hardware-version
  firmware-version utc-time)

(defun get-token-info (slot-id)
  (with-foreign-object (info '(:struct %ck:token-info))
    (check-rv (%ck:get-token-info slot-id info) "C_GetTokenInfo")
    (flet ((str (slot size)
             (foreign-string-to-lisp
              (foreign-slot-pointer info '(:struct %ck:token-info) slot)
              :max-chars size :encoding :ascii))
           (ver (slot)
             (version :decode (foreign-slot-pointer info '(:struct %ck:token-info) slot)))
           (long (slot)
             (let ((value (foreign-slot-value info '(:struct %ck:token-info) slot)))
               (cond
                 ((= value %ck:+unavailable-information+) nil)
                 ((= value %ck:+effectively-infinite+)    :infinite)
                 (t                                       value)))))
      (make-token-info
       :label                (str '%ck:label            32)
       :manufacturer-id      (str '%ck:manufacturer-id  32)
       :model                (str '%ck:model            16)
       :serial-number        (str '%ck:serial-number    16)
       :flags                (convert-token-info-flags :decode (foreign-slot-value info '(:struct %ck:token-info) '%ck:flags))
       :max-session-count    (long '%ck:max-session-count)
       :session-count        (long '%ck:session-count)
       :max-rw-session-count (long '%ck:max-rw-session-count)
       :rw-session-count     (long '%ck:rw-session-count)
       :max-pin-len          (long '%ck:max-pin-len)
       :min-pin-len          (long '%ck:min-pin-len)
       :total-public-memory  (long '%ck:total-public-memory)
       :free-public-memory   (long '%ck:free-public-memory)
       :total-private-mmeory (long '%ck:total-private-mmeory)
       :free-private-memory  (long '%ck:free-private-memory)
       :hardware-version     (ver '%ck:hardware-version)
       :firmware-version     (ver '%ck:firmware-version)
       :utc-time             (str '%ck:utc-time 16)))))


(defun wait-for-slot-event (flags)
  (with-foreign-object (slot-id :ulong)
    (check-rv (%ck:wait-for-slot-event (if (integerp flags)
                                           flags
                                           (convert-wait-for-slot-event-flags :encode flags))
                                       slot-id
                                       (cffi:null-pointer))
              "C_WaitForSlotEvent")
    (mem-ref slot-id :ulong)))


(defun get-mechanism-list (slot-id)
  (with-foreign-object (count :ulong)
    (check-rv (%ck:get-mechanism-list slot-id (cffi:null-pointer) count) "C_GetMechanismList")
    (let ((mechanism-count  (mem-ref count :ulong)))
      (when (plusp mechanism-count)
        (with-foreign-object (mechanism-types '%ck:mechanism-type mechanism-count)
          (check-rv (%ck:get-mechanism-list slot-id mechanism-types count))
          (loop :for i :below mechanism-count
                :collect (mechanism-type :decode (mem-aref mechanism-types '%ck:mechanism-type i))))))))

(defstruct mechanism-info
  min-key-size max-key-size flags)

(defun get-mechanism-info (slot-id mechanism-type)
  (with-foreign-object (info '(:struct %ck:mechanism-info))
    (check-rv (%ck:get-mechanism-info slot-id
                                      (if (integerp mechanism-type)
                                          mechanism-type
                                          (mechanism-type :encode mechanism-type))
                                      info)
              "C_GetMechanismInfo")
    (flet ((long (slot)
             (foreign-slot-value info '(:struct %ck:mechanism-info) slot)))
      (make-mechanism-info
       :min-key-size (long '%ck:min-key-size)
       :max-key-size (long '%ck:min-key-size)
       :flags        (convert-mechanism-info-flags :decode (foreign-slot-value info '(:struct %ck:mechanism-info) '%ck:flags))))))

(defun string-to-utf-8 (string &key size padchar)
  ;; TODO: actually convert to utf-8
  (let ((bytes (map '(vector (unsigned-byte 8))
		    (lambda (ch)
		      (let ((code (char-code ch)))
			(if (<= 32 code 126)
			    code
			    (error "Unicode not supported yet: ~C (~D) in ~S"
				   (code-char code) code string))))
		    string)))
    (when (and size (< size (length bytes)))
      (setf bytes (subseq bytes 0 size)))
    (when (and padchar size (< (length bytes) size))
      (let ((code (char-code padchar)))
        (unless (<= 32 code 126)
            (error "Unicode not supported yet: ~C (~D) pad-character"
                   (code-char code) code))
        (setf bytes (concatenate '(vector (unsigned-byte 8)) bytes
                                 (make-array (- size (length bytes)) :initial-element code)))))
    bytes))

(defun init-token (slot-id pin label)
  (error "Not tested yet! Please, provide new smart-cards!")
  (let* ((label  (string-to-utf-8 label :size 32 :padchar #\space))
         (pin    (string-to-utf-8 label))
         (pinlen (length pin)))
    (with-foreign-objects ((flabel  :uchar 32)
                           (fpin    :uchar pinlen)
                           (fpinlen :ulong))
      (dotimes (i 32)     (setf (mem-aref flabel :uchar i) (aref label i)))
      (dotimes (i pinlen) (setf (mem-aref fpin   :uchar i) (aref pin   i)))
      (setf (mem-ref fpinlen :ulong) pinlen)
      (check-rv (%ck:init-token slot-id fpin fpinlen flabel) "C_InitToken")
      (foreign-string-to-lisp fpin :size fpinlen :encoding :ascii))))

(defun open-session (slot-id flags ) ( "C_OpenSession")    rv
  (slot-id     slot-id)
  (flags       flags)
  (application :pointer)
  (notify      notify)
  (session     (:pointer session-handle)))
#|
(defcfun (close-session "C_CloseSession") rv
  (session session-handle))

(defcfun (close-all-sessions "C_CloseAllSessions") rv
  (slot-id slot-id))


(defcfun (init-pin "C_InitPIN") rv
  (session session-handle)
  (pin     (:pointer :uchar))
  (pin-len :ulong))

(defcfun (set-pin "C_SetPIN")    rv
  (session session-handle)
  (old-pin (:pointer :uchar))
  (old-len :ulong)
  (new-pin (:pointer :uchar))
  (new-len :ulong))

|#

(defun test ()
  (with-pkcs11
    (format t "Info: ~S~%" (get-info))
    (format t "All Slot IDs: ~S~%" (get-slot-list nil))
    (format t "~:{- Slot ID: ~A~%  Slot Info: ~S~%~%~}"
            (mapcar (lambda (slot-id)
                      (list slot-id
                            (handler-case (get-slot-info slot-id)
                              (error (err) (princ-to-string err)))))
                    (get-slot-list nil)))
    (format t "Slot IDs with a token: ~S~%" (get-slot-list t))
    (format t "~:{- Slot ID: ~A~%  Slot Info: ~S~%  Token Info: ~S~
               ~%  Mechanism list: ~{~A~^~%                  ~}~%~}"
            (mapcar (lambda (slot-id)
                      (list slot-id
                            (handler-case (get-slot-info slot-id)
                              (error (err) (princ-to-string err)))
                            (handler-case (get-token-info slot-id)
                              (error (err) (princ-to-string err)))
                            (handler-case (mapcar (lambda (mechanism-type)
                                                    (list mechanism-type
                                                          (get-mechanism-info slot-id mechanism-type)))
                                                  (get-mechanism-list slot-id))
                              (error (err) (list (princ-to-string err))))))
                    (get-slot-list t)))))



(test)

;; (load-library)
;; (with-pkcs11 (wait-for-slot-event nil)) ;; not supported by   "/usr/local/lib/libiaspkcs11.so"

#|

(defcfun (get-session-info "C_GetSessionInfo")    rv
  (session session-handle)
  (info    (:pointer (:struct session-info))))

(defcfun (get-operation-state "C_GetOperationState")    rv
  (session             session-handle)
  (operation-state     (:pointer :uchar))
  (operation-state-len (:pointer :ulong)))

(defcfun (set-operation-state "C_SetOperationState")    rv
  (session             session-handle)
  (operation-state     (:pointer :uchar))
  (operation-state-len :ulong)
  (encryption-key      object-handle)
  (authentiation-key   object-handle))

(defcfun (login "C_Login")    rv
  (session   session-handle)
  (user-type user-type)
  (pin       (:pointer :uchar))
  (pin-len   :ulong))

(defcfun (logout "C_Logout") rv
  (session session-handle))

(defcfun (create-object "C_CreateObject")    rv
  (session session-handle)
  (templ (:pointer (:struct attribute)))
  (count :ulong)
  (object (:pointer object-handle)))

(defcfun (copy-object "C_CopyObject")    rv
  (session    session-handle)
  (object     object-handle)
  (templ      (:pointer (:struct attribute)))
  (count      :ulong)
  (new-object (:pointer object-handle)))

(defcfun (destroy-object "C_DestroyObject") rv
  (session session-handle)
  (object object-handle))

(defcfun (get-object-size "C_GetObjectSize")    rv
  (session session-handle)
  (object  object-handle)
  (size    (:pointer :ulong)))

(defcfun (get-attribute-value "C_GetAttributeValue")    rv
  (session session-handle)
  (object  object-handle)
  (templ   (:pointer (:struct attribute)))
  (count   :ulong))

(defcfun (set-attribute-value "C_SetAttributeValue")    rv
  (session session-handle)
  (object  object-handle)
  (templ   (:pointer (:struct attribute)))
  (count   :ulong))

(defcfun (find-objects-init "C_FindObjectsInit")    rv
  (session session-handle)
  (templ   (:pointer (:struct attribute)))
  (count   :ulong))

(defcfun (find-objects "C_FindObjects")    rv
  (session          session-handle)
  (object           (:pointer object-handle))
  (max-object-count :ulong)
  (object-count     (:pointer :ulong)))

(defcfun (find-objects-final "C_FindObjectsFinal") rv (session session-handle))

(defcfun (encrypt-init "C_EncryptInit")    rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (key       object-handle))

(defcfun (encrypt "C_Encrypt")    rv
  (session            session-handle)
  (data               (:pointer :uchar))
  (data-len           :ulong)
  (encrypted-data     (:pointer :uchar))
  (encrypted-data-len (:pointer :ulong)))

(defcfun (encrypt-update "C_EncryptUpdate")    rv
  (session            session-handle)
  (part               (:pointer :uchar))
  (part-len           :ulong)
  (encrypted-part     (:pointer :uchar))
  (encrypted-part-len (:pointer :ulong)))

(defcfun (encrypt-final "C_EncryptFinal")    rv
  (session                 session-handle)
  (last-encrypted-part     (:pointer :uchar))
  (last-encrypted-part-len (:pointer :ulong)))

(defcfun (decrypt-init "C_DecryptInit")    rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (key       object-handle))

(defcfun (decrypt "C_Decrypt")    rv
  (session            session-handle)
  (encrypted-data     (:pointer :uchar))
  (encrypted-data-len :ulong)
  (data               (:pointer :uchar))
  (data-len           (:pointer :ulong)))

(defcfun (decrypt-update "C_DecryptUpdate")    rv
  (session            session-handle)
  (encrypted-part     (:pointer :uchar))
  (encrypted-part-len :ulong)
  (part               (:pointer :uchar))
  (part-len           (:pointer :ulong)))

(defcfun (decrypt-final "C_DecryptFinal")    rv
  (session       session-handle)
  (last-part     (:pointer :uchar))
  (last-part-len (:pointer :ulong)))

(defcfun (digest-init "C_DigestInit") rv (session session-handle) (mechanism (:pointer (:struct mechanism))))

(defcfun (digest "C_Digest")    rv
  (session    session-handle)
  (data       (:pointer :uchar))
  (data-len   :ulong)
  (digest     (:pointer :uchar))
  (digest-len (:pointer :ulong)))

(defcfun (digest-update "C_DigestUpdate") rv (session session-handle) (part (:pointer :uchar)) (part-len :ulong))
(defcfun (digest-key    "C_DigestKey")    rv (session session-handle) (key  object-handle))

(defcfun (digest-final "C_DigestFinal")    rv
  (session    session-handle)
  (digest     (:pointer :uchar))
  (digest-len (:pointer :ulong)))

(defcfun (sign-init "C_SignInit")    rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (key       object-handle))

(defcfun (sign "C_Sign")    rv
  (session       session-handle)
  (data          (:pointer :uchar))
  (data-len      :ulong)
  (signature     (:pointer :uchar))
  (signature-len (:pointer :ulong)))

(defcfun (sign-update "C_SignUpdate") rv
  (session  session-handle)
  (part     (:pointer :uchar))
  (part-len :ulong))

(defcfun (sign-final "C_SignFinal")    rv
  (session       session-handle)
  (signature     (:pointer :uchar))
  (signature-len (:pointer :ulong)))

(defcfun (sign-recover-init "C_SignRecoverInit")    rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (key       object-handle))

(defcfun (sign-recover "C_SignRecover")    rv
  (session       session-handle)
  (data          (:pointer :uchar))
  (data-len      :ulong)
  (signature     (:pointer :uchar))
  (signature-len (:pointer :ulong)))

(defcfun (verify-init "C_VerifyInit")    rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (key       object-handle))

(defcfun (verify "C_Verify")    rv
  (session       session-handle)
  (data          (:pointer :uchar))
  (data-len      :ulong)
  (signature     (:pointer :uchar))
  (signature-len :ulong))

(defcfun (verify-update "C_VerifyUpdate") rv
  (session  session-handle)
  (part     (:pointer :uchar))
  (part-len :ulong))

(defcfun (verify-final "C_VerifyFinal")    rv
  (session       session-handle)
  (signature     (:pointer :uchar))
  (signature-len :ulong))

(defcfun (verify-recover-init "C_VerifyRecoverInit")    rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (key       object-handle))

(defcfun (verify-recover "C_VerifyRecover")    rv
  (session       session-handle)
  (signature     (:pointer :uchar))
  (signature-len :ulong)
  (data          (:pointer :uchar))
  (data-len      (:pointer :ulong)))

(defcfun (digest-encrypt-update "C_DigestEncryptUpdate")    rv
  (session            session-handle)
  (part               (:pointer :uchar))
  (part-len           :ulong)
  (encrypted-part     (:pointer :uchar))
  (encrypted-part-len (:pointer :ulong)))

(defcfun (decrypt-digest-update "C_DecryptDigestUpdate")    rv
  (session            session-handle)
  (encrypted-part     (:pointer :uchar))
  (encrypted-part-len :ulong)
  (part               (:pointer :uchar))
  (part-len           (:pointer :ulong)))

(defcfun (sign-encrypt-update "C_SignEncryptUpdate")    rv
  (session            session-handle)
  (part               (:pointer :uchar))
  (part-len           :ulong)
  (encrypted-part     (:pointer :uchar))
  (encrypted-part-len (:pointer :ulong)))

(defcfun (decrypt-verify-update "C_DecryptVerifyUpdate")  rv
  (session            session-handle)
  (encrypted-part     (:pointer :uchar))
  (encrypted-part-len :ulong)
  (part               (:pointer :uchar))
  (part-len           (:pointer :ulong)))

(defcfun (generate-key "C_GenerateKey")  rv
  (session   session-handle)
  (mechanism (:pointer (:struct mechanism)))
  (templ     (:pointer (:struct attribute)))
  (count     :ulong)
  (key       (:pointer object-handle)))

(defcfun (generate-key-pair "C_GenerateKeyPair") rv
  (session                     session-handle)
  (mechanism                   (:pointer (:struct mechanism)))
  (public-key-template         (:pointer (:struct attribute)))
  (public-key-attribute-count  :ulong)
  (private-key-template        (:pointer (:struct attribute)))
  (private-key-attribute-count :ulong)
  (public-key                  (:pointer object-handle))
  (private-key                 (:pointer object-handle)))

(defcfun (wrap-key "C_WrapKey")    rv
  (session         session-handle)
  (mechanism       (:pointer (:struct mechanism)))
  (wrapping-key    object-handle)
  (key             object-handle)
  (wrapped-key     (:pointer :uchar))
  (wrapped-key-len (:pointer :ulong)))

(defcfun (unwrap-key "C_UnwrapKey")    rv
  (session         session-handle)
  (mechanism       (:pointer (:struct mechanism)))
  (unwrapping-key  object-handle)
  (wrapped-key     (:pointer :uchar))
  (wrapped-key-len :ulong)
  (templ           (:pointer (:struct attribute)))
  (attribute-count :ulong)
  (key             (:pointer object-handle)))

(defcfun (derive-key "C_DeriveKey")    rv
  (session         session-handle)
  (mechanism       (:pointer (:struct mechanism)))
  (base-key        object-handle)
  (templ           (:pointer (:struct attribute)))
  (attribute-count :ulong)
  (key             (:pointer object-handle)))

(defcfun (seed-random         "C_SeedRandom")        rv  (session session-handle)  (seed        (:pointer :uchar))  (seed-len   :ulong))
(defcfun (generate-random     "C_GenerateRandom")    rv  (session session-handle)  (random-data (:pointer :uchar))  (random-len :ulong))
(defcfun (get-function-status "C_GetFunctionStatus") rv  (session session-handle))
(defcfun (cancel-function     "C_CancelFunction")    rv  (session session-handle))


|#


(defun foreign-vector (pointer type size)
  (coerce (loop
            :for i :below size
            :collect (mem-aref pointer type i))
          'vector))




;;;; THE END ;;;;
