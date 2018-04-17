(cl:in-package "COMMON-LISP")
(defpackage "COM.INFORMATIMAGO.PKCS11"
  (:use "COMMON-LISP" "CFFI")
  (:nicknames "CK" "PKCS11")
  (:export)
  (:documentation "CFFI interface over pkcs11-helper-1.0/pkcs11.h version 2.02"))
(in-package "COM.INFORMATIMAGO.PKCS11")

(load-foreign-library "/usr/local/lib/libiaspkcs11.so")

(defcstruct version
  (major :uchar)
  (minor :uchar))

(defctype flags :ulong)
(defctype rv    :ulong)

(defcstruct info
  (cryptoki-version    (:struct version))
  (manufacturer-id     :uchar :count 32)
  (flags               flags)
  (library-description :uchar :count 32)
  (library-version     (:struct version)))


(defcfun (initialize "C_Initialize") rv (init-args :pointer))
(defcfun (finalize   "C_Finalize")   rv (reserved  :pointer))
(defcfun (get-info   "C_GetInfo")    rv (info     (:pointer (:struct info))))



(define-condition pkcs11-error (error)
  ((rv :initarg :rv :reader pkcs11-error-code)
   (function :initarg :function :reader pkcs11-error-function)))

(defun check-rv (rv &optional function)
  (if (zerop rv)
      (values)
      (error 'pkcs11-error :rv rv :function function)))

(defmacro with-pkcs11 (&body body)
  `(progn
     (check-rv (initialize (cffi:null-pointer)) 'initialize)
     (unwind-protect (progn ,@body)
       (check-rv (finalize (cffi:null-pointer)) 'finalize))))

(defun foreign-vector (pointer type size)
  (coerce (loop
            :for i :below size
            :collect (mem-aref pointer type i))
          'vector))

(with-pkcs11
  (with-foreign-object (info '(:struct info))
    (get-info info)
    (list (foreign-slot-value info 'info 'cryptoki-version)
          (foreign-string-to-lisp (foreign-slot-pointer info 'info 'manufacturer-id)
                                  :max-chars 32 :encoding :ascii)
          (foreign-slot-value info 'info 'flags)
          (foreign-string-to-lisp (foreign-slot-pointer info 'info 'library-description) 
                                  :max-chars 32 :encoding :ascii)
          (foreign-slot-value info 'info 'library-version))))

;; --> ((minor 20 major 2)
;;      "ANTS                            "
;;      0
;;      "IAS-ECC Middleware P11 library  "
;;      (minor 1 major 3))
