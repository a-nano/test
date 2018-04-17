(ql:quickload :split-sequence)
(ql:quickload :com.informatimago.common-lisp.cesarum)
(use-package :split-sequence)
(use-package :com.informatimago.common-lisp.cesarum.file)

(defun validate-symbol (string-designator valid-names &optional (label "symbol"))
  (if (member string-designator valid-names :test (function string-equal))
      (intern (string-upcase string-designator))
      (error "Invalid ~A: ~A (expected ~{~A~^, ~}~:*~@[ or ~]~*~A)"
             label string-designator (butlast valid-names) (first (last valid-names)))))

(defun load-trace (pathname)
  (mapcar (lambda (line)
            (destructuring-bind (direction &rest byte-strings)
                (split-sequence #\space line :remove-empty-subseqs t)
              (cons (validate-symbol direction '("send" "recv") "direction")
                    (map 'vector (lambda (byte-string)
                                   (parse-integer byte-string :radix 16. :junk-allowed nil))
                      byte-strings))))
          (string-list-text-file-contents pathname)))



#|
Lc, Le: when present, either both short (1 byte) or both long (3 or 2 bytes).

(length bytes)

 Lc=0, Le=0  -> 0   4

 Lc=1, Le=0  -> 1   5   Lc:1..255
 Lc=0, Le=1  -> 1   5
 Lc=1, Le=1  -> 2   6   Lc:1..255

 Lc=0, Le=3  -> 3   7                 Le:0,0..65535
 Lc=3, Le=0  -> 3   7   Lc:0,0..65535
 Lc=3, Le=2  -> 5   9   Lc:0,0..65535,Le:0..65535

|#

(defun decode-lengths-and-data (bytes)
  ;; This is wrong: in some cases the Ne is interpreted as Nc (when Lc is actually 0).
  (let (nc)
   (cond
     ((= 4 (length bytes))
      ;; Lc=0
      (values 0 nil 0))
     ((zerop (aref bytes 4))
      (if (<= 7 (length bytes))
          (values (setf nc (dpb (aref bytes 5) (byte 8 8) (aref bytes 6)))
                  (nsubseq bytes 7 (+ 7 nc))
                  (if (< (+ 7 nc) (length bytes))
                      (dpb (aref bytes (+ 7 nc)) (byte 8 8) (aref bytes (+ 8 nc)))
                      0))
          (values (setf nc 0)
                  nil
                  (case (- (length bytes) 4)
                    ((0) 0)
                    ((1) (aref bytes 4))
                    ((2) (dpb (aref bytes 4) (byte 8 8) (aref bytes 5)))
                    (otherwise
                     (unless (< 3 (- (length bytes) 4))
                       (format *error-output*
                               "Warning: command way too long: ~D bytes, expected ~D bytes~%~A"
                               (length bytes) 7 (dump-to-string bytes)))
                     (unless (zerop (aref bytes 4))
                       (format *error-output*
                               "Warning: non-zero byte as prefix of 3-byte ~
                                  Ne length: ~D at offset 4~%~A"
                               (aref bytes 4)
                               (dump-to-string bytes)))
                     (dpb (aref bytes 5) (byte 8 8) (aref bytes 6)))))))
     (t (values (setf nc (aref bytes 4))
                (nsubseq bytes 5 (+ 5 nc))
                (if (< (+ 5 nc) (length bytes))
                    (if (zerop (aref bytes (+ 5 nc)))
                        256
                        (aref bytes (+ 5 nc)))
                    0))))))

(defun decode-class (class)
  (cond
    ((= class #xFF) (list 'class 'invalid))
    ((zerop (ldb (byte 1 7) class))
     ;; interindustry class
     (cond
       ((= #b001 (ldb (byte 3 5) class))
        `(class (interindustry-reserved ,class)))
       ((= #b000  (ldb (byte 3 5) class))
        (let ((last-command-p (zerop (ldb (byte 1 4) class)))
              (secure-messaging (case (ldb (byte 2 2) class)
                                  (0 'no)
                                  (1 'proprietary)
                                  (2 'sm-header-not-processed)
                                  (3 'sm-header-authenticated)))
              (logical-channel   (ldb (byte 2 0) class)))
          `(class (interindustry ,class
                                 :logical-channel  ,logical-channel
                                 :secure-messaging ,secure-messaging
                                 :last-command-p ,last-command-p))))

       ((= #b01  (ldb (byte 2 6) class))
        (let ((last-command-p (zerop (ldb (byte 1 4) class)))
              (secure-messaging (case (ldb (byte 1 5) class)
                                  (0 'no)
                                  (1 'sm-header-not-processed)))
              (logical-channel   (ldb (byte 4 0) class)))
          `(class (interindustry-further ,class
                                         :logical-channel  ,(+ 4 logical-channel)
                                         :secure-messaging ,secure-messaging
                                         :last-command-p ,last-command-p))))))

    (t
     ;; proprietary class
     `(class (proprietary ,class)))))

(defun decode-instruction (ins p1 p2)
  `(ins ,(case ins
           ((#x04)        'deactivate-file)
           ((#x0C)        'erase-records)
           ((#x0E #x0F)   'erase-binary)
           ((#x10)        'perform-scql-operation)
           ((#x12)        'perform-transaction-operation)
           ((#x14)        'perform-user-operation)
           ((#x20 #x21)   'verify)
           ((#x22)        'manage-security-environment)
           ((#x24)        'change-reference-data)
           ((#x26)        'disable-verification-requirement)
           ((#x28)        'enable-verification-requirement)
           ((#x2A)        'perform-security-operation)
           ((#x44)        'activate-file)
           ((#x46)        'generate-asymetric-key-pair)
           ((#x82)        'external/mutual-authenticate)
           ((#x84)        'get-challenge)
           ((#x86 #x87)   'general-authenticate)
           ((#x88)        'internal-authenticate)
           ((#xA0 #xA1)   'search-binary)
           ((#xA2)        'search-record)
           ((#xA4)        'select)
           ((#xB0 #xB1)   'read-binary)
           ((#xB2 #xB3)   'read-records)
           ((#xC0)        'get-response)
           ((#xC2 #xC3)   'envelope)
           ((#xCA #xCB)   'get-data)
           ((#xD0 #xD1)   'write-binary)
           ((#xD2)        'write-record)
           ((#xD6 #xD7)   'update-binary)
           ((#xDA #xDB)   'put-data)
           ((#xDC #xDD)   'update-record)
           ((#xE0)        'create-file)
           ((#xE2)        'append-record)
           ((#xE4)        'delete-file)
           ((#xE6)        'terminate-df)
           ((#xE8)        'terminate-ef)
           ((#xFE)        'terminate-card-usage)
           (otherwise     `(unknown-instruction ,ins)))
     (:data-format ,(if (ber-tlv-p ins)
                        'ber-tlv
                        'normal))))

(defun ber-tlv-p (ins)
  (plusp (ldb (byte 1 0) ins)))

(defun describe-command-apdu (bytes)
  ;; When ins:ber-tlv and chaining -> collect all data and decode ber-tlv on the concatenation.
  (multiple-value-bind (nc data ne) (decode-lengths-and-data bytes)
    (let* ((class (aref bytes 0))
           (ins   (aref bytes 1))
           (p1    (aref bytes 2))
           (p2    (aref bytes 3)))
      (list
       (decode-class class)
       (decode-instruction ins p1 p2)
       `(data (:nc ,nc) ,data
              ,(if (ber-tlv-p ins)
                   (dump-to-string data) #|TODO: (decode-ber-tlv data)|#
                   (dump-to-string data) #|TODO: not in all cases (decode-simple-tlv data)|#))
       `(response (:ne ,ne))))))


(defun dump-to-string (bytes)
  (with-output-to-string (*standard-output*)
    (loop
      :with length = (length bytes)
      :for i :below length :by 16
      :do (loop
            :repeat 16
            :for j :from i :below length
            :do (format t "~2,'0X " (aref bytes j))
            :finally (unless (< (+ i 16) length)
                       (format t "~V{   ~}" (- (+ i 16) length) '(nil))))
          (loop
            :repeat 16
            :for j :from i :below length
            :for code := (aref bytes j)
            :initially (format t "  ")
            :do (format t "~C"  (if (<= 32 code 126)
                                    (code-char code)
                                    #\.))
            :finally (format t "~%")))))

;; (dump-to-string (coerce (loop for i from 30 to 198 collect i) 'vector))

(defun describe-response-apdu (bytes)
  (flet ((unknown (sw1 sw2)
           (format nil "Unknown interindustry status code #x~2,'0X #x~2,'0X" sw1 sw2))
         (proprietary (sw1 sw2)
           (format nil "Unknown proprietary status code #x~2,'0X #x~2,'0X" sw1 sw2))
         (triggering (sw2)
           (format nil "Triggering by the card (see 8.6.1) #x~2,'0X" sw2)))
    (let* ((nr (- (length bytes) 2))
           (response (nsubseq bytes 0 nr))
           (sw1 (aref bytes (- (length bytes) 2)))
           (sw2 (aref bytes (- (length bytes) 1)))
           (sw  (dpb sw1 (byte 8 8) sw2)))
      `(response
        ,@(when (plusp nr)
            (list
             (dump-to-string response)))

        ,(case sw1

           (#x61 `(info
                   (format nil "~D byte~:*~P still available" sw2)
                   sw2))

           (#x62 `(warning
                   ,(case sw2
                      (#x00 "No information given")
                      (#x81 "Part of returned data may be corrupted")
                      (#x82 "End of file or record reached before reading Ne bytes")
                      (#x83 "Selected file deactivated")
                      (#x84 "File control information not formatted according to 5.3.3")
                      (#x85 "Selected file in termination state")
                      (#x86 "No input data available from a sensor on the card")
                      (otherwise
                       (cond ((<= #x02 sw2 #x80)  (triggering sw2))
                             (t                   (unknown sw1 sw2)))))
                   non-volatile-memory-unchanged))

           (#x63 `(warning
                   ,(case sw2
                      (#x00 "No information given")
                      (#x81 "File filled up by the last write")
                      (otherwise
                       (cond ((<= #xC0 sw2 #xCF)  (format nil "Counter ~D" (ldb (byte 4 0) sw2)))
                             (t                   (unknown sw1 sw2)))))
                   non-volatile-memory-changed
                   ,@(cond ((<= #xC0 sw2 #xCF) (list (ldb (byte 4 0) sw2))))))

           (#x64 `(execution-error
                   ,(case sw2
                      (#x00 "Execution error")
                      (#x01 "Imediate response required by the card")
                      (otherwise
                       (cond ((<= #x02 sw2 #x80)   (triggering sw2))
                             (t                    (unknown sw1 sw2)))))
                   non-volatile-memory-unchanged))

           (#x65 `(execution-error
                   ,(case sw2
                      (#x00 "No information given")
                      (#x81 "Memory failure")
                      (otherwise (unknown sw1 sw2)))
                   non-volatile-memory-changed))

           (#x66 `(execution-error
                   ,(unknown sw1 sw2)
                   security-related-issues))

           (#x67 `(checking-error
                   ,(case sw2
                      (#x00 "Wrong length")
                      (otherwise (proprietary sw1 sw2)))))

           (#x68 `(checking-error
                   ,(case sw2
                      (#x00 "No information given")
                      (#x81 "Logical channel not supported")
                      (#x82 "Secure messaging not supported")
                      (#x83 "Last command of the chain expected")
                      (#x84 "Command chaining not supported")
                      (otherwise (unknown sw1 sw2)))
                   functions-in-cla-not-supported))

           (#x69 `(checking-error
                   ,(case sw2
                      (#x00 "No information given")
                      (#x81 "Command incompatible with file structure")
                      (#x82 "Security status not satisfied")
                      (#x83 "Authentication method blocked")
                      (#x84 "Reference data not usable")
                      (#x85 "Condition of use not satisfied")
                      (#x86 "Command not allowed (no current EF)")
                      (#x87 "Expected secure messaging data objects missing")
                      (#x88 "Incorrect secure messaging data objects")
                      (otherwise (unknown sw1 sw2)))
                   command-not-allowed))

           (#x6A `(checking-error
                   ,(case sw2
                      (#x00 "No information given")
                      (#x80 "Incorrect parameters in the command data field")
                      (#x81 "Function not supported")
                      (#x82 "File or application not found")
                      (#x83 "Record not found")
                      (#x84 "Not enough memory space in the file")
                      (#x85 "Nc inconsistent with TLV structure")
                      (#x86 "Incorrect parameters P1-P2")
                      (#x87 "Nc inconsistent with parameters P1-P2")
                      (#x88 "Reference data or reference data not found")
                      (#x89 "File already exists")
                      (#x8A "DF name already exists")
                      (otherwise (unknown sw1 sw2)))
                   wrong-parameters-p1-p2))

           (#x6C `(checking-error
                   ,(format nil "Wrong Le field: ~D available data byte~:*~P" sw2)
                   wrong-le-field
                   ,sw2))

           (#x6B `(checking-error
                   ,(case sw2
                      (#x00 "Wrong parameters P1-P2")
                      (otherwise (proprietary sw1 sw2)))
                   wrong-parameters-p1-p2))

           (#x6D `(checking-error
                   ,(case sw2
                      (#x00 "Instruction code not supported or invalid")
                      (otherwise (proprietary sw1 sw2)))))

           (#x6E `(checking-error
                   ,(case sw2
                      (#x00 "Class not supported")
                      (otherwise (proprietary sw1 sw2)))))

           (#x6F `(checking-error
                   ,(case sw2
                      (#x00 "No precise diagnosis")
                      (otherwise (proprietary sw1 sw2)))))

           (#x90 `(info
                   ,(case sw2
                      (#x00 "Process completed so far")
                      (otherwise (proprietary sw1 sw2)))))
           (otherwise
            (unknown sw1 sw2)))))))

(defun describe-apdu (message)
  (ecase (car message)
    (send (describe-command-apdu  (cdr message)))
    (recv (describe-response-apdu (cdr message)))))





(defgeneric encode-simple-tlv (type data))
(defgeneric decode-simple-tlv (bytes &key start)
  (:documentation "Return 2 values: (type . decoded-data), and the END index."))


(defmethod encode-simple-tlv (type (data vector))
  (let ((length (length data)))
    (check-type type (integer 1 254))
    (check-type length (integer 0 65535))
    (assert (every (lambda (byte) (typep byte '(unsigned-byte 8))) data)
            (data) "Should be a vector of (unsigned-byte 8).")
    (let ((buffer (make-array (+ 1 (if (< length 254) 2 3) length)
                              :element-type '(unsigned-byte 8)))

          start)
      (setf (aref buffer 0) type)
      (if (< length 254)
          (setf (aref buffer 1) length
                start 2)
          (setf (aref buffer 1) #xFF
                (aref buffer 2) (ldb (byte 8 8) length)
                (aref buffer 3) (ldb (byte 8 0) length)
                start 4))
      (replace buffer data :start1 start)
      buffer)))


(defmethod encode-simple-tlv (type (data string))
  (encode-simple-tlv type (map-into (make-array (length data) :element-type '(unsigned-byte 8))
                                    (function char-code) data)))

(defmethod encode-simple-tlv (type (data list))
  (encode-simple-tlv type (coerce data '(vector (unsigned-byte 8)))))

(defmethod decode-simple-tlv ((bytes null) &key (start 0))
  nil)

(defmethod decode-simple-tlv ((bytes vector) &key (start 0))
  (unless (zerop (length bytes))
    (let ((type (aref bytes start))
          (len  (aref bytes (incf start))))
      (when (= len #xff)
        (setf len (dpb (aref bytes (incf start))
                       (byte 8 8)
                       (aref bytes (incf start)))))
      (list type len
            (if (zerop len)
                nil
                (nsubseq bytes (+ 2 start) (+ 2 start len)))))))


(defun test/encode-simple-tlv ()
  (assert (equalp (encode-simple-tlv 33 '(1 2 3 4))
                  #(33 4 1 2 3 4 0)))
  (assert (equalp (encode-simple-tlv 33 "Hello world!")
                  #(33 12 72 101 108 108 111 32 119 111 114 108 100 33 0)))
  (assert (equalp (let ((data (make-array 1000 :element-type '(unsigned-byte 8))))
                    (assert (evenp (length data)))
                    (loop :for i :from 0 :by 2 :below (length data)
                          :do (setf (aref data i)      (ldb (byte 8 8) i)
                                    (aref data (1+ i)) (ldb (byte 8 0) i)))
                    (subseq (encode-simple-tlv 44 data) 0 16))
                  #(44 255 3 232 0 0 0 2 0 4 0 6 0 8 0 10)))
  :success)


(defun run ()
  (test/encode-simple-tlv)
  (let ((*print-right-margin* 80)
        (*print-circle* nil))
    (pprint (mapcar (function describe-apdu)
                    (load-trace #P"~/src/public/test/smartcard/smartcard.trace")))))


