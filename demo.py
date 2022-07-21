# *
# * This is an example implementation of the OATH
# * TOTP algorithm.
# * Visit www.openauthentication.org for more information.
# *
# * @author Johan Rydell, PortWise, Inc.
class TOTP :
    # *
    # 		* This method uses the JCE to provide the crypto algorithm.
    # 		* HMAC computes a Hashed Message Authentication Code with the
    # 		* crypto hash algorithm as a parameter.
    # 		*
    # 		* @param crypto: the crypto algorithm (HmacSHA1, HmacSHA256,
    # 		*                             HmacSHA512)
    # 		* @param keyBytes: the bytes to use for the HMAC key
    # 		* @param text: the message or text to be authenticated
    @staticmethod
    def  hmac_sha( crypto,  keyBytes,  text) :
        try :
            hmac = None
            hmac = Mac.getInstance(crypto)
            macKey = SecretKeySpec(keyBytes, "RAW")
            hmac.init(macKey)
            return hmac.doFinal(text)
        except java.security.GeneralSecurityException as gse :
            raise  java.lang.reflect.UndeclaredThrowableException(gse)
    # *
    # 		* This method converts a HEX string to Byte[]
    # 		*
    # 		* @param hex: the HEX string
    # 		*
    # 		* @return: a byte array
    @staticmethod
    def  hexStr2Bytes( hex) :
        # Adding one byte to get the right conversion
        # Values starting with "0" can be converted
        bArray =  java.math.BigInteger("10" + hex, 16).toByteArray()
        # Copy all the REAL bytes, not the "first"
        ret = [None] * (len(bArray) - 1)
        i = 0
        while (i < len(ret)) :
            ret[i] = bArray[i + 1]
            i += 1
        return ret
    DIGITS_POWER = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000]
    # *
    # 		* This method generates a TOTP value for the given
    # 		* set of parameters.
    # 		*
    # 		* @param key: the shared secret, HEX encoded
    # 		* @param time: a value that reflects a time
    # 		* @param returnDigits: number of digits to return
    # 		*
    # 		* @return: a numeric String in base 10 that includes
    # 		*              {@link truncationDigits} digits
    @staticmethod
    def  generateTOTP( key,  time,  returnDigits) :
        return TOTP.generateTOTP(key, time, returnDigits, "HmacSHA1")
    # *
    # 		* This method generates a TOTP value for the given
    # 		* set of parameters.
    # 		*
    # 		* @param key: the shared secret, HEX encoded
    # 		* @param time: a value that reflects a time
    # 		* @param returnDigits: number of digits to return
    # 		*
    # 		* @return: a numeric String in base 10 that includes
    # 		*              {@link truncationDigits} digits
    @staticmethod
    def  generateTOTP256( key,  time,  returnDigits) :
        return TOTP.generateTOTP(key, time, returnDigits, "HmacSHA256")
    # *
    # 		* This method generates a TOTP value for the given
    # 		* set of parameters.
    # 		*
    # 		* @param key: the shared secret, HEX encoded
    # 		* @param time: a value that reflects a time
    # 		* @param returnDigits: number of digits to return
    # 		*
    # 		* @return: a numeric String in base 10 that includes
    # 		*              {@link truncationDigits} digits
    @staticmethod
    def  generateTOTP512( key,  time,  returnDigits) :
        return TOTP.generateTOTP(key, time, returnDigits, "HmacSHA512")
    # *
    # 		* This method generates a TOTP value for the given
    # 		* set of parameters.
    # 		*
    # 		* @param key: the shared secret, HEX encoded
    # 		* @param time: a value that reflects a time
    # 		* @param returnDigits: number of digits to return
    # 		* @param crypto: the crypto function to use
    # 		*
    # 		* @return: a numeric String in base 10 that includes
    # 		*              {@link truncationDigits} digits
    @staticmethod
    def  generateTOTP( key,  time,  returnDigits,  crypto) :
        codeDigits = Integer.decode(returnDigits).intValue()
        result = None
        # Using the counter
        # First 8 bytes are for the movingFactor
        # Compliant with base RFC 4226 (HOTP)
        while (len(time) < 16) :
            time = "0" + time
        # Get the HEX in a Byte[]
        msg = TOTP.hexStr2Bytes(time)
        k = TOTP.hexStr2Bytes(key)
        hash = TOTP.hmac_sha(crypto, k, msg)
        # put selected bytes into result int
        offset = hash[len(hash) - 1] & 15
        binary = ((hash[offset] & 127) << 24) | ((hash[offset + 1] & 255) << 16) | ((hash[offset + 2] & 255) << 8) | (hash[offset + 3] & 255)
        otp = binary % TOTP.DIGITS_POWER[codeDigits]
        result = str(otp)
        while (len(result) < codeDigits) :
            result = "0" + result
        return result
    @staticmethod
    def main( args) :
        # Seed for HMAC-SHA1 - 20 bytes
        seed = "3132333435363738393031323334353637383930"
        # Seed for HMAC-SHA256 - 32 bytes
        seed32 = "3132333435363738393031323334353637383930313233343536373839303132"
        # Seed for HMAC-SHA512 - 64 bytes
        seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334"
        T0 = 0
        X = 30
        testTime = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]
        steps = "0"
        df =  java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
        df.setTimeZone(TimeZone.getTimeZone("UTC"))
        try :
            print("+---------------+-----------------------+------------------+--------+--------+")
            print("|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  | Mode   |")
            print("+---------------+-----------------------+------------------+--------+--------+")
            i = 0
            while (i < len(testTime)) :
                T = (testTime[i] - T0) / X
                steps = Long.toHexString(T).upper()
                while (len(steps) < 16) :
                    steps = "0" + steps
                fmtTime = String.format("%1$-11s",testTime[i])
                utcTime = df.format( java.util.Date(testTime[i] * 1000))
                print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |", end ="")
                print(TOTP.generateTOTP(seed, steps, "8", "HmacSHA1") + "| SHA1   |")
                print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |", end ="")
                print(TOTP.generateTOTP(seed32, steps, "8", "HmacSHA256") + "| SHA256 |")
                print("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |", end ="")
                print(TOTP.generateTOTP(seed64, steps, "8", "HmacSHA512") + "| SHA512 |")
                print("+---------------+-----------------------+------------------+--------+--------+")
                i += 1
        except java.lang.Exception as e :
            print("Error : " + str(e))


if __name__=="__main__":
    TOTP.main([])
