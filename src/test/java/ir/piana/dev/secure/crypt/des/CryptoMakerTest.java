package ir.piana.dev.secure.crypt.des;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.piana.dev.secure.crypto.CryptoAttribute;
import ir.piana.dev.secure.crypto.CryptoMaker;
import ir.piana.dev.secure.key.SecretKeyAlgorithm;
import ir.piana.dev.secure.key.SecretKeyMaker;
import ir.piana.dev.secure.util.HexConverter;
import org.apache.commons.codec.binary.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.SecretKey;

/**
 * @author Mohammad Rahmati, 4/16/2017 7:03 PM
 */
public class CryptoMakerTest {
    @Test
    public void testDes() throws Exception {
        SecretKey secretKey = SecretKeyMaker
                .make(SecretKeyAlgorithm.DES);
        byte[] encrypted = CryptoMaker.encrypt(
                "Hello".getBytes("UTF-8"),
                secretKey,
                CryptoAttribute.DES_ECB_PKCS_5_PADDING, null);
//        System.out.println(Hex.encodeHexString(encrypted));
        byte[] decrypted = CryptoMaker.decrypt(encrypted,
                secretKey,
                CryptoAttribute.DES_ECB_PKCS_5_PADDING);
        Assert.assertEquals("not correct decryption",
                "Hello",
                new String(decrypted, "UTF-8"));
    }
}
