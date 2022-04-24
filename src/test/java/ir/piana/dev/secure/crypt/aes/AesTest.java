package ir.piana.dev.secure.crypt.aes;

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
 * @author MJ.Rahmati 4/24/2022-2:52 PM
 */
public class AesTest {
    @Test
    public void test() throws Exception {
        SecretKey secretKey = SecretKeyMaker
                .make(HexConverter.fromHexString("9bac6755c005b5dff18ecf875019cbf9"), SecretKeyAlgorithm.AES_128);

        String data = "GetAcquiringInfo:{\"PAN\":\"8372360000000001\",\"TransmissionDateTime\":\"20220418102030\",\"Stan\":\"000000\",\"TransactionDateTime\":\"20220418102030\",\"POS\":\"0002\",\"InstitutionCode\":\"160836\",\"RRN\":\"000000000001\",\"TerminalID\":\"17142348\",\"Tags\":\"0104010b02000201020202030204020502060207\"}";
        String s = HexConverter.toHexString(data.getBytes());
        int padLength = 0;
        int padLength1 = s.length() % 32;
        int padLength2 = s.length() / 32;
        if(padLength1 > 0) {
            padLength = (padLength2 + 1) * 32 - s.length();
        }
        String paddedData = s + (padLength > 0 ? String.format("%0"+ padLength + "d", 0) : "");

        byte[] encrypted = CryptoMaker.encrypt(
                HexConverter.fromHexString(paddedData),
                secretKey,
                CryptoAttribute.AES_CBC_NO_PADDING,
                CryptoMaker.createZeroInitialVector(CryptoAttribute.AES_CBC_NO_PADDING));

        String hexEncoded = Hex.encodeHexString(encrypted);
        Assert.assertEquals("7529c44ca0032d4062176db02f7b06daee23751442bdf82a2b69f15495e00b84f5f83766898d673550465f1dfb9754b269abfb3688ee1503a2229d3845de044b46b9670021d47ce5394bc3a119d2cd7206f92fc5e951d9f3e0307782b33683bc88ff1ca2cbf3e34d2c4fe02d571c43c636930d69b38962ef1ac07bea2420a08228a7ac71c89349e9c355bb4cbe30b3e4c6e084f9187c367e42a17867a24b7086fbef4765c7aed0532019a87ab44038b4073a3add71f2dfa4008649d72c15f5ba7758ea602c0ccc7ff45996df1e170b3737d7c8ad0a83c5f25f1c80b4bf7dec583366e9fe7a2e70c18da3e9107c147d742151fa7534099d81d5ef27fb3328d66a2af7ed2b36e3c3d52eaf4ece617e6d1ad44956c07000204893e3678289ef2097",
                hexEncoded);
    }
}
