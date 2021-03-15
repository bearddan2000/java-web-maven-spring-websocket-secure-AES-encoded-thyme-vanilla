package example.security;

import example.security.AESUtils;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;

public class AESPasswordEncoder extends org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
  implements PasswordEncoder {

    final String password = "@amG89>";
    final String salt = "blacknoir";

    IvParameterSpec ivParameterSpec;
    SecretKey key;

    public AESPasswordEncoder()
    throws InvalidKeySpecException, NoSuchAlgorithmException,
    IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
    InvalidAlgorithmParameterException, NoSuchPaddingException {
      super();
      ivParameterSpec = AESUtils.generateIv();
      key = AESUtils.getKeyFromPassword(password,salt);
    }

    @Override
    public java.lang.String encode(java.lang.CharSequence rawPassword)
    {
      try {
        String res = AESUtils.encryptPasswordBased(rawPassword.toString(), key, ivParameterSpec);
        return super.encode(res);//BCrypt.hashpw(res, BCrypt.gensalt());
      } catch(NoSuchPaddingException | NoSuchAlgorithmException
       | InvalidAlgorithmParameterException | InvalidKeyException
       | BadPaddingException | IllegalBlockSizeException e) {}
      return super.encode(rawPassword);
    }

    @Override
    public boolean matches(java.lang.CharSequence rawPassword,
                       java.lang.String encodedPassword)
                       {
                           try {
                             String res = AESUtils.encryptPasswordBased(rawPassword.toString(), key, ivParameterSpec);
                             return super.matches(res, encodedPassword);
                           } catch(NoSuchPaddingException | NoSuchAlgorithmException
                            | InvalidAlgorithmParameterException | InvalidKeyException
                            | BadPaddingException | IllegalBlockSizeException e) {}
                           return false;
                       }
}
