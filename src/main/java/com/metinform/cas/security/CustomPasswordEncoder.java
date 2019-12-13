package com.metinform.cas.security;

import com.metinform.cas.cipher.EncryptUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

/**
 * 自定义加密类
 */
public class CustomPasswordEncoder implements PasswordEncoder {

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    @Override
    public String encode(CharSequence password) {
        try {
            Assert.notNull(password, "password can not be null.");
            password = EncryptUtil.entryptPassword(password.toString());
            return password.toString();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
            return null;
        }
    }

    /**
     * 调用这个方法来判断密码是否匹配
     */
    @Override
    public boolean matches(CharSequence rawPassword, String dbPassword) {
        Assert.notNull(rawPassword, "password can not be null.");
        return EncryptUtil.validatePassword(rawPassword.toString(), dbPassword);
    }
}