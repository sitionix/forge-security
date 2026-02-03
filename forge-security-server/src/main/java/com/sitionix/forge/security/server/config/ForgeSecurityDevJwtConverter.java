package com.sitionix.forge.security.server.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@ConfigurationPropertiesBinding
public class ForgeSecurityDevJwtConverter implements Converter<String, ForgeSecurityServerProperties.DevJwt> {

    @Override
    public ForgeSecurityServerProperties.DevJwt convert(final String source) {
        final ForgeSecurityServerProperties.DevJwt devJwt = new ForgeSecurityServerProperties.DevJwt();
        if (StringUtils.hasText(source)) {
            devJwt.setStaticToken(source.trim());
        }
        return devJwt;
    }
}
