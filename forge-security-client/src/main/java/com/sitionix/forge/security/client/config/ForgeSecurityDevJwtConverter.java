package com.sitionix.forge.security.client.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
@ConfigurationPropertiesBinding
public class ForgeSecurityDevJwtConverter implements Converter<String, ForgeSecurityClientProperties.DevJwt> {

    @Override
    public ForgeSecurityClientProperties.DevJwt convert(final String source) {
        final ForgeSecurityClientProperties.DevJwt devJwt = new ForgeSecurityClientProperties.DevJwt();
        if (StringUtils.hasText(source)) {
            devJwt.setStaticToken(source.trim());
        }
        return devJwt;
    }
}
