package com.sitionix.forge.security.userjwt.web;

import com.sitionix.forge.security.userjwt.core.ForgeUser;

public interface CurrentForgeUser {

    ForgeUser currentUser();
}
