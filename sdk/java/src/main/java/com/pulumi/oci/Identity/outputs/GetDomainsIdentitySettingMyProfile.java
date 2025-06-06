// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetDomainsIdentitySettingMyProfile {
    /**
     * @return Whether to allow users to change their own password.
     * 
     */
    private Boolean allowEndUsersToChangeTheirPassword;
    /**
     * @return Whether to allow users to link or unlink their support accounts.
     * 
     */
    private Boolean allowEndUsersToLinkTheirSupportAccount;
    /**
     * @return Whether to allow users to update their capabilities.
     * 
     */
    private Boolean allowEndUsersToManageTheirCapabilities;
    /**
     * @return Whether to allow users to update their security settings.
     * 
     */
    private Boolean allowEndUsersToUpdateTheirSecuritySettings;

    private GetDomainsIdentitySettingMyProfile() {}
    /**
     * @return Whether to allow users to change their own password.
     * 
     */
    public Boolean allowEndUsersToChangeTheirPassword() {
        return this.allowEndUsersToChangeTheirPassword;
    }
    /**
     * @return Whether to allow users to link or unlink their support accounts.
     * 
     */
    public Boolean allowEndUsersToLinkTheirSupportAccount() {
        return this.allowEndUsersToLinkTheirSupportAccount;
    }
    /**
     * @return Whether to allow users to update their capabilities.
     * 
     */
    public Boolean allowEndUsersToManageTheirCapabilities() {
        return this.allowEndUsersToManageTheirCapabilities;
    }
    /**
     * @return Whether to allow users to update their security settings.
     * 
     */
    public Boolean allowEndUsersToUpdateTheirSecuritySettings() {
        return this.allowEndUsersToUpdateTheirSecuritySettings;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsIdentitySettingMyProfile defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean allowEndUsersToChangeTheirPassword;
        private Boolean allowEndUsersToLinkTheirSupportAccount;
        private Boolean allowEndUsersToManageTheirCapabilities;
        private Boolean allowEndUsersToUpdateTheirSecuritySettings;
        public Builder() {}
        public Builder(GetDomainsIdentitySettingMyProfile defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowEndUsersToChangeTheirPassword = defaults.allowEndUsersToChangeTheirPassword;
    	      this.allowEndUsersToLinkTheirSupportAccount = defaults.allowEndUsersToLinkTheirSupportAccount;
    	      this.allowEndUsersToManageTheirCapabilities = defaults.allowEndUsersToManageTheirCapabilities;
    	      this.allowEndUsersToUpdateTheirSecuritySettings = defaults.allowEndUsersToUpdateTheirSecuritySettings;
        }

        @CustomType.Setter
        public Builder allowEndUsersToChangeTheirPassword(Boolean allowEndUsersToChangeTheirPassword) {
            if (allowEndUsersToChangeTheirPassword == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingMyProfile", "allowEndUsersToChangeTheirPassword");
            }
            this.allowEndUsersToChangeTheirPassword = allowEndUsersToChangeTheirPassword;
            return this;
        }
        @CustomType.Setter
        public Builder allowEndUsersToLinkTheirSupportAccount(Boolean allowEndUsersToLinkTheirSupportAccount) {
            if (allowEndUsersToLinkTheirSupportAccount == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingMyProfile", "allowEndUsersToLinkTheirSupportAccount");
            }
            this.allowEndUsersToLinkTheirSupportAccount = allowEndUsersToLinkTheirSupportAccount;
            return this;
        }
        @CustomType.Setter
        public Builder allowEndUsersToManageTheirCapabilities(Boolean allowEndUsersToManageTheirCapabilities) {
            if (allowEndUsersToManageTheirCapabilities == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingMyProfile", "allowEndUsersToManageTheirCapabilities");
            }
            this.allowEndUsersToManageTheirCapabilities = allowEndUsersToManageTheirCapabilities;
            return this;
        }
        @CustomType.Setter
        public Builder allowEndUsersToUpdateTheirSecuritySettings(Boolean allowEndUsersToUpdateTheirSecuritySettings) {
            if (allowEndUsersToUpdateTheirSecuritySettings == null) {
              throw new MissingRequiredPropertyException("GetDomainsIdentitySettingMyProfile", "allowEndUsersToUpdateTheirSecuritySettings");
            }
            this.allowEndUsersToUpdateTheirSecuritySettings = allowEndUsersToUpdateTheirSecuritySettings;
            return this;
        }
        public GetDomainsIdentitySettingMyProfile build() {
            final var _resultValue = new GetDomainsIdentitySettingMyProfile();
            _resultValue.allowEndUsersToChangeTheirPassword = allowEndUsersToChangeTheirPassword;
            _resultValue.allowEndUsersToLinkTheirSupportAccount = allowEndUsersToLinkTheirSupportAccount;
            _resultValue.allowEndUsersToManageTheirCapabilities = allowEndUsersToManageTheirCapabilities;
            _resultValue.allowEndUsersToUpdateTheirSecuritySettings = allowEndUsersToUpdateTheirSecuritySettings;
            return _resultValue;
        }
    }
}
