// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount {
    /**
     * @return Status of the account
     * 
     */
    private Boolean active;
    /**
     * @return The ID of the App in this Grant.
     * 
     */
    private String appId;
    /**
     * @return Name of the account assigned to the User.
     * 
     */
    private String name;
    /**
     * @return User Token URI
     * 
     */
    private String ref;
    /**
     * @return The value of a X509 certificate.
     * 
     */
    private String value;

    private GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount() {}
    /**
     * @return Status of the account
     * 
     */
    public Boolean active() {
        return this.active;
    }
    /**
     * @return The ID of the App in this Grant.
     * 
     */
    public String appId() {
        return this.appId;
    }
    /**
     * @return Name of the account assigned to the User.
     * 
     */
    public String name() {
        return this.name;
    }
    /**
     * @return User Token URI
     * 
     */
    public String ref() {
        return this.ref;
    }
    /**
     * @return The value of a X509 certificate.
     * 
     */
    public String value() {
        return this.value;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean active;
        private String appId;
        private String name;
        private String ref;
        private String value;
        public Builder() {}
        public Builder(GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.active = defaults.active;
    	      this.appId = defaults.appId;
    	      this.name = defaults.name;
    	      this.ref = defaults.ref;
    	      this.value = defaults.value;
        }

        @CustomType.Setter
        public Builder active(Boolean active) {
            if (active == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount", "active");
            }
            this.active = active;
            return this;
        }
        @CustomType.Setter
        public Builder appId(String appId) {
            if (appId == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount", "appId");
            }
            this.appId = appId;
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            if (name == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount", "name");
            }
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder ref(String ref) {
            if (ref == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount", "ref");
            }
            this.ref = ref;
            return this;
        }
        @CustomType.Setter
        public Builder value(String value) {
            if (value == null) {
              throw new MissingRequiredPropertyException("GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount", "value");
            }
            this.value = value;
            return this;
        }
        public GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount build() {
            final var _resultValue = new GetDomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserAccount();
            _resultValue.active = active;
            _resultValue.appId = appId;
            _resultValue.name = name;
            _resultValue.ref = ref;
            _resultValue.value = value;
            return _resultValue;
        }
    }
}
