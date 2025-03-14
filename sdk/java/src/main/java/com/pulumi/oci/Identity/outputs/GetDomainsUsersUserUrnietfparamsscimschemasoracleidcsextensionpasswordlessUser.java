// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Identity.outputs.GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifier;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser {
    /**
     * @return Factor Identifier ID
     * 
     */
    private List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifier> factorIdentifiers;
    /**
     * @return Authentication Factor Method
     * 
     */
    private String factorMethod;
    /**
     * @return Authentication Factor Type
     * 
     */
    private String factorType;

    private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser() {}
    /**
     * @return Factor Identifier ID
     * 
     */
    public List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifier> factorIdentifiers() {
        return this.factorIdentifiers;
    }
    /**
     * @return Authentication Factor Method
     * 
     */
    public String factorMethod() {
        return this.factorMethod;
    }
    /**
     * @return Authentication Factor Type
     * 
     */
    public String factorType() {
        return this.factorType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifier> factorIdentifiers;
        private String factorMethod;
        private String factorType;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.factorIdentifiers = defaults.factorIdentifiers;
    	      this.factorMethod = defaults.factorMethod;
    	      this.factorType = defaults.factorType;
        }

        @CustomType.Setter
        public Builder factorIdentifiers(List<GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifier> factorIdentifiers) {
            if (factorIdentifiers == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser", "factorIdentifiers");
            }
            this.factorIdentifiers = factorIdentifiers;
            return this;
        }
        public Builder factorIdentifiers(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUserFactorIdentifier... factorIdentifiers) {
            return factorIdentifiers(List.of(factorIdentifiers));
        }
        @CustomType.Setter
        public Builder factorMethod(String factorMethod) {
            if (factorMethod == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser", "factorMethod");
            }
            this.factorMethod = factorMethod;
            return this;
        }
        @CustomType.Setter
        public Builder factorType(String factorType) {
            if (factorType == null) {
              throw new MissingRequiredPropertyException("GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser", "factorType");
            }
            this.factorType = factorType;
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser build() {
            final var _resultValue = new GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionpasswordlessUser();
            _resultValue.factorIdentifiers = factorIdentifiers;
            _resultValue.factorMethod = factorMethod;
            _resultValue.factorType = factorType;
            return _resultValue;
        }
    }
}
