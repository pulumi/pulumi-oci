// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser {
    /**
     * @return If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    private Boolean allowSelfChange;

    private GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser() {}
    /**
     * @return If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    public Boolean allowSelfChange() {
        return this.allowSelfChange;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean allowSelfChange;
        public Builder() {}
        public Builder(GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowSelfChange = defaults.allowSelfChange;
        }

        @CustomType.Setter
        public Builder allowSelfChange(Boolean allowSelfChange) {
            if (allowSelfChange == null) {
              throw new MissingRequiredPropertyException("GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser", "allowSelfChange");
            }
            this.allowSelfChange = allowSelfChange;
            return this;
        }
        public GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser build() {
            final var _resultValue = new GetDomainsAuthTokensAuthTokenUrnietfparamsscimschemasoracleidcsextensionselfChangeUser();
            _resultValue.allowSelfChange = allowSelfChange;
            return _resultValue;
        }
    }
}
