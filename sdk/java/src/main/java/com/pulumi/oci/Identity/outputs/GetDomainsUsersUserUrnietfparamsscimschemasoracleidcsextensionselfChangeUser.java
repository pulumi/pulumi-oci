// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfChangeUser {
    /**
     * @return If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    private Boolean allowSelfChange;

    private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfChangeUser() {}
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

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfChangeUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Boolean allowSelfChange;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfChangeUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowSelfChange = defaults.allowSelfChange;
        }

        @CustomType.Setter
        public Builder allowSelfChange(Boolean allowSelfChange) {
            this.allowSelfChange = Objects.requireNonNull(allowSelfChange);
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfChangeUser build() {
            final var o = new GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionselfChangeUser();
            o.allowSelfChange = allowSelfChange;
            return o;
        }
    }
}