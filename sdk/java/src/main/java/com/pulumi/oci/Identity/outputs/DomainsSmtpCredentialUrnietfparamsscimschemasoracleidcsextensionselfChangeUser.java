// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Boolean;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DomainsSmtpCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser {
    /**
     * @return If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    private @Nullable Boolean allowSelfChange;

    private DomainsSmtpCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser() {}
    /**
     * @return If true, allows requesting user to update themselves. If false, requesting user can&#39;t update themself (default).
     * 
     */
    public Optional<Boolean> allowSelfChange() {
        return Optional.ofNullable(this.allowSelfChange);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DomainsSmtpCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable Boolean allowSelfChange;
        public Builder() {}
        public Builder(DomainsSmtpCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.allowSelfChange = defaults.allowSelfChange;
        }

        @CustomType.Setter
        public Builder allowSelfChange(@Nullable Boolean allowSelfChange) {
            this.allowSelfChange = allowSelfChange;
            return this;
        }
        public DomainsSmtpCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser build() {
            final var o = new DomainsSmtpCredentialUrnietfparamsscimschemasoracleidcsextensionselfChangeUser();
            o.allowSelfChange = allowSelfChange;
            return o;
        }
    }
}