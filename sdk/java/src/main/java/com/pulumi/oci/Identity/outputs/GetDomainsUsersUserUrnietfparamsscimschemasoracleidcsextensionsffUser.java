// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionsffUser {
    /**
     * @return SFF auth keys clob
     * 
     */
    private String sffAuthKeys;

    private GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionsffUser() {}
    /**
     * @return SFF auth keys clob
     * 
     */
    public String sffAuthKeys() {
        return this.sffAuthKeys;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionsffUser defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String sffAuthKeys;
        public Builder() {}
        public Builder(GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionsffUser defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.sffAuthKeys = defaults.sffAuthKeys;
        }

        @CustomType.Setter
        public Builder sffAuthKeys(String sffAuthKeys) {
            this.sffAuthKeys = Objects.requireNonNull(sffAuthKeys);
            return this;
        }
        public GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionsffUser build() {
            final var o = new GetDomainsUsersUserUrnietfparamsscimschemasoracleidcsextensionsffUser();
            o.sffAuthKeys = sffAuthKeys;
            return o;
        }
    }
}