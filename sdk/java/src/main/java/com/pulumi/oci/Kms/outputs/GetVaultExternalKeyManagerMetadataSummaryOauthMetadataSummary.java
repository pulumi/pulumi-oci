// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Kms.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummary {
    /**
     * @return ID of the client app created in IDP.
     * 
     */
    private String clientAppId;
    /**
     * @return Base URL of the IDCS account where confidential client app is created.
     * 
     */
    private String idcsAccountNameUrl;

    private GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummary() {}
    /**
     * @return ID of the client app created in IDP.
     * 
     */
    public String clientAppId() {
        return this.clientAppId;
    }
    /**
     * @return Base URL of the IDCS account where confidential client app is created.
     * 
     */
    public String idcsAccountNameUrl() {
        return this.idcsAccountNameUrl;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummary defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String clientAppId;
        private String idcsAccountNameUrl;
        public Builder() {}
        public Builder(GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummary defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.clientAppId = defaults.clientAppId;
    	      this.idcsAccountNameUrl = defaults.idcsAccountNameUrl;
        }

        @CustomType.Setter
        public Builder clientAppId(String clientAppId) {
            this.clientAppId = Objects.requireNonNull(clientAppId);
            return this;
        }
        @CustomType.Setter
        public Builder idcsAccountNameUrl(String idcsAccountNameUrl) {
            this.idcsAccountNameUrl = Objects.requireNonNull(idcsAccountNameUrl);
            return this;
        }
        public GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummary build() {
            final var o = new GetVaultExternalKeyManagerMetadataSummaryOauthMetadataSummary();
            o.clientAppId = clientAppId;
            o.idcsAccountNameUrl = idcsAccountNameUrl;
            return o;
        }
    }
}