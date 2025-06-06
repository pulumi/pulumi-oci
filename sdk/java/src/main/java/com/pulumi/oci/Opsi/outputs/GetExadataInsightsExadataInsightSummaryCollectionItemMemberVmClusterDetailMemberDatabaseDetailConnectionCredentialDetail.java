// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail {
    private String credentialSourceName;
    private String credentialType;
    private String passwordSecretId;
    private String role;
    private String userName;
    private String walletSecretId;

    private GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail() {}
    public String credentialSourceName() {
        return this.credentialSourceName;
    }
    public String credentialType() {
        return this.credentialType;
    }
    public String passwordSecretId() {
        return this.passwordSecretId;
    }
    public String role() {
        return this.role;
    }
    public String userName() {
        return this.userName;
    }
    public String walletSecretId() {
        return this.walletSecretId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String credentialSourceName;
        private String credentialType;
        private String passwordSecretId;
        private String role;
        private String userName;
        private String walletSecretId;
        public Builder() {}
        public Builder(GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.credentialSourceName = defaults.credentialSourceName;
    	      this.credentialType = defaults.credentialType;
    	      this.passwordSecretId = defaults.passwordSecretId;
    	      this.role = defaults.role;
    	      this.userName = defaults.userName;
    	      this.walletSecretId = defaults.walletSecretId;
        }

        @CustomType.Setter
        public Builder credentialSourceName(String credentialSourceName) {
            if (credentialSourceName == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail", "credentialSourceName");
            }
            this.credentialSourceName = credentialSourceName;
            return this;
        }
        @CustomType.Setter
        public Builder credentialType(String credentialType) {
            if (credentialType == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail", "credentialType");
            }
            this.credentialType = credentialType;
            return this;
        }
        @CustomType.Setter
        public Builder passwordSecretId(String passwordSecretId) {
            if (passwordSecretId == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail", "passwordSecretId");
            }
            this.passwordSecretId = passwordSecretId;
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            if (role == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail", "role");
            }
            this.role = role;
            return this;
        }
        @CustomType.Setter
        public Builder userName(String userName) {
            if (userName == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail", "userName");
            }
            this.userName = userName;
            return this;
        }
        @CustomType.Setter
        public Builder walletSecretId(String walletSecretId) {
            if (walletSecretId == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail", "walletSecretId");
            }
            this.walletSecretId = walletSecretId;
            return this;
        }
        public GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail build() {
            final var _resultValue = new GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionCredentialDetail();
            _resultValue.credentialSourceName = credentialSourceName;
            _resultValue.credentialType = credentialType;
            _resultValue.passwordSecretId = passwordSecretId;
            _resultValue.role = role;
            _resultValue.userName = userName;
            _resultValue.walletSecretId = walletSecretId;
            return _resultValue;
        }
    }
}
