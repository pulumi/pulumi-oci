// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.NetworkFirewall.outputs.GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollection;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetNetworkFirewallPolicyMappedSecretsResult {
    private @Nullable String displayName;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of mapped_secret_summary_collection.
     * 
     */
    private List<GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollection> mappedSecretSummaryCollections;
    private String networkFirewallPolicyId;

    private GetNetworkFirewallPolicyMappedSecretsResult() {}
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of mapped_secret_summary_collection.
     * 
     */
    public List<GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollection> mappedSecretSummaryCollections() {
        return this.mappedSecretSummaryCollections;
    }
    public String networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNetworkFirewallPolicyMappedSecretsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String displayName;
        private String id;
        private List<GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollection> mappedSecretSummaryCollections;
        private String networkFirewallPolicyId;
        public Builder() {}
        public Builder(GetNetworkFirewallPolicyMappedSecretsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.id = defaults.id;
    	      this.mappedSecretSummaryCollections = defaults.mappedSecretSummaryCollections;
    	      this.networkFirewallPolicyId = defaults.networkFirewallPolicyId;
        }

        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyMappedSecretsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder mappedSecretSummaryCollections(List<GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollection> mappedSecretSummaryCollections) {
            if (mappedSecretSummaryCollections == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyMappedSecretsResult", "mappedSecretSummaryCollections");
            }
            this.mappedSecretSummaryCollections = mappedSecretSummaryCollections;
            return this;
        }
        public Builder mappedSecretSummaryCollections(GetNetworkFirewallPolicyMappedSecretsMappedSecretSummaryCollection... mappedSecretSummaryCollections) {
            return mappedSecretSummaryCollections(List.of(mappedSecretSummaryCollections));
        }
        @CustomType.Setter
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            if (networkFirewallPolicyId == null) {
              throw new MissingRequiredPropertyException("GetNetworkFirewallPolicyMappedSecretsResult", "networkFirewallPolicyId");
            }
            this.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }
        public GetNetworkFirewallPolicyMappedSecretsResult build() {
            final var _resultValue = new GetNetworkFirewallPolicyMappedSecretsResult();
            _resultValue.displayName = displayName;
            _resultValue.id = id;
            _resultValue.mappedSecretSummaryCollections = mappedSecretSummaryCollections;
            _resultValue.networkFirewallPolicyId = networkFirewallPolicyId;
            return _resultValue;
        }
    }
}
