// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost {
    private String hostIp;
    private Integer port;

    private GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost() {}
    public String hostIp() {
        return this.hostIp;
    }
    public Integer port() {
        return this.port;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostIp;
        private Integer port;
        public Builder() {}
        public Builder(GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostIp = defaults.hostIp;
    	      this.port = defaults.port;
        }

        @CustomType.Setter
        public Builder hostIp(String hostIp) {
            if (hostIp == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost", "hostIp");
            }
            this.hostIp = hostIp;
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            if (port == null) {
              throw new MissingRequiredPropertyException("GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost", "port");
            }
            this.port = port;
            return this;
        }
        public GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost build() {
            final var _resultValue = new GetExadataInsightsExadataInsightSummaryCollectionItemMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost();
            _resultValue.hostIp = hostIp;
            _resultValue.port = port;
            return _resultValue;
        }
    }
}
