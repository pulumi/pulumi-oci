// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost {
    private String hostIp;
    private Integer port;

    private GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost() {}
    public String hostIp() {
        return this.hostIp;
    }
    public Integer port() {
        return this.port;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostIp;
        private Integer port;
        public Builder() {}
        public Builder(GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostIp = defaults.hostIp;
    	      this.port = defaults.port;
        }

        @CustomType.Setter
        public Builder hostIp(String hostIp) {
            this.hostIp = Objects.requireNonNull(hostIp);
            return this;
        }
        @CustomType.Setter
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }
        public GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost build() {
            final var o = new GetExadataInsightMemberVmClusterDetailMemberDatabaseDetailConnectionDetailHost();
            o.hostIp = hostIp;
            o.port = port;
            return o;
        }
    }
}