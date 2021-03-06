// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetIpsecConfigFilter;
import com.pulumi.oci.Core.outputs.GetIpsecConfigTunnel;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetIpsecConfigResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPSec connection.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetIpsecConfigFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String ipsecId;
    /**
     * @return The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private final String timeCreated;
    /**
     * @return Two [TunnelConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelConfig/) objects.
     * 
     */
    private final List<GetIpsecConfigTunnel> tunnels;

    @CustomType.Constructor
    private GetIpsecConfigResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetIpsecConfigFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("ipsecId") String ipsecId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("tunnels") List<GetIpsecConfigTunnel> tunnels) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.ipsecId = ipsecId;
        this.timeCreated = timeCreated;
        this.tunnels = tunnels;
    }

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPSec connection.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetIpsecConfigFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String ipsecId() {
        return this.ipsecId;
    }
    /**
     * @return The date and time the IPSec connection was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return Two [TunnelConfig](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelConfig/) objects.
     * 
     */
    public List<GetIpsecConfigTunnel> tunnels() {
        return this.tunnels;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecConfigResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetIpsecConfigFilter> filters;
        private String id;
        private String ipsecId;
        private String timeCreated;
        private List<GetIpsecConfigTunnel> tunnels;

        public Builder() {
    	      // Empty
        }

        public Builder(GetIpsecConfigResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.ipsecId = defaults.ipsecId;
    	      this.timeCreated = defaults.timeCreated;
    	      this.tunnels = defaults.tunnels;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetIpsecConfigFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIpsecConfigFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder ipsecId(String ipsecId) {
            this.ipsecId = Objects.requireNonNull(ipsecId);
            return this;
        }
        public Builder timeCreated(String timeCreated) {
            this.timeCreated = Objects.requireNonNull(timeCreated);
            return this;
        }
        public Builder tunnels(List<GetIpsecConfigTunnel> tunnels) {
            this.tunnels = Objects.requireNonNull(tunnels);
            return this;
        }
        public Builder tunnels(GetIpsecConfigTunnel... tunnels) {
            return tunnels(List.of(tunnels));
        }        public GetIpsecConfigResult build() {
            return new GetIpsecConfigResult(compartmentId, filters, id, ipsecId, timeCreated, tunnels);
        }
    }
}
