// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Core.outputs.GetIpsecStatusFilter;
import com.pulumi.oci.Core.outputs.GetIpsecStatusTunnel;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import javax.annotation.Nullable;

@CustomType
public final class GetIpsecStatusResult {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the IPSec connection.
     * 
     */
    private final String compartmentId;
    private final @Nullable List<GetIpsecStatusFilter> filters;
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
     * @return Two [TunnelStatus](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelStatus/) objects.
     * 
     */
    private final List<GetIpsecStatusTunnel> tunnels;

    @CustomType.Constructor
    private GetIpsecStatusResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetIpsecStatusFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("ipsecId") String ipsecId,
        @CustomType.Parameter("timeCreated") String timeCreated,
        @CustomType.Parameter("tunnels") List<GetIpsecStatusTunnel> tunnels) {
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
    public List<GetIpsecStatusFilter> filters() {
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
     * @return Two [TunnelStatus](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/TunnelStatus/) objects.
     * 
     */
    public List<GetIpsecStatusTunnel> tunnels() {
        return this.tunnels;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecStatusResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable List<GetIpsecStatusFilter> filters;
        private String id;
        private String ipsecId;
        private String timeCreated;
        private List<GetIpsecStatusTunnel> tunnels;

        public Builder() {
    	      // Empty
        }

        public Builder(GetIpsecStatusResult defaults) {
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
        public Builder filters(@Nullable List<GetIpsecStatusFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetIpsecStatusFilter... filters) {
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
        public Builder tunnels(List<GetIpsecStatusTunnel> tunnels) {
            this.tunnels = Objects.requireNonNull(tunnels);
            return this;
        }
        public Builder tunnels(GetIpsecStatusTunnel... tunnels) {
            return tunnels(List.of(tunnels));
        }        public GetIpsecStatusResult build() {
            return new GetIpsecStatusResult(compartmentId, filters, id, ipsecId, timeCreated, tunnels);
        }
    }
}
