// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrgAttachmentNetworkDetails {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
     * 
     */
    private String id;
    /**
     * @return The IPSec connection that contains the attached IPSec tunnel.
     * 
     */
    private @Nullable String ipsecConnectionId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
     * 
     */
    private @Nullable String routeTableId;
    /**
     * @return (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
     * 
     */
    private String type;
    /**
     * @return (Updatable) Indicates whether the VCN CIDRs or the individual subnet CIDRs are imported from the attachment. Routes from the VCN ingress route table are always imported.
     * 
     */
    private @Nullable String vcnRouteType;

    private DrgAttachmentNetworkDetails() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The IPSec connection that contains the attached IPSec tunnel.
     * 
     */
    public Optional<String> ipsecConnectionId() {
        return Optional.ofNullable(this.ipsecConnectionId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table used by the DRG attachment.
     * 
     */
    public Optional<String> routeTableId() {
        return Optional.ofNullable(this.routeTableId);
    }
    /**
     * @return (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
     * 
     */
    public String type() {
        return this.type;
    }
    /**
     * @return (Updatable) Indicates whether the VCN CIDRs or the individual subnet CIDRs are imported from the attachment. Routes from the VCN ingress route table are always imported.
     * 
     */
    public Optional<String> vcnRouteType() {
        return Optional.ofNullable(this.vcnRouteType);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrgAttachmentNetworkDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private @Nullable String ipsecConnectionId;
        private @Nullable String routeTableId;
        private String type;
        private @Nullable String vcnRouteType;
        public Builder() {}
        public Builder(DrgAttachmentNetworkDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.ipsecConnectionId = defaults.ipsecConnectionId;
    	      this.routeTableId = defaults.routeTableId;
    	      this.type = defaults.type;
    	      this.vcnRouteType = defaults.vcnRouteType;
        }

        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder ipsecConnectionId(@Nullable String ipsecConnectionId) {
            this.ipsecConnectionId = ipsecConnectionId;
            return this;
        }
        @CustomType.Setter
        public Builder routeTableId(@Nullable String routeTableId) {
            this.routeTableId = routeTableId;
            return this;
        }
        @CustomType.Setter
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }
        @CustomType.Setter
        public Builder vcnRouteType(@Nullable String vcnRouteType) {
            this.vcnRouteType = vcnRouteType;
            return this;
        }
        public DrgAttachmentNetworkDetails build() {
            final var o = new DrgAttachmentNetworkDetails();
            o.id = id;
            o.ipsecConnectionId = ipsecConnectionId;
            o.routeTableId = routeTableId;
            o.type = type;
            o.vcnRouteType = vcnRouteType;
            return o;
        }
    }
}