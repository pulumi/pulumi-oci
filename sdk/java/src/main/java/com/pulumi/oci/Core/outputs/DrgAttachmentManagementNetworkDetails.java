// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrgAttachmentManagementNetworkDetails {
    /**
     * @return -(Required) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
     * 
     */
    private String id;
    /**
     * @return The IPSec connection that contains the attached IPSec tunnel.
     * 
     */
    private @Nullable String ipsecConnectionId;
    /**
     * @return (Updatable)- The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the DRG attachment is using.
     * 
     */
    private @Nullable String routeTableId;
    /**
     * @return The type can be one of these values: `IPSEC_TUNNEL`, `REMOTE_PEERING_CONNECTION`, `VCN`,`VIRTUAL_CIRCUIT`
     * * `route_table_id`(Optional)(Updatable) - The OCID of the route table the DRG attachment is using.
     * 
     */
    private String type;

    private DrgAttachmentManagementNetworkDetails() {}
    /**
     * @return -(Required) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
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
     * @return (Updatable)- The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table the DRG attachment is using.
     * 
     */
    public Optional<String> routeTableId() {
        return Optional.ofNullable(this.routeTableId);
    }
    /**
     * @return The type can be one of these values: `IPSEC_TUNNEL`, `REMOTE_PEERING_CONNECTION`, `VCN`,`VIRTUAL_CIRCUIT`
     * * `route_table_id`(Optional)(Updatable) - The OCID of the route table the DRG attachment is using.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrgAttachmentManagementNetworkDetails defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private @Nullable String ipsecConnectionId;
        private @Nullable String routeTableId;
        private String type;
        public Builder() {}
        public Builder(DrgAttachmentManagementNetworkDetails defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.ipsecConnectionId = defaults.ipsecConnectionId;
    	      this.routeTableId = defaults.routeTableId;
    	      this.type = defaults.type;
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
        public DrgAttachmentManagementNetworkDetails build() {
            final var o = new DrgAttachmentManagementNetworkDetails();
            o.id = id;
            o.ipsecConnectionId = ipsecConnectionId;
            o.routeTableId = routeTableId;
            o.type = type;
            return o;
        }
    }
}