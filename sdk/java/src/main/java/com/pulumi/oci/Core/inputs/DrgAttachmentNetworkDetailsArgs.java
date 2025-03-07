// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrgAttachmentNetworkDetailsArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrgAttachmentNetworkDetailsArgs Empty = new DrgAttachmentNetworkDetailsArgs();

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
     * 
     */
    @Import(name="id")
    private @Nullable Output<String> id;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
     * 
     */
    public Optional<Output<String>> id() {
        return Optional.ofNullable(this.id);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target IPSec tunnel attachment.
     * 
     */
    @Import(name="ids")
    private @Nullable Output<List<String>> ids;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target IPSec tunnel attachment.
     * 
     */
    public Optional<Output<List<String>>> ids() {
        return Optional.ofNullable(this.ids);
    }

    /**
     * The IPSec connection that contains the attached IPSec tunnel.
     * 
     */
    @Import(name="ipsecConnectionId")
    private @Nullable Output<String> ipsecConnectionId;

    /**
     * @return The IPSec connection that contains the attached IPSec tunnel.
     * 
     */
    public Optional<Output<String>> ipsecConnectionId() {
        return Optional.ofNullable(this.ipsecConnectionId);
    }

    /**
     * (Updatable) This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that is used to route the traffic as it enters a VCN through this attachment.
     * 
     * For information about why you would associate a route table with a DRG attachment, see [Advanced Scenario: Transit Routing](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm). For information about why you would associate a route table with a DRG attachment, see:
     * * [Transit Routing: Access to Multiple VCNs in Same Region](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm)
     * * [Transit Routing: Private Access to Oracle Services](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitroutingoracleservices.htm)
     * 
     */
    @Import(name="routeTableId")
    private @Nullable Output<String> routeTableId;

    /**
     * @return (Updatable) This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that is used to route the traffic as it enters a VCN through this attachment.
     * 
     * For information about why you would associate a route table with a DRG attachment, see [Advanced Scenario: Transit Routing](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm). For information about why you would associate a route table with a DRG attachment, see:
     * * [Transit Routing: Access to Multiple VCNs in Same Region](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm)
     * * [Transit Routing: Private Access to Oracle Services](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitroutingoracleservices.htm)
     * 
     */
    public Optional<Output<String>> routeTableId() {
        return Optional.ofNullable(this.routeTableId);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit&#39;s DRG attachment.
     * 
     */
    @Import(name="transportAttachmentId")
    private @Nullable Output<String> transportAttachmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit&#39;s DRG attachment.
     * 
     */
    public Optional<Output<String>> transportAttachmentId() {
        return Optional.ofNullable(this.transportAttachmentId);
    }

    /**
     * Boolean flag that determines wether all traffic over the virtual circuits is encrypted.  Example: `true`
     * 
     */
    @Import(name="transportOnlyMode")
    private @Nullable Output<Boolean> transportOnlyMode;

    /**
     * @return Boolean flag that determines wether all traffic over the virtual circuits is encrypted.  Example: `true`
     * 
     */
    public Optional<Output<Boolean>> transportOnlyMode() {
        return Optional.ofNullable(this.transportOnlyMode);
    }

    /**
     * (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `LOOPBACK`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
     * 
     */
    @Import(name="type", required=true)
    private Output<String> type;

    /**
     * @return (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `LOOPBACK`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
     * 
     */
    public Output<String> type() {
        return this.type;
    }

    /**
     * (Updatable) Indicates whether the VCN CIDRs or the individual subnet CIDRs are imported from the attachment. Routes from the VCN ingress route table are always imported.
     * 
     */
    @Import(name="vcnRouteType")
    private @Nullable Output<String> vcnRouteType;

    /**
     * @return (Updatable) Indicates whether the VCN CIDRs or the individual subnet CIDRs are imported from the attachment. Routes from the VCN ingress route table are always imported.
     * 
     */
    public Optional<Output<String>> vcnRouteType() {
        return Optional.ofNullable(this.vcnRouteType);
    }

    private DrgAttachmentNetworkDetailsArgs() {}

    private DrgAttachmentNetworkDetailsArgs(DrgAttachmentNetworkDetailsArgs $) {
        this.id = $.id;
        this.ids = $.ids;
        this.ipsecConnectionId = $.ipsecConnectionId;
        this.routeTableId = $.routeTableId;
        this.transportAttachmentId = $.transportAttachmentId;
        this.transportOnlyMode = $.transportOnlyMode;
        this.type = $.type;
        this.vcnRouteType = $.vcnRouteType;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrgAttachmentNetworkDetailsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrgAttachmentNetworkDetailsArgs $;

        public Builder() {
            $ = new DrgAttachmentNetworkDetailsArgs();
        }

        public Builder(DrgAttachmentNetworkDetailsArgs defaults) {
            $ = new DrgAttachmentNetworkDetailsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
         * 
         * @return builder
         * 
         */
        public Builder id(@Nullable Output<String> id) {
            $.id = id;
            return this;
        }

        /**
         * @param id The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the network attached to the DRG.
         * 
         * @return builder
         * 
         */
        public Builder id(String id) {
            return id(Output.of(id));
        }

        /**
         * @param ids The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target IPSec tunnel attachment.
         * 
         * @return builder
         * 
         */
        public Builder ids(@Nullable Output<List<String>> ids) {
            $.ids = ids;
            return this;
        }

        /**
         * @param ids The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target IPSec tunnel attachment.
         * 
         * @return builder
         * 
         */
        public Builder ids(List<String> ids) {
            return ids(Output.of(ids));
        }

        /**
         * @param ids The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the target IPSec tunnel attachment.
         * 
         * @return builder
         * 
         */
        public Builder ids(String... ids) {
            return ids(List.of(ids));
        }

        /**
         * @param ipsecConnectionId The IPSec connection that contains the attached IPSec tunnel.
         * 
         * @return builder
         * 
         */
        public Builder ipsecConnectionId(@Nullable Output<String> ipsecConnectionId) {
            $.ipsecConnectionId = ipsecConnectionId;
            return this;
        }

        /**
         * @param ipsecConnectionId The IPSec connection that contains the attached IPSec tunnel.
         * 
         * @return builder
         * 
         */
        public Builder ipsecConnectionId(String ipsecConnectionId) {
            return ipsecConnectionId(Output.of(ipsecConnectionId));
        }

        /**
         * @param routeTableId (Updatable) This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that is used to route the traffic as it enters a VCN through this attachment.
         * 
         * For information about why you would associate a route table with a DRG attachment, see [Advanced Scenario: Transit Routing](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm). For information about why you would associate a route table with a DRG attachment, see:
         * * [Transit Routing: Access to Multiple VCNs in Same Region](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm)
         * * [Transit Routing: Private Access to Oracle Services](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitroutingoracleservices.htm)
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(@Nullable Output<String> routeTableId) {
            $.routeTableId = routeTableId;
            return this;
        }

        /**
         * @param routeTableId (Updatable) This is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that is used to route the traffic as it enters a VCN through this attachment.
         * 
         * For information about why you would associate a route table with a DRG attachment, see [Advanced Scenario: Transit Routing](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm). For information about why you would associate a route table with a DRG attachment, see:
         * * [Transit Routing: Access to Multiple VCNs in Same Region](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitrouting.htm)
         * * [Transit Routing: Private Access to Oracle Services](https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/transitroutingoracleservices.htm)
         * 
         * @return builder
         * 
         */
        public Builder routeTableId(String routeTableId) {
            return routeTableId(Output.of(routeTableId));
        }

        /**
         * @param transportAttachmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit&#39;s DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder transportAttachmentId(@Nullable Output<String> transportAttachmentId) {
            $.transportAttachmentId = transportAttachmentId;
            return this;
        }

        /**
         * @param transportAttachmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the virtual circuit&#39;s DRG attachment.
         * 
         * @return builder
         * 
         */
        public Builder transportAttachmentId(String transportAttachmentId) {
            return transportAttachmentId(Output.of(transportAttachmentId));
        }

        /**
         * @param transportOnlyMode Boolean flag that determines wether all traffic over the virtual circuits is encrypted.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder transportOnlyMode(@Nullable Output<Boolean> transportOnlyMode) {
            $.transportOnlyMode = transportOnlyMode;
            return this;
        }

        /**
         * @param transportOnlyMode Boolean flag that determines wether all traffic over the virtual circuits is encrypted.  Example: `true`
         * 
         * @return builder
         * 
         */
        public Builder transportOnlyMode(Boolean transportOnlyMode) {
            return transportOnlyMode(Output.of(transportOnlyMode));
        }

        /**
         * @param type (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `LOOPBACK`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
         * 
         * @return builder
         * 
         */
        public Builder type(Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type (Updatable) The type can be one of these values: `IPSEC_TUNNEL`, `LOOPBACK`, `REMOTE_PEERING_CONNECTION`, `VCN`, `VIRTUAL_CIRCUIT`
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        /**
         * @param vcnRouteType (Updatable) Indicates whether the VCN CIDRs or the individual subnet CIDRs are imported from the attachment. Routes from the VCN ingress route table are always imported.
         * 
         * @return builder
         * 
         */
        public Builder vcnRouteType(@Nullable Output<String> vcnRouteType) {
            $.vcnRouteType = vcnRouteType;
            return this;
        }

        /**
         * @param vcnRouteType (Updatable) Indicates whether the VCN CIDRs or the individual subnet CIDRs are imported from the attachment. Routes from the VCN ingress route table are always imported.
         * 
         * @return builder
         * 
         */
        public Builder vcnRouteType(String vcnRouteType) {
            return vcnRouteType(Output.of(vcnRouteType));
        }

        public DrgAttachmentNetworkDetailsArgs build() {
            if ($.type == null) {
                throw new MissingRequiredPropertyException("DrgAttachmentNetworkDetailsArgs", "type");
            }
            return $;
        }
    }

}
