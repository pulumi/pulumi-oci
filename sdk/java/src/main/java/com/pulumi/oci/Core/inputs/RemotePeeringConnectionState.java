// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class RemotePeeringConnectionState extends com.pulumi.resources.ResourceArgs {

    public static final RemotePeeringConnectionState Empty = new RemotePeeringConnectionState();

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the RPC.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the RPC.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the RPC belongs to.
     * 
     */
    @Import(name="drgId")
    private @Nullable Output<String> drgId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the RPC belongs to.
     * 
     */
    public Optional<Output<String>> drgId() {
        return Optional.ofNullable(this.drgId);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
     * 
     */
    @Import(name="isCrossTenancyPeering")
    private @Nullable Output<Boolean> isCrossTenancyPeering;

    /**
     * @return Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
     * 
     */
    public Optional<Output<Boolean>> isCrossTenancyPeering() {
        return Optional.ofNullable(this.isCrossTenancyPeering);
    }

    /**
     * The OCID of the RPC you want to peer with.
     * 
     */
    @Import(name="peerId")
    private @Nullable Output<String> peerId;

    /**
     * @return The OCID of the RPC you want to peer with.
     * 
     */
    public Optional<Output<String>> peerId() {
        return Optional.ofNullable(this.peerId);
    }

    /**
     * The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
     * 
     */
    @Import(name="peerRegionName")
    private @Nullable Output<String> peerRegionName;

    /**
     * @return The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
     * 
     */
    public Optional<Output<String>> peerRegionName() {
        return Optional.ofNullable(this.peerRegionName);
    }

    /**
     * If this RPC is peered, this value is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the other RPC&#39;s tenancy.
     * 
     */
    @Import(name="peerTenancyId")
    private @Nullable Output<String> peerTenancyId;

    /**
     * @return If this RPC is peered, this value is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the other RPC&#39;s tenancy.
     * 
     */
    public Optional<Output<String>> peerTenancyId() {
        return Optional.ofNullable(this.peerTenancyId);
    }

    /**
     * Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
     * 
     */
    @Import(name="peeringStatus")
    private @Nullable Output<String> peeringStatus;

    /**
     * @return Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
     * 
     */
    public Optional<Output<String>> peeringStatus() {
        return Optional.ofNullable(this.peeringStatus);
    }

    /**
     * The RPC&#39;s current lifecycle state.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The RPC&#39;s current lifecycle state.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    private RemotePeeringConnectionState() {}

    private RemotePeeringConnectionState(RemotePeeringConnectionState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.drgId = $.drgId;
        this.freeformTags = $.freeformTags;
        this.isCrossTenancyPeering = $.isCrossTenancyPeering;
        this.peerId = $.peerId;
        this.peerRegionName = $.peerRegionName;
        this.peerTenancyId = $.peerTenancyId;
        this.peeringStatus = $.peeringStatus;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(RemotePeeringConnectionState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private RemotePeeringConnectionState $;

        public Builder() {
            $ = new RemotePeeringConnectionState();
        }

        public Builder(RemotePeeringConnectionState defaults) {
            $ = new RemotePeeringConnectionState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the RPC.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment to contain the RPC.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param drgId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the RPC belongs to.
         * 
         * @return builder
         * 
         */
        public Builder drgId(@Nullable Output<String> drgId) {
            $.drgId = drgId;
            return this;
        }

        /**
         * @param drgId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the DRG the RPC belongs to.
         * 
         * @return builder
         * 
         */
        public Builder drgId(String drgId) {
            return drgId(Output.of(drgId));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param isCrossTenancyPeering Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isCrossTenancyPeering(@Nullable Output<Boolean> isCrossTenancyPeering) {
            $.isCrossTenancyPeering = isCrossTenancyPeering;
            return this;
        }

        /**
         * @param isCrossTenancyPeering Whether the VCN at the other end of the peering is in a different tenancy.  Example: `false`
         * 
         * @return builder
         * 
         */
        public Builder isCrossTenancyPeering(Boolean isCrossTenancyPeering) {
            return isCrossTenancyPeering(Output.of(isCrossTenancyPeering));
        }

        /**
         * @param peerId The OCID of the RPC you want to peer with.
         * 
         * @return builder
         * 
         */
        public Builder peerId(@Nullable Output<String> peerId) {
            $.peerId = peerId;
            return this;
        }

        /**
         * @param peerId The OCID of the RPC you want to peer with.
         * 
         * @return builder
         * 
         */
        public Builder peerId(String peerId) {
            return peerId(Output.of(peerId));
        }

        /**
         * @param peerRegionName The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
         * 
         * @return builder
         * 
         */
        public Builder peerRegionName(@Nullable Output<String> peerRegionName) {
            $.peerRegionName = peerRegionName;
            return this;
        }

        /**
         * @param peerRegionName The name of the region that contains the RPC you want to peer with.  Example: `us-ashburn-1`
         * 
         * @return builder
         * 
         */
        public Builder peerRegionName(String peerRegionName) {
            return peerRegionName(Output.of(peerRegionName));
        }

        /**
         * @param peerTenancyId If this RPC is peered, this value is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the other RPC&#39;s tenancy.
         * 
         * @return builder
         * 
         */
        public Builder peerTenancyId(@Nullable Output<String> peerTenancyId) {
            $.peerTenancyId = peerTenancyId;
            return this;
        }

        /**
         * @param peerTenancyId If this RPC is peered, this value is the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the other RPC&#39;s tenancy.
         * 
         * @return builder
         * 
         */
        public Builder peerTenancyId(String peerTenancyId) {
            return peerTenancyId(Output.of(peerTenancyId));
        }

        /**
         * @param peeringStatus Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
         * 
         * @return builder
         * 
         */
        public Builder peeringStatus(@Nullable Output<String> peeringStatus) {
            $.peeringStatus = peeringStatus;
            return this;
        }

        /**
         * @param peeringStatus Whether the RPC is peered with another RPC. `NEW` means the RPC has not yet been peered. `PENDING` means the peering is being established. `REVOKED` means the RPC at the other end of the peering has been deleted.
         * 
         * @return builder
         * 
         */
        public Builder peeringStatus(String peeringStatus) {
            return peeringStatus(Output.of(peeringStatus));
        }

        /**
         * @param state The RPC&#39;s current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The RPC&#39;s current lifecycle state.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated The date and time the RPC was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        public RemotePeeringConnectionState build() {
            return $;
        }
    }

}