// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.Identity.inputs.NetworkSourceVirtualSourceListArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkSourceState extends com.pulumi.resources.ResourceArgs {

    public static final NetworkSourceState Empty = new NetworkSourceState();

    /**
     * The OCID of the tenancy (root compartment) containing the network source object.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy (root compartment) containing the network source object.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it&#39;s changeable.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The detailed status of INACTIVE lifecycleState.
     * 
     */
    @Import(name="inactiveState")
    private @Nullable Output<String> inactiveState;

    /**
     * @return The detailed status of INACTIVE lifecycleState.
     * 
     */
    public Optional<Output<String>> inactiveState() {
        return Optional.ofNullable(this.inactiveState);
    }

    /**
     * The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) A list of allowed public IP addresses and CIDR ranges.
     * 
     */
    @Import(name="publicSourceLists")
    private @Nullable Output<List<String>> publicSourceLists;

    /**
     * @return (Updatable) A list of allowed public IP addresses and CIDR ranges.
     * 
     */
    public Optional<Output<List<String>>> publicSourceLists() {
        return Optional.ofNullable(this.publicSourceLists);
    }

    /**
     * (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     * 
     */
    @Import(name="services")
    private @Nullable Output<List<String>> services;

    /**
     * @return (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
     * 
     */
    public Optional<Output<List<String>>> services() {
        return Optional.ofNullable(this.services);
    }

    /**
     * The network source object&#39;s current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The network source object&#39;s current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeCreated")
    private @Nullable Output<String> timeCreated;

    /**
     * @return Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeCreated() {
        return Optional.ofNullable(this.timeCreated);
    }

    /**
     * (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
     * 
     */
    @Import(name="virtualSourceLists")
    private @Nullable Output<List<NetworkSourceVirtualSourceListArgs>> virtualSourceLists;

    /**
     * @return (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
     * 
     */
    public Optional<Output<List<NetworkSourceVirtualSourceListArgs>>> virtualSourceLists() {
        return Optional.ofNullable(this.virtualSourceLists);
    }

    private NetworkSourceState() {}

    private NetworkSourceState(NetworkSourceState $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.freeformTags = $.freeformTags;
        this.inactiveState = $.inactiveState;
        this.name = $.name;
        this.publicSourceLists = $.publicSourceLists;
        this.services = $.services;
        this.state = $.state;
        this.timeCreated = $.timeCreated;
        this.virtualSourceLists = $.virtualSourceLists;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkSourceState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkSourceState $;

        public Builder() {
            $ = new NetworkSourceState();
        }

        public Builder(NetworkSourceState defaults) {
            $ = new NetworkSourceState(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the tenancy (root compartment) containing the network source object.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the tenancy (root compartment) containing the network source object.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description you assign to the network source during creation. Does not have to be unique, and it&#39;s changeable.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(@Nullable Output<String> inactiveState) {
            $.inactiveState = inactiveState;
            return this;
        }

        /**
         * @param inactiveState The detailed status of INACTIVE lifecycleState.
         * 
         * @return builder
         * 
         */
        public Builder inactiveState(String inactiveState) {
            return inactiveState(Output.of(inactiveState));
        }

        /**
         * @param name The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name The name you assign to the network source during creation. The name must be unique across all groups in the tenancy and cannot be changed.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param publicSourceLists (Updatable) A list of allowed public IP addresses and CIDR ranges.
         * 
         * @return builder
         * 
         */
        public Builder publicSourceLists(@Nullable Output<List<String>> publicSourceLists) {
            $.publicSourceLists = publicSourceLists;
            return this;
        }

        /**
         * @param publicSourceLists (Updatable) A list of allowed public IP addresses and CIDR ranges.
         * 
         * @return builder
         * 
         */
        public Builder publicSourceLists(List<String> publicSourceLists) {
            return publicSourceLists(Output.of(publicSourceLists));
        }

        /**
         * @param publicSourceLists (Updatable) A list of allowed public IP addresses and CIDR ranges.
         * 
         * @return builder
         * 
         */
        public Builder publicSourceLists(String... publicSourceLists) {
            return publicSourceLists(List.of(publicSourceLists));
        }

        /**
         * @param services (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
         * 
         * @return builder
         * 
         */
        public Builder services(@Nullable Output<List<String>> services) {
            $.services = services;
            return this;
        }

        /**
         * @param services (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
         * 
         * @return builder
         * 
         */
        public Builder services(List<String> services) {
            return services(Output.of(services));
        }

        /**
         * @param services (Updatable) A list of services allowed to make on-behalf-of requests. These requests can have different source IP addresses than those listed in the network source. Currently, only `all` and `none` are supported. The default is `all`.
         * 
         * @return builder
         * 
         */
        public Builder services(String... services) {
            return services(List.of(services));
        }

        /**
         * @param state The network source object&#39;s current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The network source object&#39;s current state. After creating a network source, make sure its `lifecycleState` changes from CREATING to ACTIVE before using it.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param timeCreated Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(@Nullable Output<String> timeCreated) {
            $.timeCreated = timeCreated;
            return this;
        }

        /**
         * @param timeCreated Date and time the group was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeCreated(String timeCreated) {
            return timeCreated(Output.of(timeCreated));
        }

        /**
         * @param virtualSourceLists (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
         * 
         * @return builder
         * 
         */
        public Builder virtualSourceLists(@Nullable Output<List<NetworkSourceVirtualSourceListArgs>> virtualSourceLists) {
            $.virtualSourceLists = virtualSourceLists;
            return this;
        }

        /**
         * @param virtualSourceLists (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
         * 
         * @return builder
         * 
         */
        public Builder virtualSourceLists(List<NetworkSourceVirtualSourceListArgs> virtualSourceLists) {
            return virtualSourceLists(Output.of(virtualSourceLists));
        }

        /**
         * @param virtualSourceLists (Updatable) A list of allowed VCN OCID and IP range pairs. Example:`&#34;vcnId&#34;: &#34;ocid1.vcn.oc1.iad.aaaaaaaaexampleuniqueID&#34;, &#34;ipRanges&#34;: [ &#34;129.213.39.0/24&#34; ]`
         * 
         * @return builder
         * 
         */
        public Builder virtualSourceLists(NetworkSourceVirtualSourceListArgs... virtualSourceLists) {
            return virtualSourceLists(List.of(virtualSourceLists));
        }

        public NetworkSourceState build() {
            return $;
        }
    }

}