// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.DisasterRecovery.inputs.DrProtectionGroupAssociationArgs;
import com.pulumi.oci.DisasterRecovery.inputs.DrProtectionGroupLogLocationArgs;
import com.pulumi.oci.DisasterRecovery.inputs.DrProtectionGroupMemberArgs;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DrProtectionGroupArgs extends com.pulumi.resources.ResourceArgs {

    public static final DrProtectionGroupArgs Empty = new DrProtectionGroupArgs();

    /**
     * The details for associating this DR Protection Group with a peer (remote) DR Protection Group.
     * 
     */
    @Import(name="association")
    private @Nullable Output<DrProtectionGroupAssociationArgs> association;

    /**
     * @return The details for associating this DR Protection Group with a peer (remote) DR Protection Group.
     * 
     */
    public Optional<Output<DrProtectionGroupAssociationArgs>> association() {
        return Optional.ofNullable(this.association);
    }

    /**
     * (Updatable) The OCID of the compartment in which to create the DR Protection Group.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment in which to create the DR Protection Group.  Example: `ocid1.compartment.oc1..exampleocid1`
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
     * 
     */
    @Import(name="disassociateTrigger")
    private @Nullable Output<Integer> disassociateTrigger;

    /**
     * @return (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
     * 
     */
    public Optional<Output<Integer>> disassociateTrigger() {
        return Optional.ofNullable(this.disassociateTrigger);
    }

    /**
     * (Updatable) The display name of the DR Protection Group.  Example: `EBS PHX DRPG`
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) The display name of the DR Protection Group.  Example: `EBS PHX DRPG`
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Information about creating an Object Storage log location for a DR Protection Group.
     * 
     */
    @Import(name="logLocation", required=true)
    private Output<DrProtectionGroupLogLocationArgs> logLocation;

    /**
     * @return (Updatable) Information about creating an Object Storage log location for a DR Protection Group.
     * 
     */
    public Output<DrProtectionGroupLogLocationArgs> logLocation() {
        return this.logLocation;
    }

    /**
     * (Updatable) A list of DR Protection Group members.
     * 
     */
    @Import(name="members")
    private @Nullable Output<List<DrProtectionGroupMemberArgs>> members;

    /**
     * @return (Updatable) A list of DR Protection Group members.
     * 
     */
    public Optional<Output<List<DrProtectionGroupMemberArgs>>> members() {
        return Optional.ofNullable(this.members);
    }

    private DrProtectionGroupArgs() {}

    private DrProtectionGroupArgs(DrProtectionGroupArgs $) {
        this.association = $.association;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.disassociateTrigger = $.disassociateTrigger;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.logLocation = $.logLocation;
        this.members = $.members;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DrProtectionGroupArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DrProtectionGroupArgs $;

        public Builder() {
            $ = new DrProtectionGroupArgs();
        }

        public Builder(DrProtectionGroupArgs defaults) {
            $ = new DrProtectionGroupArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param association The details for associating this DR Protection Group with a peer (remote) DR Protection Group.
         * 
         * @return builder
         * 
         */
        public Builder association(@Nullable Output<DrProtectionGroupAssociationArgs> association) {
            $.association = association;
            return this;
        }

        /**
         * @param association The details for associating this DR Protection Group with a peer (remote) DR Protection Group.
         * 
         * @return builder
         * 
         */
        public Builder association(DrProtectionGroupAssociationArgs association) {
            return association(Output.of(association));
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment in which to create the DR Protection Group.  Example: `ocid1.compartment.oc1..exampleocid1`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The OCID of the compartment in which to create the DR Protection Group.  Example: `ocid1.compartment.oc1..exampleocid1`
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param disassociateTrigger (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
         * 
         * @return builder
         * 
         */
        public Builder disassociateTrigger(@Nullable Output<Integer> disassociateTrigger) {
            $.disassociateTrigger = disassociateTrigger;
            return this;
        }

        /**
         * @param disassociateTrigger (Updatable) An optional property when incremented triggers Disassociate. Could be set to any integer value.
         * 
         * @return builder
         * 
         */
        public Builder disassociateTrigger(Integer disassociateTrigger) {
            return disassociateTrigger(Output.of(disassociateTrigger));
        }

        /**
         * @param displayName (Updatable) The display name of the DR Protection Group.  Example: `EBS PHX DRPG`
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The display name of the DR Protection Group.  Example: `EBS PHX DRPG`
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param logLocation (Updatable) Information about creating an Object Storage log location for a DR Protection Group.
         * 
         * @return builder
         * 
         */
        public Builder logLocation(Output<DrProtectionGroupLogLocationArgs> logLocation) {
            $.logLocation = logLocation;
            return this;
        }

        /**
         * @param logLocation (Updatable) Information about creating an Object Storage log location for a DR Protection Group.
         * 
         * @return builder
         * 
         */
        public Builder logLocation(DrProtectionGroupLogLocationArgs logLocation) {
            return logLocation(Output.of(logLocation));
        }

        /**
         * @param members (Updatable) A list of DR Protection Group members.
         * 
         * @return builder
         * 
         */
        public Builder members(@Nullable Output<List<DrProtectionGroupMemberArgs>> members) {
            $.members = members;
            return this;
        }

        /**
         * @param members (Updatable) A list of DR Protection Group members.
         * 
         * @return builder
         * 
         */
        public Builder members(List<DrProtectionGroupMemberArgs> members) {
            return members(Output.of(members));
        }

        /**
         * @param members (Updatable) A list of DR Protection Group members.
         * 
         * @return builder
         * 
         */
        public Builder members(DrProtectionGroupMemberArgs... members) {
            return members(List.of(members));
        }

        public DrProtectionGroupArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.logLocation = Objects.requireNonNull($.logLocation, "expected parameter 'logLocation' to be non-null");
            return $;
        }
    }

}