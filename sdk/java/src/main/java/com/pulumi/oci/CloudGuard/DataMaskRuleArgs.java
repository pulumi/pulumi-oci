// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CloudGuard;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.CloudGuard.inputs.DataMaskRuleTargetSelectedArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DataMaskRuleArgs extends com.pulumi.resources.ResourceArgs {

    public static final DataMaskRuleArgs Empty = new DataMaskRuleArgs();

    /**
     * (Updatable) Compartment Identifier where the resource is created
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier where the resource is created
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Data Mask Categories
     * 
     */
    @Import(name="dataMaskCategories", required=true)
    private Output<List<String>> dataMaskCategories;

    /**
     * @return (Updatable) Data Mask Categories
     * 
     */
    public Output<List<String>> dataMaskCategories() {
        return this.dataMaskCategories;
    }

    /**
     * (Updatable) The status of the dataMaskRule.
     * 
     */
    @Import(name="dataMaskRuleStatus")
    private @Nullable Output<String> dataMaskRuleStatus;

    /**
     * @return (Updatable) The status of the dataMaskRule.
     * 
     */
    public Optional<Output<String>> dataMaskRuleStatus() {
        return Optional.ofNullable(this.dataMaskRuleStatus);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * The data mask rule description. Avoid entering confidential information.
     * 
     */
    @Import(name="description")
    private @Nullable Output<String> description;

    /**
     * @return The data mask rule description. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> description() {
        return Optional.ofNullable(this.description);
    }

    /**
     * (Updatable) Data mask rule name.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Data mask rule name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) IAM Group id associated with the data mask rule
     * 
     */
    @Import(name="iamGroupId", required=true)
    private Output<String> iamGroupId;

    /**
     * @return (Updatable) IAM Group id associated with the data mask rule
     * 
     */
    public Output<String> iamGroupId() {
        return this.iamGroupId;
    }

    /**
     * The current state of the DataMaskRule.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return The current state of the DataMaskRule.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    /**
     * (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     * 
     */
    @Import(name="targetSelected", required=true)
    private Output<DataMaskRuleTargetSelectedArgs> targetSelected;

    /**
     * @return (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
     * 
     */
    public Output<DataMaskRuleTargetSelectedArgs> targetSelected() {
        return this.targetSelected;
    }

    private DataMaskRuleArgs() {}

    private DataMaskRuleArgs(DataMaskRuleArgs $) {
        this.compartmentId = $.compartmentId;
        this.dataMaskCategories = $.dataMaskCategories;
        this.dataMaskRuleStatus = $.dataMaskRuleStatus;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.iamGroupId = $.iamGroupId;
        this.state = $.state;
        this.targetSelected = $.targetSelected;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DataMaskRuleArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DataMaskRuleArgs $;

        public Builder() {
            $ = new DataMaskRuleArgs();
        }

        public Builder(DataMaskRuleArgs defaults) {
            $ = new DataMaskRuleArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier where the resource is created
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier where the resource is created
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param dataMaskCategories (Updatable) Data Mask Categories
         * 
         * @return builder
         * 
         */
        public Builder dataMaskCategories(Output<List<String>> dataMaskCategories) {
            $.dataMaskCategories = dataMaskCategories;
            return this;
        }

        /**
         * @param dataMaskCategories (Updatable) Data Mask Categories
         * 
         * @return builder
         * 
         */
        public Builder dataMaskCategories(List<String> dataMaskCategories) {
            return dataMaskCategories(Output.of(dataMaskCategories));
        }

        /**
         * @param dataMaskCategories (Updatable) Data Mask Categories
         * 
         * @return builder
         * 
         */
        public Builder dataMaskCategories(String... dataMaskCategories) {
            return dataMaskCategories(List.of(dataMaskCategories));
        }

        /**
         * @param dataMaskRuleStatus (Updatable) The status of the dataMaskRule.
         * 
         * @return builder
         * 
         */
        public Builder dataMaskRuleStatus(@Nullable Output<String> dataMaskRuleStatus) {
            $.dataMaskRuleStatus = dataMaskRuleStatus;
            return this;
        }

        /**
         * @param dataMaskRuleStatus (Updatable) The status of the dataMaskRule.
         * 
         * @return builder
         * 
         */
        public Builder dataMaskRuleStatus(String dataMaskRuleStatus) {
            return dataMaskRuleStatus(Output.of(dataMaskRuleStatus));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description The data mask rule description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(@Nullable Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description The data mask rule description. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) Data mask rule name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Data mask rule name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param iamGroupId (Updatable) IAM Group id associated with the data mask rule
         * 
         * @return builder
         * 
         */
        public Builder iamGroupId(Output<String> iamGroupId) {
            $.iamGroupId = iamGroupId;
            return this;
        }

        /**
         * @param iamGroupId (Updatable) IAM Group id associated with the data mask rule
         * 
         * @return builder
         * 
         */
        public Builder iamGroupId(String iamGroupId) {
            return iamGroupId(Output.of(iamGroupId));
        }

        /**
         * @param state The current state of the DataMaskRule.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state The current state of the DataMaskRule.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        /**
         * @param targetSelected (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
         * 
         * @return builder
         * 
         */
        public Builder targetSelected(Output<DataMaskRuleTargetSelectedArgs> targetSelected) {
            $.targetSelected = targetSelected;
            return this;
        }

        /**
         * @param targetSelected (Updatable) Target Selection eg select ALL or select on basis of TargetResourceTypes or TargetIds.
         * 
         * @return builder
         * 
         */
        public Builder targetSelected(DataMaskRuleTargetSelectedArgs targetSelected) {
            return targetSelected(Output.of(targetSelected));
        }

        public DataMaskRuleArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.dataMaskCategories = Objects.requireNonNull($.dataMaskCategories, "expected parameter 'dataMaskCategories' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            $.iamGroupId = Objects.requireNonNull($.iamGroupId, "expected parameter 'iamGroupId' to be non-null");
            $.targetSelected = Objects.requireNonNull($.targetSelected, "expected parameter 'targetSelected' to be non-null");
            return $;
        }
    }

}