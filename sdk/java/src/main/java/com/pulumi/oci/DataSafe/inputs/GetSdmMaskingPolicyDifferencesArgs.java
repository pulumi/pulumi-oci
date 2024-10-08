// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.inputs.GetSdmMaskingPolicyDifferencesFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetSdmMaskingPolicyDifferencesArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetSdmMaskingPolicyDifferencesArgs Empty = new GetSdmMaskingPolicyDifferencesArgs();

    /**
     * A filter to return only resources that match the specified compartment OCID.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return A filter to return only resources that match the specified compartment OCID.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    @Import(name="compartmentIdInSubtree")
    private @Nullable Output<Boolean> compartmentIdInSubtree;

    /**
     * @return Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
     * 
     */
    public Optional<Output<Boolean>> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }

    /**
     * Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
     * 
     */
    @Import(name="differenceAccessLevel")
    private @Nullable Output<String> differenceAccessLevel;

    /**
     * @return Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
     * 
     */
    public Optional<Output<String>> differenceAccessLevel() {
        return Optional.ofNullable(this.differenceAccessLevel);
    }

    /**
     * A filter to return only resources that match the specified display name.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return A filter to return only resources that match the specified display name.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetSdmMaskingPolicyDifferencesFilterArgs>> filters;

    public Optional<Output<List<GetSdmMaskingPolicyDifferencesFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return only the resources that match the specified masking policy OCID.
     * 
     */
    @Import(name="maskingPolicyId")
    private @Nullable Output<String> maskingPolicyId;

    /**
     * @return A filter to return only the resources that match the specified masking policy OCID.
     * 
     */
    public Optional<Output<String>> maskingPolicyId() {
        return Optional.ofNullable(this.maskingPolicyId);
    }

    /**
     * A filter to return only the resources that match the specified sensitive data model OCID.
     * 
     */
    @Import(name="sensitiveDataModelId")
    private @Nullable Output<String> sensitiveDataModelId;

    /**
     * @return A filter to return only the resources that match the specified sensitive data model OCID.
     * 
     */
    public Optional<Output<String>> sensitiveDataModelId() {
        return Optional.ofNullable(this.sensitiveDataModelId);
    }

    /**
     * A filter to return only the resources that match the specified lifecycle states.
     * 
     */
    @Import(name="state")
    private @Nullable Output<String> state;

    /**
     * @return A filter to return only the resources that match the specified lifecycle states.
     * 
     */
    public Optional<Output<String>> state() {
        return Optional.ofNullable(this.state);
    }

    private GetSdmMaskingPolicyDifferencesArgs() {}

    private GetSdmMaskingPolicyDifferencesArgs(GetSdmMaskingPolicyDifferencesArgs $) {
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.differenceAccessLevel = $.differenceAccessLevel;
        this.displayName = $.displayName;
        this.filters = $.filters;
        this.maskingPolicyId = $.maskingPolicyId;
        this.sensitiveDataModelId = $.sensitiveDataModelId;
        this.state = $.state;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetSdmMaskingPolicyDifferencesArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetSdmMaskingPolicyDifferencesArgs $;

        public Builder() {
            $ = new GetSdmMaskingPolicyDifferencesArgs();
        }

        public Builder(GetSdmMaskingPolicyDifferencesArgs defaults) {
            $ = new GetSdmMaskingPolicyDifferencesArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId A filter to return only resources that match the specified compartment OCID.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(@Nullable Output<Boolean> compartmentIdInSubtree) {
            $.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }

        /**
         * @param compartmentIdInSubtree Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the &#39;accessLevel&#39; setting.
         * 
         * @return builder
         * 
         */
        public Builder compartmentIdInSubtree(Boolean compartmentIdInSubtree) {
            return compartmentIdInSubtree(Output.of(compartmentIdInSubtree));
        }

        /**
         * @param differenceAccessLevel Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
         * 
         * @return builder
         * 
         */
        public Builder differenceAccessLevel(@Nullable Output<String> differenceAccessLevel) {
            $.differenceAccessLevel = differenceAccessLevel;
            return this;
        }

        /**
         * @param differenceAccessLevel Valid value is ACCESSIBLE. Default is ACCESSIBLE. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment).
         * 
         * @return builder
         * 
         */
        public Builder differenceAccessLevel(String differenceAccessLevel) {
            return differenceAccessLevel(Output.of(differenceAccessLevel));
        }

        /**
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName A filter to return only resources that match the specified display name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        public Builder filters(@Nullable Output<List<GetSdmMaskingPolicyDifferencesFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetSdmMaskingPolicyDifferencesFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetSdmMaskingPolicyDifferencesFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param maskingPolicyId A filter to return only the resources that match the specified masking policy OCID.
         * 
         * @return builder
         * 
         */
        public Builder maskingPolicyId(@Nullable Output<String> maskingPolicyId) {
            $.maskingPolicyId = maskingPolicyId;
            return this;
        }

        /**
         * @param maskingPolicyId A filter to return only the resources that match the specified masking policy OCID.
         * 
         * @return builder
         * 
         */
        public Builder maskingPolicyId(String maskingPolicyId) {
            return maskingPolicyId(Output.of(maskingPolicyId));
        }

        /**
         * @param sensitiveDataModelId A filter to return only the resources that match the specified sensitive data model OCID.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveDataModelId(@Nullable Output<String> sensitiveDataModelId) {
            $.sensitiveDataModelId = sensitiveDataModelId;
            return this;
        }

        /**
         * @param sensitiveDataModelId A filter to return only the resources that match the specified sensitive data model OCID.
         * 
         * @return builder
         * 
         */
        public Builder sensitiveDataModelId(String sensitiveDataModelId) {
            return sensitiveDataModelId(Output.of(sensitiveDataModelId));
        }

        /**
         * @param state A filter to return only the resources that match the specified lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder state(@Nullable Output<String> state) {
            $.state = state;
            return this;
        }

        /**
         * @param state A filter to return only the resources that match the specified lifecycle states.
         * 
         * @return builder
         * 
         */
        public Builder state(String state) {
            return state(Output.of(state));
        }

        public GetSdmMaskingPolicyDifferencesArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetSdmMaskingPolicyDifferencesArgs", "compartmentId");
            }
            return $;
        }
    }

}
