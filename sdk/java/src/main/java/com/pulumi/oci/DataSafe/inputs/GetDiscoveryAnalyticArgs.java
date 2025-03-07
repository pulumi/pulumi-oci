// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetDiscoveryAnalyticArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetDiscoveryAnalyticArgs Empty = new GetDiscoveryAnalyticArgs();

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
     * Attribute by which the discovery analytics data should be grouped.
     * 
     */
    @Import(name="groupBy")
    private @Nullable Output<String> groupBy;

    /**
     * @return Attribute by which the discovery analytics data should be grouped.
     * 
     */
    public Optional<Output<String>> groupBy() {
        return Optional.ofNullable(this.groupBy);
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
     * A filter to return only items related to a specific target OCID.
     * 
     */
    @Import(name="targetId")
    private @Nullable Output<String> targetId;

    /**
     * @return A filter to return only items related to a specific target OCID.
     * 
     */
    public Optional<Output<String>> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    private GetDiscoveryAnalyticArgs() {}

    private GetDiscoveryAnalyticArgs(GetDiscoveryAnalyticArgs $) {
        this.compartmentId = $.compartmentId;
        this.compartmentIdInSubtree = $.compartmentIdInSubtree;
        this.groupBy = $.groupBy;
        this.sensitiveDataModelId = $.sensitiveDataModelId;
        this.targetId = $.targetId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetDiscoveryAnalyticArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetDiscoveryAnalyticArgs $;

        public Builder() {
            $ = new GetDiscoveryAnalyticArgs();
        }

        public Builder(GetDiscoveryAnalyticArgs defaults) {
            $ = new GetDiscoveryAnalyticArgs(Objects.requireNonNull(defaults));
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
         * @param groupBy Attribute by which the discovery analytics data should be grouped.
         * 
         * @return builder
         * 
         */
        public Builder groupBy(@Nullable Output<String> groupBy) {
            $.groupBy = groupBy;
            return this;
        }

        /**
         * @param groupBy Attribute by which the discovery analytics data should be grouped.
         * 
         * @return builder
         * 
         */
        public Builder groupBy(String groupBy) {
            return groupBy(Output.of(groupBy));
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
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(@Nullable Output<String> targetId) {
            $.targetId = targetId;
            return this;
        }

        /**
         * @param targetId A filter to return only items related to a specific target OCID.
         * 
         * @return builder
         * 
         */
        public Builder targetId(String targetId) {
            return targetId(Output.of(targetId));
        }

        public GetDiscoveryAnalyticArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetDiscoveryAnalyticArgs", "compartmentId");
            }
            return $;
        }
    }

}
