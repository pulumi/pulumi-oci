// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetMaskingReportsFilter;
import com.pulumi.oci.DataSafe.outputs.GetMaskingReportsMaskingReportCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetMaskingReportsResult {
    private @Nullable String accessLevel;
    /**
     * @return The OCID of the compartment that contains the masking report.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    private @Nullable List<GetMaskingReportsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The OCID of the masking policy used.
     * 
     */
    private @Nullable String maskingPolicyId;
    /**
     * @return The list of masking_report_collection.
     * 
     */
    private List<GetMaskingReportsMaskingReportCollection> maskingReportCollections;
    /**
     * @return The OCID of the target database masked.
     * 
     */
    private @Nullable String targetId;

    private GetMaskingReportsResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return The OCID of the compartment that contains the masking report.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    public List<GetMaskingReportsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The OCID of the masking policy used.
     * 
     */
    public Optional<String> maskingPolicyId() {
        return Optional.ofNullable(this.maskingPolicyId);
    }
    /**
     * @return The list of masking_report_collection.
     * 
     */
    public List<GetMaskingReportsMaskingReportCollection> maskingReportCollections() {
        return this.maskingReportCollections;
    }
    /**
     * @return The OCID of the target database masked.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMaskingReportsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable List<GetMaskingReportsFilter> filters;
        private String id;
        private @Nullable String maskingPolicyId;
        private List<GetMaskingReportsMaskingReportCollection> maskingReportCollections;
        private @Nullable String targetId;
        public Builder() {}
        public Builder(GetMaskingReportsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.maskingPolicyId = defaults.maskingPolicyId;
    	      this.maskingReportCollections = defaults.maskingReportCollections;
    	      this.targetId = defaults.targetId;
        }

        @CustomType.Setter
        public Builder accessLevel(@Nullable String accessLevel) {

            this.accessLevel = accessLevel;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetMaskingReportsResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentIdInSubtree(@Nullable Boolean compartmentIdInSubtree) {

            this.compartmentIdInSubtree = compartmentIdInSubtree;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetMaskingReportsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetMaskingReportsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMaskingReportsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder maskingPolicyId(@Nullable String maskingPolicyId) {

            this.maskingPolicyId = maskingPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder maskingReportCollections(List<GetMaskingReportsMaskingReportCollection> maskingReportCollections) {
            if (maskingReportCollections == null) {
              throw new MissingRequiredPropertyException("GetMaskingReportsResult", "maskingReportCollections");
            }
            this.maskingReportCollections = maskingReportCollections;
            return this;
        }
        public Builder maskingReportCollections(GetMaskingReportsMaskingReportCollection... maskingReportCollections) {
            return maskingReportCollections(List.of(maskingReportCollections));
        }
        @CustomType.Setter
        public Builder targetId(@Nullable String targetId) {

            this.targetId = targetId;
            return this;
        }
        public GetMaskingReportsResult build() {
            final var _resultValue = new GetMaskingReportsResult();
            _resultValue.accessLevel = accessLevel;
            _resultValue.compartmentId = compartmentId;
            _resultValue.compartmentIdInSubtree = compartmentIdInSubtree;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.maskingPolicyId = maskingPolicyId;
            _resultValue.maskingReportCollections = maskingReportCollections;
            _resultValue.targetId = targetId;
            return _resultValue;
        }
    }
}
