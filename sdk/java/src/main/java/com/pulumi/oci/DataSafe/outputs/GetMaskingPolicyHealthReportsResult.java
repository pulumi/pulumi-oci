// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetMaskingPolicyHealthReportsFilter;
import com.pulumi.oci.DataSafe.outputs.GetMaskingPolicyHealthReportsMaskingPolicyHealthReportCollection;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetMaskingPolicyHealthReportsResult {
    private @Nullable String accessLevel;
    /**
     * @return The OCID of the compartment that contains the health report.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return The display name of the health report.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetMaskingPolicyHealthReportsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The list of masking_policy_health_report_collection.
     * 
     */
    private List<GetMaskingPolicyHealthReportsMaskingPolicyHealthReportCollection> maskingPolicyHealthReportCollections;
    private @Nullable String maskingPolicyHealthReportId;
    /**
     * @return The OCID of the masking policy.
     * 
     */
    private @Nullable String maskingPolicyId;
    /**
     * @return The current state of the health report.
     * 
     */
    private @Nullable String state;
    /**
     * @return The OCID of the target database for which this report was created.
     * 
     */
    private @Nullable String targetId;

    private GetMaskingPolicyHealthReportsResult() {}
    public Optional<String> accessLevel() {
        return Optional.ofNullable(this.accessLevel);
    }
    /**
     * @return The OCID of the compartment that contains the health report.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return The display name of the health report.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetMaskingPolicyHealthReportsFilter> filters() {
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
     * @return The list of masking_policy_health_report_collection.
     * 
     */
    public List<GetMaskingPolicyHealthReportsMaskingPolicyHealthReportCollection> maskingPolicyHealthReportCollections() {
        return this.maskingPolicyHealthReportCollections;
    }
    public Optional<String> maskingPolicyHealthReportId() {
        return Optional.ofNullable(this.maskingPolicyHealthReportId);
    }
    /**
     * @return The OCID of the masking policy.
     * 
     */
    public Optional<String> maskingPolicyId() {
        return Optional.ofNullable(this.maskingPolicyId);
    }
    /**
     * @return The current state of the health report.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The OCID of the target database for which this report was created.
     * 
     */
    public Optional<String> targetId() {
        return Optional.ofNullable(this.targetId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMaskingPolicyHealthReportsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String accessLevel;
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private @Nullable String displayName;
        private @Nullable List<GetMaskingPolicyHealthReportsFilter> filters;
        private String id;
        private List<GetMaskingPolicyHealthReportsMaskingPolicyHealthReportCollection> maskingPolicyHealthReportCollections;
        private @Nullable String maskingPolicyHealthReportId;
        private @Nullable String maskingPolicyId;
        private @Nullable String state;
        private @Nullable String targetId;
        public Builder() {}
        public Builder(GetMaskingPolicyHealthReportsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.accessLevel = defaults.accessLevel;
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.maskingPolicyHealthReportCollections = defaults.maskingPolicyHealthReportCollections;
    	      this.maskingPolicyHealthReportId = defaults.maskingPolicyHealthReportId;
    	      this.maskingPolicyId = defaults.maskingPolicyId;
    	      this.state = defaults.state;
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
              throw new MissingRequiredPropertyException("GetMaskingPolicyHealthReportsResult", "compartmentId");
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
        public Builder displayName(@Nullable String displayName) {

            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetMaskingPolicyHealthReportsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetMaskingPolicyHealthReportsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetMaskingPolicyHealthReportsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder maskingPolicyHealthReportCollections(List<GetMaskingPolicyHealthReportsMaskingPolicyHealthReportCollection> maskingPolicyHealthReportCollections) {
            if (maskingPolicyHealthReportCollections == null) {
              throw new MissingRequiredPropertyException("GetMaskingPolicyHealthReportsResult", "maskingPolicyHealthReportCollections");
            }
            this.maskingPolicyHealthReportCollections = maskingPolicyHealthReportCollections;
            return this;
        }
        public Builder maskingPolicyHealthReportCollections(GetMaskingPolicyHealthReportsMaskingPolicyHealthReportCollection... maskingPolicyHealthReportCollections) {
            return maskingPolicyHealthReportCollections(List.of(maskingPolicyHealthReportCollections));
        }
        @CustomType.Setter
        public Builder maskingPolicyHealthReportId(@Nullable String maskingPolicyHealthReportId) {

            this.maskingPolicyHealthReportId = maskingPolicyHealthReportId;
            return this;
        }
        @CustomType.Setter
        public Builder maskingPolicyId(@Nullable String maskingPolicyId) {

            this.maskingPolicyId = maskingPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder targetId(@Nullable String targetId) {

            this.targetId = targetId;
            return this;
        }
        public GetMaskingPolicyHealthReportsResult build() {
            final var _resultValue = new GetMaskingPolicyHealthReportsResult();
            _resultValue.accessLevel = accessLevel;
            _resultValue.compartmentId = compartmentId;
            _resultValue.compartmentIdInSubtree = compartmentIdInSubtree;
            _resultValue.displayName = displayName;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.maskingPolicyHealthReportCollections = maskingPolicyHealthReportCollections;
            _resultValue.maskingPolicyHealthReportId = maskingPolicyHealthReportId;
            _resultValue.maskingPolicyId = maskingPolicyId;
            _resultValue.state = state;
            _resultValue.targetId = targetId;
            return _resultValue;
        }
    }
}
