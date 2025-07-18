// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.outputs.GetComplianceRecordsComplianceRecordCollection;
import com.pulumi.oci.FleetAppsManagement.outputs.GetComplianceRecordsFilter;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetComplianceRecordsResult {
    /**
     * @return Compartment OCID of the resource.
     * 
     */
    private String compartmentId;
    private @Nullable Boolean compartmentIdInSubtree;
    /**
     * @return The list of compliance_record_collection.
     * 
     */
    private List<GetComplianceRecordsComplianceRecordCollection> complianceRecordCollections;
    /**
     * @return Last known compliance state of target.
     * 
     */
    private @Nullable String complianceState;
    /**
     * @return The OCID of the entity for which the compliance is calculated.Ex.FleetId
     * 
     */
    private @Nullable String entityId;
    private @Nullable List<GetComplianceRecordsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Product Name.
     * 
     */
    private @Nullable String productName;
    /**
     * @return Product Stack.
     * 
     */
    private @Nullable String productStack;
    /**
     * @return The OCID to identify the resource.
     * 
     */
    private @Nullable String resourceId;
    /**
     * @return Target Name.
     * 
     */
    private @Nullable String targetName;

    private GetComplianceRecordsResult() {}
    /**
     * @return Compartment OCID of the resource.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    public Optional<Boolean> compartmentIdInSubtree() {
        return Optional.ofNullable(this.compartmentIdInSubtree);
    }
    /**
     * @return The list of compliance_record_collection.
     * 
     */
    public List<GetComplianceRecordsComplianceRecordCollection> complianceRecordCollections() {
        return this.complianceRecordCollections;
    }
    /**
     * @return Last known compliance state of target.
     * 
     */
    public Optional<String> complianceState() {
        return Optional.ofNullable(this.complianceState);
    }
    /**
     * @return The OCID of the entity for which the compliance is calculated.Ex.FleetId
     * 
     */
    public Optional<String> entityId() {
        return Optional.ofNullable(this.entityId);
    }
    public List<GetComplianceRecordsFilter> filters() {
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
     * @return Product Name.
     * 
     */
    public Optional<String> productName() {
        return Optional.ofNullable(this.productName);
    }
    /**
     * @return Product Stack.
     * 
     */
    public Optional<String> productStack() {
        return Optional.ofNullable(this.productStack);
    }
    /**
     * @return The OCID to identify the resource.
     * 
     */
    public Optional<String> resourceId() {
        return Optional.ofNullable(this.resourceId);
    }
    /**
     * @return Target Name.
     * 
     */
    public Optional<String> targetName() {
        return Optional.ofNullable(this.targetName);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetComplianceRecordsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable Boolean compartmentIdInSubtree;
        private List<GetComplianceRecordsComplianceRecordCollection> complianceRecordCollections;
        private @Nullable String complianceState;
        private @Nullable String entityId;
        private @Nullable List<GetComplianceRecordsFilter> filters;
        private String id;
        private @Nullable String productName;
        private @Nullable String productStack;
        private @Nullable String resourceId;
        private @Nullable String targetName;
        public Builder() {}
        public Builder(GetComplianceRecordsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.compartmentIdInSubtree = defaults.compartmentIdInSubtree;
    	      this.complianceRecordCollections = defaults.complianceRecordCollections;
    	      this.complianceState = defaults.complianceState;
    	      this.entityId = defaults.entityId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.productName = defaults.productName;
    	      this.productStack = defaults.productStack;
    	      this.resourceId = defaults.resourceId;
    	      this.targetName = defaults.targetName;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsResult", "compartmentId");
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
        public Builder complianceRecordCollections(List<GetComplianceRecordsComplianceRecordCollection> complianceRecordCollections) {
            if (complianceRecordCollections == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsResult", "complianceRecordCollections");
            }
            this.complianceRecordCollections = complianceRecordCollections;
            return this;
        }
        public Builder complianceRecordCollections(GetComplianceRecordsComplianceRecordCollection... complianceRecordCollections) {
            return complianceRecordCollections(List.of(complianceRecordCollections));
        }
        @CustomType.Setter
        public Builder complianceState(@Nullable String complianceState) {

            this.complianceState = complianceState;
            return this;
        }
        @CustomType.Setter
        public Builder entityId(@Nullable String entityId) {

            this.entityId = entityId;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetComplianceRecordsFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetComplianceRecordsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetComplianceRecordsResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder productName(@Nullable String productName) {

            this.productName = productName;
            return this;
        }
        @CustomType.Setter
        public Builder productStack(@Nullable String productStack) {

            this.productStack = productStack;
            return this;
        }
        @CustomType.Setter
        public Builder resourceId(@Nullable String resourceId) {

            this.resourceId = resourceId;
            return this;
        }
        @CustomType.Setter
        public Builder targetName(@Nullable String targetName) {

            this.targetName = targetName;
            return this;
        }
        public GetComplianceRecordsResult build() {
            final var _resultValue = new GetComplianceRecordsResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.compartmentIdInSubtree = compartmentIdInSubtree;
            _resultValue.complianceRecordCollections = complianceRecordCollections;
            _resultValue.complianceState = complianceState;
            _resultValue.entityId = entityId;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.productName = productName;
            _resultValue.productStack = productStack;
            _resultValue.resourceId = resourceId;
            _resultValue.targetName = targetName;
            return _resultValue;
        }
    }
}
