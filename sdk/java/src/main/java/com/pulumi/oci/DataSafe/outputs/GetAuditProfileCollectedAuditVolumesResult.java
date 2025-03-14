// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataSafe.outputs.GetAuditProfileCollectedAuditVolumesCollectedAuditVolumeCollection;
import com.pulumi.oci.DataSafe.outputs.GetAuditProfileCollectedAuditVolumesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAuditProfileCollectedAuditVolumesResult {
    /**
     * @return The OCID of the audit profile resource.
     * 
     */
    private String auditProfileId;
    /**
     * @return The list of collected_audit_volume_collection.
     * 
     */
    private List<GetAuditProfileCollectedAuditVolumesCollectedAuditVolumeCollection> collectedAuditVolumeCollections;
    private @Nullable List<GetAuditProfileCollectedAuditVolumesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String monthInConsiderationGreaterThan;
    private @Nullable String monthInConsiderationLessThan;
    private String workRequestId;

    private GetAuditProfileCollectedAuditVolumesResult() {}
    /**
     * @return The OCID of the audit profile resource.
     * 
     */
    public String auditProfileId() {
        return this.auditProfileId;
    }
    /**
     * @return The list of collected_audit_volume_collection.
     * 
     */
    public List<GetAuditProfileCollectedAuditVolumesCollectedAuditVolumeCollection> collectedAuditVolumeCollections() {
        return this.collectedAuditVolumeCollections;
    }
    public List<GetAuditProfileCollectedAuditVolumesFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> monthInConsiderationGreaterThan() {
        return Optional.ofNullable(this.monthInConsiderationGreaterThan);
    }
    public Optional<String> monthInConsiderationLessThan() {
        return Optional.ofNullable(this.monthInConsiderationLessThan);
    }
    public String workRequestId() {
        return this.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditProfileCollectedAuditVolumesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String auditProfileId;
        private List<GetAuditProfileCollectedAuditVolumesCollectedAuditVolumeCollection> collectedAuditVolumeCollections;
        private @Nullable List<GetAuditProfileCollectedAuditVolumesFilter> filters;
        private String id;
        private @Nullable String monthInConsiderationGreaterThan;
        private @Nullable String monthInConsiderationLessThan;
        private String workRequestId;
        public Builder() {}
        public Builder(GetAuditProfileCollectedAuditVolumesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.auditProfileId = defaults.auditProfileId;
    	      this.collectedAuditVolumeCollections = defaults.collectedAuditVolumeCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.monthInConsiderationGreaterThan = defaults.monthInConsiderationGreaterThan;
    	      this.monthInConsiderationLessThan = defaults.monthInConsiderationLessThan;
    	      this.workRequestId = defaults.workRequestId;
        }

        @CustomType.Setter
        public Builder auditProfileId(String auditProfileId) {
            if (auditProfileId == null) {
              throw new MissingRequiredPropertyException("GetAuditProfileCollectedAuditVolumesResult", "auditProfileId");
            }
            this.auditProfileId = auditProfileId;
            return this;
        }
        @CustomType.Setter
        public Builder collectedAuditVolumeCollections(List<GetAuditProfileCollectedAuditVolumesCollectedAuditVolumeCollection> collectedAuditVolumeCollections) {
            if (collectedAuditVolumeCollections == null) {
              throw new MissingRequiredPropertyException("GetAuditProfileCollectedAuditVolumesResult", "collectedAuditVolumeCollections");
            }
            this.collectedAuditVolumeCollections = collectedAuditVolumeCollections;
            return this;
        }
        public Builder collectedAuditVolumeCollections(GetAuditProfileCollectedAuditVolumesCollectedAuditVolumeCollection... collectedAuditVolumeCollections) {
            return collectedAuditVolumeCollections(List.of(collectedAuditVolumeCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetAuditProfileCollectedAuditVolumesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetAuditProfileCollectedAuditVolumesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetAuditProfileCollectedAuditVolumesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder monthInConsiderationGreaterThan(@Nullable String monthInConsiderationGreaterThan) {

            this.monthInConsiderationGreaterThan = monthInConsiderationGreaterThan;
            return this;
        }
        @CustomType.Setter
        public Builder monthInConsiderationLessThan(@Nullable String monthInConsiderationLessThan) {

            this.monthInConsiderationLessThan = monthInConsiderationLessThan;
            return this;
        }
        @CustomType.Setter
        public Builder workRequestId(String workRequestId) {
            if (workRequestId == null) {
              throw new MissingRequiredPropertyException("GetAuditProfileCollectedAuditVolumesResult", "workRequestId");
            }
            this.workRequestId = workRequestId;
            return this;
        }
        public GetAuditProfileCollectedAuditVolumesResult build() {
            final var _resultValue = new GetAuditProfileCollectedAuditVolumesResult();
            _resultValue.auditProfileId = auditProfileId;
            _resultValue.collectedAuditVolumeCollections = collectedAuditVolumeCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.monthInConsiderationGreaterThan = monthInConsiderationGreaterThan;
            _resultValue.monthInConsiderationLessThan = monthInConsiderationLessThan;
            _resultValue.workRequestId = workRequestId;
            return _resultValue;
        }
    }
}
