// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DataSafe.outputs.GetAuditProfileAvailableAuditVolumeItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAuditProfileAvailableAuditVolumeResult {
    /**
     * @return The OCID of the audit profile resource.
     * 
     */
    private String auditProfileId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Array of available audit volume summary.
     * 
     */
    private List<GetAuditProfileAvailableAuditVolumeItem> items;
    private @Nullable String monthInConsiderationGreaterThan;
    private @Nullable String monthInConsiderationLessThan;
    /**
     * @return Audit trail location on the target database from where the audit data is being collected by Data Safe.
     * 
     */
    private @Nullable String trailLocation;
    private String workRequestId;

    private GetAuditProfileAvailableAuditVolumeResult() {}
    /**
     * @return The OCID of the audit profile resource.
     * 
     */
    public String auditProfileId() {
        return this.auditProfileId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Array of available audit volume summary.
     * 
     */
    public List<GetAuditProfileAvailableAuditVolumeItem> items() {
        return this.items;
    }
    public Optional<String> monthInConsiderationGreaterThan() {
        return Optional.ofNullable(this.monthInConsiderationGreaterThan);
    }
    public Optional<String> monthInConsiderationLessThan() {
        return Optional.ofNullable(this.monthInConsiderationLessThan);
    }
    /**
     * @return Audit trail location on the target database from where the audit data is being collected by Data Safe.
     * 
     */
    public Optional<String> trailLocation() {
        return Optional.ofNullable(this.trailLocation);
    }
    public String workRequestId() {
        return this.workRequestId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAuditProfileAvailableAuditVolumeResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String auditProfileId;
        private String id;
        private List<GetAuditProfileAvailableAuditVolumeItem> items;
        private @Nullable String monthInConsiderationGreaterThan;
        private @Nullable String monthInConsiderationLessThan;
        private @Nullable String trailLocation;
        private String workRequestId;
        public Builder() {}
        public Builder(GetAuditProfileAvailableAuditVolumeResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.auditProfileId = defaults.auditProfileId;
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.monthInConsiderationGreaterThan = defaults.monthInConsiderationGreaterThan;
    	      this.monthInConsiderationLessThan = defaults.monthInConsiderationLessThan;
    	      this.trailLocation = defaults.trailLocation;
    	      this.workRequestId = defaults.workRequestId;
        }

        @CustomType.Setter
        public Builder auditProfileId(String auditProfileId) {
            this.auditProfileId = Objects.requireNonNull(auditProfileId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetAuditProfileAvailableAuditVolumeItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetAuditProfileAvailableAuditVolumeItem... items) {
            return items(List.of(items));
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
        public Builder trailLocation(@Nullable String trailLocation) {
            this.trailLocation = trailLocation;
            return this;
        }
        @CustomType.Setter
        public Builder workRequestId(String workRequestId) {
            this.workRequestId = Objects.requireNonNull(workRequestId);
            return this;
        }
        public GetAuditProfileAvailableAuditVolumeResult build() {
            final var o = new GetAuditProfileAvailableAuditVolumeResult();
            o.auditProfileId = auditProfileId;
            o.id = id;
            o.items = items;
            o.monthInConsiderationGreaterThan = monthInConsiderationGreaterThan;
            o.monthInConsiderationLessThan = monthInConsiderationLessThan;
            o.trailLocation = trailLocation;
            o.workRequestId = workRequestId;
            return o;
        }
    }
}