// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedInstanceEventReportResult {
    private String compartmentId;
    private Integer counts;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String latestTimestampGreaterThanOrEqualTo;
    private @Nullable String latestTimestampLessThan;
    private String managedInstanceId;

    private GetManagedInstanceEventReportResult() {}
    public String compartmentId() {
        return this.compartmentId;
    }
    public Integer counts() {
        return this.counts;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> latestTimestampGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.latestTimestampGreaterThanOrEqualTo);
    }
    public Optional<String> latestTimestampLessThan() {
        return Optional.ofNullable(this.latestTimestampLessThan);
    }
    public String managedInstanceId() {
        return this.managedInstanceId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedInstanceEventReportResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private Integer counts;
        private String id;
        private @Nullable String latestTimestampGreaterThanOrEqualTo;
        private @Nullable String latestTimestampLessThan;
        private String managedInstanceId;
        public Builder() {}
        public Builder(GetManagedInstanceEventReportResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.counts = defaults.counts;
    	      this.id = defaults.id;
    	      this.latestTimestampGreaterThanOrEqualTo = defaults.latestTimestampGreaterThanOrEqualTo;
    	      this.latestTimestampLessThan = defaults.latestTimestampLessThan;
    	      this.managedInstanceId = defaults.managedInstanceId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder counts(Integer counts) {
            this.counts = Objects.requireNonNull(counts);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder latestTimestampGreaterThanOrEqualTo(@Nullable String latestTimestampGreaterThanOrEqualTo) {
            this.latestTimestampGreaterThanOrEqualTo = latestTimestampGreaterThanOrEqualTo;
            return this;
        }
        @CustomType.Setter
        public Builder latestTimestampLessThan(@Nullable String latestTimestampLessThan) {
            this.latestTimestampLessThan = latestTimestampLessThan;
            return this;
        }
        @CustomType.Setter
        public Builder managedInstanceId(String managedInstanceId) {
            this.managedInstanceId = Objects.requireNonNull(managedInstanceId);
            return this;
        }
        public GetManagedInstanceEventReportResult build() {
            final var o = new GetManagedInstanceEventReportResult();
            o.compartmentId = compartmentId;
            o.counts = counts;
            o.id = id;
            o.latestTimestampGreaterThanOrEqualTo = latestTimestampGreaterThanOrEqualTo;
            o.latestTimestampLessThan = latestTimestampLessThan;
            o.managedInstanceId = managedInstanceId;
            return o;
        }
    }
}