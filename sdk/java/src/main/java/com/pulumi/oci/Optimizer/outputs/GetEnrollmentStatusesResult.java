// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Optimizer.outputs.GetEnrollmentStatusesEnrollmentStatusCollection;
import com.pulumi.oci.Optimizer.outputs.GetEnrollmentStatusesFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetEnrollmentStatusesResult {
    /**
     * @return The OCID of the compartment.
     * 
     */
    private String compartmentId;
    /**
     * @return The list of enrollment_status_collection.
     * 
     */
    private List<GetEnrollmentStatusesEnrollmentStatusCollection> enrollmentStatusCollections;
    private @Nullable List<GetEnrollmentStatusesFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The enrollment status&#39; current state.
     * 
     */
    private @Nullable String state;
    /**
     * @return The current Cloud Advisor enrollment status.
     * 
     */
    private @Nullable String status;

    private GetEnrollmentStatusesResult() {}
    /**
     * @return The OCID of the compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The list of enrollment_status_collection.
     * 
     */
    public List<GetEnrollmentStatusesEnrollmentStatusCollection> enrollmentStatusCollections() {
        return this.enrollmentStatusCollections;
    }
    public List<GetEnrollmentStatusesFilter> filters() {
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
     * @return The enrollment status&#39; current state.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The current Cloud Advisor enrollment status.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetEnrollmentStatusesResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private List<GetEnrollmentStatusesEnrollmentStatusCollection> enrollmentStatusCollections;
        private @Nullable List<GetEnrollmentStatusesFilter> filters;
        private String id;
        private @Nullable String state;
        private @Nullable String status;
        public Builder() {}
        public Builder(GetEnrollmentStatusesResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.enrollmentStatusCollections = defaults.enrollmentStatusCollections;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetEnrollmentStatusesResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder enrollmentStatusCollections(List<GetEnrollmentStatusesEnrollmentStatusCollection> enrollmentStatusCollections) {
            if (enrollmentStatusCollections == null) {
              throw new MissingRequiredPropertyException("GetEnrollmentStatusesResult", "enrollmentStatusCollections");
            }
            this.enrollmentStatusCollections = enrollmentStatusCollections;
            return this;
        }
        public Builder enrollmentStatusCollections(GetEnrollmentStatusesEnrollmentStatusCollection... enrollmentStatusCollections) {
            return enrollmentStatusCollections(List.of(enrollmentStatusCollections));
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetEnrollmentStatusesFilter> filters) {

            this.filters = filters;
            return this;
        }
        public Builder filters(GetEnrollmentStatusesFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetEnrollmentStatusesResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {

            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder status(@Nullable String status) {

            this.status = status;
            return this;
        }
        public GetEnrollmentStatusesResult build() {
            final var _resultValue = new GetEnrollmentStatusesResult();
            _resultValue.compartmentId = compartmentId;
            _resultValue.enrollmentStatusCollections = enrollmentStatusCollections;
            _resultValue.filters = filters;
            _resultValue.id = id;
            _resultValue.state = state;
            _resultValue.status = status;
            return _resultValue;
        }
    }
}
