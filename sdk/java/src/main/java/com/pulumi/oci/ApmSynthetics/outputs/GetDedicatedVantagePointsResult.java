// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.ApmSynthetics.outputs.GetDedicatedVantagePointsDedicatedVantagePointCollection;
import com.pulumi.oci.ApmSynthetics.outputs.GetDedicatedVantagePointsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetDedicatedVantagePointsResult {
    private String apmDomainId;
    /**
     * @return The list of dedicated_vantage_point_collection.
     * 
     */
    private List<GetDedicatedVantagePointsDedicatedVantagePointCollection> dedicatedVantagePointCollections;
    /**
     * @return Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable List<GetDedicatedVantagePointsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return Unique permanent name of the dedicated vantage point. This is the same as the displayName.
     * 
     */
    private @Nullable String name;
    /**
     * @return Status of the dedicated vantage point.
     * 
     */
    private @Nullable String status;

    private GetDedicatedVantagePointsResult() {}
    public String apmDomainId() {
        return this.apmDomainId;
    }
    /**
     * @return The list of dedicated_vantage_point_collection.
     * 
     */
    public List<GetDedicatedVantagePointsDedicatedVantagePointCollection> dedicatedVantagePointCollections() {
        return this.dedicatedVantagePointCollections;
    }
    /**
     * @return Unique dedicated vantage point name that cannot be edited. The name should not contain any confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public List<GetDedicatedVantagePointsFilter> filters() {
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
     * @return Unique permanent name of the dedicated vantage point. This is the same as the displayName.
     * 
     */
    public Optional<String> name() {
        return Optional.ofNullable(this.name);
    }
    /**
     * @return Status of the dedicated vantage point.
     * 
     */
    public Optional<String> status() {
        return Optional.ofNullable(this.status);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVantagePointsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String apmDomainId;
        private List<GetDedicatedVantagePointsDedicatedVantagePointCollection> dedicatedVantagePointCollections;
        private @Nullable String displayName;
        private @Nullable List<GetDedicatedVantagePointsFilter> filters;
        private String id;
        private @Nullable String name;
        private @Nullable String status;
        public Builder() {}
        public Builder(GetDedicatedVantagePointsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.apmDomainId = defaults.apmDomainId;
    	      this.dedicatedVantagePointCollections = defaults.dedicatedVantagePointCollections;
    	      this.displayName = defaults.displayName;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.name = defaults.name;
    	      this.status = defaults.status;
        }

        @CustomType.Setter
        public Builder apmDomainId(String apmDomainId) {
            this.apmDomainId = Objects.requireNonNull(apmDomainId);
            return this;
        }
        @CustomType.Setter
        public Builder dedicatedVantagePointCollections(List<GetDedicatedVantagePointsDedicatedVantagePointCollection> dedicatedVantagePointCollections) {
            this.dedicatedVantagePointCollections = Objects.requireNonNull(dedicatedVantagePointCollections);
            return this;
        }
        public Builder dedicatedVantagePointCollections(GetDedicatedVantagePointsDedicatedVantagePointCollection... dedicatedVantagePointCollections) {
            return dedicatedVantagePointCollections(List.of(dedicatedVantagePointCollections));
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetDedicatedVantagePointsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetDedicatedVantagePointsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder name(@Nullable String name) {
            this.name = name;
            return this;
        }
        @CustomType.Setter
        public Builder status(@Nullable String status) {
            this.status = status;
            return this;
        }
        public GetDedicatedVantagePointsResult build() {
            final var o = new GetDedicatedVantagePointsResult();
            o.apmDomainId = apmDomainId;
            o.dedicatedVantagePointCollections = dedicatedVantagePointCollections;
            o.displayName = displayName;
            o.filters = filters;
            o.id = id;
            o.name = name;
            o.status = status;
            return o;
        }
    }
}